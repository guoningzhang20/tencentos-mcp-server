"""CLI entry point: python -m tencentos_mcp_server"""

import argparse
import logging
import os
import sys

from tencentos_mcp_server.server import mcp

logger = logging.getLogger(__name__)


def _warn_no_api_key(transport: str) -> None:
    """Warn loudly when running HTTP transports without an API key."""
    msg = (
        "\n"
        "╔══════════════════════════════════════════════════════════════╗\n"
        "║  ⚠️  WARNING: No API key configured!                        ║\n"
        "║  Running in %s mode without authentication.       ║\n"
        "║  Set TENCENTOS_MCP_API_KEY to enable Bearer token auth.    ║\n"
        "║  This server exposes system information — do NOT expose    ║\n"
        "║  to untrusted networks without authentication + TLS.       ║\n"
        "╚══════════════════════════════════════════════════════════════╝\n"
    )
    padded_transport = transport.ljust(17)
    print(msg % padded_transport, file=sys.stderr)


def cli():
    """Run the TencentOS MCP Server."""
    parser = argparse.ArgumentParser(
        prog="tencentos-mcp-server",
        description="TencentOS MCP Server — 系统遥测、故障诊断、补丁评估、合规审计、配置调优",
    )
    parser.add_argument(
        "--transport",
        choices=["stdio", "sse", "streamable-http"],
        default=os.environ.get("TENCENTOS_MCP_TRANSPORT", "stdio"),
        help="传输协议 (默认: stdio)",
    )
    parser.add_argument(
        "--host",
        default=os.environ.get("TENCENTOS_MCP_BIND_HOST", "127.0.0.1"),
        help="SSE/HTTP 监听地址 (默认: 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("TENCENTOS_MCP_BIND_PORT", "8000")),
        help="SSE/HTTP 监听端口 (默认: 8000)",
    )
    parser.add_argument(
        "--api-key",
        default=os.environ.get("TENCENTOS_MCP_API_KEY", ""),
        help="API Key for Bearer token authentication (SSE/HTTP modes)",
    )
    args = parser.parse_args()

    if args.transport == "stdio":
        mcp.run(transport="stdio")
    else:
        # HTTP-based transports: set up API key auth if configured
        api_key = args.api_key.strip()
        if api_key:
            _setup_auth_middleware(api_key)
            logger.info("API key authentication enabled for %s transport", args.transport)
        else:
            _warn_no_api_key(args.transport)

        if args.transport == "sse":
            mcp.run(transport="sse", host=args.host, port=args.port)
        elif args.transport == "streamable-http":
            mcp.run(transport="streamable-http", host=args.host, port=args.port)


def _setup_auth_middleware(api_key: str) -> None:
    """Inject Bearer token authentication into the FastMCP ASGI app.

    FastMCP uses Starlette/uvicorn under the hood for SSE and HTTP modes.
    We monkey-patch mcp.run to wrap the ASGI app with auth middleware.
    """
    from starlette.middleware import Middleware
    from starlette.responses import JSONResponse
    from starlette.types import ASGIApp, Receive, Scope, Send

    class BearerAuthMiddleware:
        """ASGI middleware: validate Authorization: Bearer <key> header."""

        def __init__(self, app: ASGIApp, expected_key: str) -> None:
            self.app = app
            self.expected_key = expected_key

        async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
            if scope["type"] in ("http", "websocket"):
                # Extract Authorization header from scope
                headers = dict(scope.get("headers", []))
                auth = headers.get(b"authorization", b"").decode()
                if not auth.startswith("Bearer ") or auth[7:] != self.expected_key:
                    if scope["type"] == "http":
                        response = JSONResponse(
                            {"error": "Unauthorized", "detail": "Invalid or missing Bearer token"},
                            status_code=401,
                            headers={"WWW-Authenticate": "Bearer"},
                        )
                        await response(scope, receive, send)
                        return
                    else:
                        # WebSocket: reject by closing before accept
                        await send({"type": "websocket.close", "code": 4001, "reason": "Unauthorized"})
                        return
            await self.app(scope, receive, send)

    # Monkey-patch: wrap mcp.run to inject middleware
    original_run = mcp.run

    def patched_run(**kwargs):
        # FastMCP accepts `middleware` kwarg for Starlette
        existing_middleware = kwargs.get("middleware", []) or []
        existing_middleware.insert(0, Middleware(BearerAuthMiddleware, expected_key=api_key))
        kwargs["middleware"] = existing_middleware
        return original_run(**kwargs)

    mcp.run = patched_run


if __name__ == "__main__":
    cli()
