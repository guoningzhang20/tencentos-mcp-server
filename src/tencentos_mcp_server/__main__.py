"""CLI entry point: python -m tencentos_mcp_server"""

import argparse
import os

from tencentos_mcp_server.server import mcp


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
        default=os.environ.get("TENCENTOS_MCP_BIND_HOST", "0.0.0.0"),
        help="SSE/HTTP 监听地址 (默认: 0.0.0.0)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("TENCENTOS_MCP_BIND_PORT", "8000")),
        help="SSE/HTTP 监听端口 (默认: 8000)",
    )
    args = parser.parse_args()

    if args.transport == "stdio":
        mcp.run(transport="stdio")
    elif args.transport == "sse":
        mcp.run(transport="sse", host=args.host, port=args.port)
    elif args.transport == "streamable-http":
        mcp.run(transport="streamable-http", host=args.host, port=args.port)


if __name__ == "__main__":
    cli()
