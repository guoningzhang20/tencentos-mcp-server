"""Audit logging decorator for MCP tool calls."""

from __future__ import annotations

import functools
import logging
import time
from typing import Any, Callable

from tencentos_mcp_server.config import get_config

audit_logger = logging.getLogger("tencentos_mcp.audit")


def log_tool_call(func: Callable) -> Callable:
    """Decorator that logs every MCP tool invocation."""

    @functools.wraps(func)
    async def wrapper(*args: Any, **kwargs: Any) -> Any:
        cfg = get_config()
        if not cfg.audit_enabled:
            return await func(*args, **kwargs)

        tool_name = func.__name__
        start = time.monotonic()
        audit_logger.info("TOOL_CALL_START | tool=%s | args=%s kwargs=%s", tool_name, args, kwargs)

        try:
            result = await func(*args, **kwargs)
            elapsed = time.monotonic() - start
            audit_logger.info(
                "TOOL_CALL_OK | tool=%s | elapsed=%.3fs",
                tool_name,
                elapsed,
            )
            return result
        except Exception as exc:
            elapsed = time.monotonic() - start
            audit_logger.error(
                "TOOL_CALL_ERROR | tool=%s | elapsed=%.3fs | error=%s",
                tool_name,
                elapsed,
                exc,
            )
            raise

    return wrapper
