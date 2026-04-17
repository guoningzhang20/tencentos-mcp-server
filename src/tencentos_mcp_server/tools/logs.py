"""Log query tools."""

from __future__ import annotations

from mcp.types import ToolAnnotations

from tencentos_mcp_server.audit import log_tool_call
from tencentos_mcp_server.executor import run_cmd
from tencentos_mcp_server.models import LogEntry
from tencentos_mcp_server.sanitize import safe_name, safe_positive_int, safe_priority, safe_time_expr
from tencentos_mcp_server.server import mcp


@mcp.tool(
    title="Query system logs",
    description=(
        "Query system logs from journalctl with optional filters. "
        "Supports filtering by unit, priority, and time range."
    ),
    tags={"logs", "system"},
    annotations=ToolAnnotations(readOnlyHint=True),
)
@log_tool_call
async def query_logs(
    unit: str = "",
    priority: str = "",
    since: str = "1 hour ago",
    lines: int = 50,
) -> list[LogEntry]:
    """Query system logs.

    Args:
        unit: Filter by systemd unit, e.g. 'sshd', 'nginx'. Empty = all units.
        priority: Minimum priority — 'emerg','alert','crit','err','warning','notice','info','debug'. Empty = all.
        since: Time range start, e.g. '1 hour ago', '2026-04-17', 'today'. Default '1 hour ago'.
        lines: Max number of log entries to return. Default 50.
    """
    if unit:
        unit = safe_name(unit, "unit")
    priority = safe_priority(priority)
    since = safe_time_expr(since, "since")
    lines = safe_positive_int(lines, "lines", max_val=1000)

    cmd_parts = ["journalctl", "--no-pager", "-o", "short-iso"]
    if unit:
        cmd_parts.append(f"-u {unit}")
    if priority:
        cmd_parts.append(f"-p {priority}")
    if since:
        cmd_parts.append(f'--since "{since}"')
    cmd_parts.append(f"-n {lines}")

    result = await run_cmd(" ".join(cmd_parts) + " 2>/dev/null")
    entries: list[LogEntry] = []
    for line in result.stdout.splitlines():
        if not line.strip() or line.startswith("--"):
            continue
        # Format: 2026-04-17T10:30:00+0800 hostname unit[pid]: message
        parts = line.split(None, 3)
        if len(parts) >= 4:
            entries.append(LogEntry(
                timestamp=parts[0],
                unit=parts[2].rstrip(":"),
                priority=priority or "",
                message=parts[3] if len(parts) > 3 else "",
            ))
        elif parts:
            entries.append(LogEntry(message=line))
    return entries
