"""Process management tools."""

from __future__ import annotations

from mcp.types import ToolAnnotations

from tencentos_mcp_server.audit import log_tool_call
from tencentos_mcp_server.executor import run_cmd
from tencentos_mcp_server.models import ProcessInfo
from tencentos_mcp_server.server import mcp


@mcp.tool(
    title="List processes",
    description=(
        "List running processes sorted by CPU or memory usage. "
        "Returns top N processes (default 20)."
    ),
    tags={"process", "system"},
    annotations=ToolAnnotations(readOnlyHint=True),
)
@log_tool_call
async def list_processes(sort_by: str = "cpu", top_n: int = 20) -> list[ProcessInfo]:
    """List running processes.

    Args:
        sort_by: Sort field — 'cpu' or 'mem'. Default 'cpu'.
        top_n: Number of processes to return. Default 20.
    """
    sort_flag = "-pcpu" if sort_by == "cpu" else "-pmem"
    result = await run_cmd(
        f"ps aux --sort={sort_flag} 2>/dev/null | head -{top_n + 1}"
    )
    processes: list[ProcessInfo] = []
    for line in result.stdout.splitlines()[1:]:
        parts = line.split(None, 10)
        if len(parts) < 11:
            continue
        try:
            processes.append(ProcessInfo(
                pid=int(parts[1]),
                user=parts[0],
                cpu_percent=float(parts[2]),
                mem_percent=float(parts[3]),
                vsz_kb=int(parts[4]),
                rss_kb=int(parts[5]),
                stat=parts[7],
                started=parts[8],
                command=parts[10],
            ))
        except (ValueError, IndexError):
            continue
    return processes
