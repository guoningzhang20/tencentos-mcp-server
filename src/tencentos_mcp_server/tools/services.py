"""Service management tools."""

from __future__ import annotations

from mcp.types import ToolAnnotations

from tencentos_mcp_server.audit import log_tool_call
from tencentos_mcp_server.executor import run_cmd
from tencentos_mcp_server.models import ServiceInfo
from tencentos_mcp_server.server import mcp


@mcp.tool(
    title="Get service status",
    description="Get the status of a specific systemd service.",
    tags={"service", "systemd"},
    annotations=ToolAnnotations(readOnlyHint=True),
)
@log_tool_call
async def get_service_status(service_name: str) -> dict:
    """Query a specific systemd service status.

    Args:
        service_name: The service name, e.g. 'sshd', 'nginx'.
    """
    result = await run_cmd(f"systemctl status {service_name} --no-pager 2>/dev/null || echo 'Service not found'")
    is_active = await run_cmd(f"systemctl is-active {service_name} 2>/dev/null || echo 'unknown'")
    is_enabled = await run_cmd(f"systemctl is-enabled {service_name} 2>/dev/null || echo 'unknown'")
    return {
        "service": service_name,
        "active": is_active.stdout.strip(),
        "enabled": is_enabled.stdout.strip(),
        "status_output": result.stdout,
    }


@mcp.tool(
    title="List services",
    description="List all systemd services and their states.",
    tags={"service", "systemd"},
    annotations=ToolAnnotations(readOnlyHint=True),
)
@log_tool_call
async def list_services(state: str = "") -> list[ServiceInfo]:
    """List systemd services.

    Args:
        state: Filter by state — 'running', 'failed', 'inactive', or '' for all.
    """
    state_filter = f"--state={state}" if state else ""
    result = await run_cmd(
        f"systemctl list-units --type=service {state_filter} --no-pager --plain --no-legend 2>/dev/null"
    )
    services: list[ServiceInfo] = []
    for line in result.stdout.splitlines():
        parts = line.split(None, 4)
        if len(parts) >= 4:
            services.append(ServiceInfo(
                name=parts[0].replace(".service", ""),
                load_state=parts[1],
                active_state=parts[2],
                sub_state=parts[3],
                description=parts[4] if len(parts) > 4 else "",
            ))
    return services
