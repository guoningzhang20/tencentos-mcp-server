"""Storage tools — block devices."""

from __future__ import annotations

import json

from mcp.types import ToolAnnotations

from tencentos_mcp_server.audit import log_tool_call
from tencentos_mcp_server.executor import run_cmd
from tencentos_mcp_server.models import BlockDevice
from tencentos_mcp_server.server import mcp


@mcp.tool(
    title="Get block devices",
    description="List block devices with size, type, filesystem, and mount points.",
    tags={"storage", "disk", "system"},
    annotations=ToolAnnotations(readOnlyHint=True),
)
@log_tool_call
async def get_block_devices() -> list[BlockDevice]:
    result = await run_cmd("lsblk -J -o NAME,SIZE,TYPE,MOUNTPOINT,FSTYPE 2>/dev/null")
    devices: list[BlockDevice] = []
    if result.ok and result.stdout.strip().startswith("{"):
        try:
            data = json.loads(result.stdout)
            for dev in data.get("blockdevices", []):
                _flatten_device(dev, devices)
        except json.JSONDecodeError:
            pass
    else:
        # Fallback: plain text
        result2 = await run_cmd("lsblk -o NAME,SIZE,TYPE,MOUNTPOINT,FSTYPE 2>/dev/null || echo ''")
        for line in result2.stdout.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 3:
                devices.append(BlockDevice(
                    name=parts[0].strip("├─└─│ "),
                    size=parts[1] if len(parts) > 1 else "",
                    device_type=parts[2] if len(parts) > 2 else "",
                    mount_point=parts[3] if len(parts) > 3 else "",
                    fs_type=parts[4] if len(parts) > 4 else "",
                ))
    return devices


def _flatten_device(dev: dict, result: list[BlockDevice], prefix: str = ""):
    result.append(BlockDevice(
        name=prefix + dev.get("name", ""),
        size=dev.get("size", ""),
        device_type=dev.get("type", ""),
        mount_point=dev.get("mountpoint") or "",
        fs_type=dev.get("fstype") or "",
    ))
    for child in dev.get("children", []):
        _flatten_device(child, result, prefix="  ")
