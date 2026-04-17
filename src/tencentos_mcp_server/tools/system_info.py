"""System information tools — OS, CPU, memory, disk."""

from __future__ import annotations

from mcp.types import ToolAnnotations

from tencentos_mcp_server.audit import log_tool_call
from tencentos_mcp_server.executor import run_cmd
from tencentos_mcp_server.models import CpuInfo, DiskPartition, DiskUsage, MemoryInfo, SystemInfo
from tencentos_mcp_server.server import mcp


# ───────────────────────── helpers ─────────────────────────

def _parse_os_release(text: str) -> dict[str, str]:
    kv: dict[str, str] = {}
    for line in text.splitlines():
        if "=" in line:
            k, _, v = line.partition("=")
            kv[k.strip()] = v.strip().strip('"')
    return kv


# ───────────────────────── tools ───────────────────────────

@mcp.tool(
    title="Get system information",
    description=(
        "Get basic TencentOS system info: OS name/version, kernel, architecture, "
        "hostname, uptime, and last boot time."
    ),
    tags={"system", "info"},
    annotations=ToolAnnotations(readOnlyHint=True),
)
@log_tool_call
async def get_system_info() -> SystemInfo:
    hostname = await run_cmd("hostname")
    os_release = await run_cmd("cat /etc/os-release 2>/dev/null || echo ''")
    kernel = await run_cmd("uname -r")
    arch = await run_cmd("uname -m")
    uptime = await run_cmd("uptime -p 2>/dev/null || uptime")
    last_boot = await run_cmd("who -b 2>/dev/null || echo ''")

    os_info = _parse_os_release(os_release.stdout)
    boot_str = ""
    if last_boot.stdout:
        parts = last_boot.stdout.split("boot")
        boot_str = parts[-1].strip() if len(parts) > 1 else last_boot.stdout

    return SystemInfo(
        hostname=hostname.stdout,
        os_name=os_info.get("NAME", os_info.get("ID", "Unknown")),
        os_version=os_info.get("VERSION_ID", os_info.get("VERSION", "Unknown")),
        kernel=kernel.stdout,
        architecture=arch.stdout,
        uptime=uptime.stdout,
        last_boot=boot_str,
    )


@mcp.tool(
    title="Get CPU information",
    description="Get CPU model, core/thread counts, frequency, and current load averages.",
    tags={"cpu", "hardware", "system"},
    annotations=ToolAnnotations(readOnlyHint=True),
)
@log_tool_call
async def get_cpu_info() -> CpuInfo:
    lscpu = await run_cmd("lscpu 2>/dev/null || echo ''")
    loadavg = await run_cmd("cat /proc/loadavg")

    info: dict[str, str] = {}
    for line in lscpu.stdout.splitlines():
        if ":" in line:
            k, _, v = line.partition(":")
            info[k.strip()] = v.strip()

    loads = loadavg.stdout.split()
    return CpuInfo(
        model_name=info.get("Model name", info.get("型号名称", "")),
        cores=int(info.get("Core(s) per socket", info.get("每个座的核数", "0")) or 0),
        threads=int(info.get("CPU(s)", info.get("CPU", "0")) or 0),
        architecture=info.get("Architecture", info.get("架构", "")),
        frequency_mhz=info.get("CPU MHz", info.get("CPU 最大 MHz", "")),
        load_1=float(loads[0]) if loads else 0,
        load_5=float(loads[1]) if len(loads) > 1 else 0,
        load_15=float(loads[2]) if len(loads) > 2 else 0,
    )


@mcp.tool(
    title="Get memory information",
    description="Get physical memory and swap usage details.",
    tags={"memory", "hardware", "system"},
    annotations=ToolAnnotations(readOnlyHint=True),
)
@log_tool_call
async def get_memory_info() -> MemoryInfo:
    free = await run_cmd("free -m")
    lines = free.stdout.splitlines()
    mem = MemoryInfo()
    for line in lines:
        parts = line.split()
        if parts and parts[0].startswith("Mem"):
            mem.total_mb = int(parts[1])
            mem.used_mb = int(parts[2])
            mem.free_mb = int(parts[3])
            mem.available_mb = int(parts[6]) if len(parts) > 6 else mem.free_mb
            mem.usage_percent = round(mem.used_mb / mem.total_mb * 100, 1) if mem.total_mb else 0
        elif parts and parts[0].startswith("Swap"):
            mem.swap_total_mb = int(parts[1])
            mem.swap_used_mb = int(parts[2])
            mem.swap_free_mb = int(parts[3])
    return mem


@mcp.tool(
    title="Get disk usage",
    description="Get disk partition sizes, usage, and mount points.",
    tags={"disk", "storage", "system"},
    annotations=ToolAnnotations(readOnlyHint=True),
)
@log_tool_call
async def get_disk_usage() -> DiskUsage:
    df = await run_cmd("df -hT --exclude-type=tmpfs --exclude-type=devtmpfs --exclude-type=squashfs 2>/dev/null || df -h")
    partitions: list[DiskPartition] = []
    for line in df.stdout.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 7:
            partitions.append(DiskPartition(
                device=parts[0],
                fs_type=parts[1],
                size=parts[2],
                used=parts[3],
                available=parts[4],
                usage_percent=parts[5],
                mount_point=parts[6],
            ))
        elif len(parts) >= 6:
            partitions.append(DiskPartition(
                device=parts[0],
                fs_type="",
                size=parts[1],
                used=parts[2],
                available=parts[3],
                usage_percent=parts[4],
                mount_point=parts[5],
            ))
    return DiskUsage(partitions=partitions)
