"""⑤ System Tuning — workload profiling and parameter recommendations.

Tools:
- analyze_system_tuning: Full tuning analysis with parameter comparison
- get_workload_profile: Detect current workload type
- check_kernel_parameters: Check specific kernel params against best practices
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

from mcp.types import ToolAnnotations

from tencentos_mcp_server.audit import log_tool_call
from tencentos_mcp_server.best_practices import TUNING_RULES
from tencentos_mcp_server.executor import run_cmd
from tencentos_mcp_server.models import (
    ParameterCheck,
    TuningRecommendation,
    TuningReport,
    WorkloadProfile,
)
from tencentos_mcp_server.server import mcp


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_sysctl(text: str) -> dict[str, str]:
    """Parse sysctl -a output into key-value dict."""
    params: dict[str, str] = {}
    for line in text.splitlines():
        if "=" in line:
            k, _, v = line.partition("=")
            params[k.strip()] = v.strip()
    return params


def _recommend_tuned_profile(workload_type: str) -> str:
    """Recommend a tuned profile based on workload type."""
    mapping = {
        "network_intensive": "network-throughput 或 network-latency",
        "io_intensive": "throughput-performance",
        "cpu_intensive": "throughput-performance",
        "mixed": "throughput-performance",
        "idle": "balanced",
    }
    return mapping.get(workload_type, "throughput-performance")


async def _detect_workload(run) -> WorkloadProfile:
    """Detect current workload profile."""
    load = await run("cat /proc/loadavg")
    cores = await run("nproc 2>/dev/null || echo 1")
    mem = await run("free -m | awk '/^Mem:/ {printf \"%.1f\", $3/$2*100}'")
    vmstat = await run("vmstat 1 2 2>/dev/null | tail -1")
    connections = await run("ss -s 2>/dev/null | grep estab | head -1")

    loads = load.stdout.split()
    load_val = float(loads[0]) if loads else 0
    cores_val = int(cores.stdout.strip() or 1)
    mem_pct = float(mem.stdout) if mem.stdout else 0

    vmstat_fields = vmstat.stdout.split()
    iowait = 0.0
    if len(vmstat_fields) >= 16:
        try:
            iowait = float(vmstat_fields[15])
        except (ValueError, IndexError):
            pass

    conn_match = re.search(r"estab\s+(\d+)", connections.stdout)
    conn_count = int(conn_match.group(1)) if conn_match else 0

    if iowait > 20:
        wl_type = "io_intensive"
        desc = f"IO 密集型 — iowait {iowait}%，磁盘 IO 是主要瓶颈"
    elif conn_count > 10000:
        wl_type = "network_intensive"
        desc = f"网络密集型 — {conn_count} 个活跃连接，网络栈参数需要优化"
    elif cores_val > 0 and load_val / cores_val > 0.8 and iowait < 5:
        wl_type = "cpu_intensive"
        desc = f"CPU 密集型 — 负载 {load_val:.1f}/{cores_val} 核，CPU 利用率高"
    elif cores_val > 0 and load_val / cores_val < 0.1:
        wl_type = "idle"
        desc = "空闲状态 — 系统负载极低"
    else:
        wl_type = "mixed"
        desc = f"混合型负载 — load {load_val:.1f}, iowait {iowait}%, conns {conn_count}"

    return WorkloadProfile(
        type=wl_type,
        cpu_avg_load=load_val,
        memory_usage_pct=mem_pct,
        io_wait_pct=iowait,
        network_connections=conn_count,
        disk_io_read_mbps=0,
        disk_io_write_mbps=0,
        description=desc,
    )


@mcp.tool(
    title="Analyze system tuning",
    description=(
        "Comprehensive system tuning analysis: detect workload type, compare current "
        "kernel/sysctl parameters against best practices, and provide prioritized "
        "tuning recommendations. Advisory only — does NOT modify any settings."
    ),
    tags={"tuning", "performance", "sysctl", "tencentos"},
    annotations=ToolAnnotations(readOnlyHint=True),
)
@log_tool_call
async def analyze_system_tuning() -> TuningReport:
    profile = await _detect_workload(run_cmd)

    sysctl_all = await run_cmd("sysctl -a 2>/dev/null")
    tuned_active = await run_cmd("tuned-adm active 2>/dev/null || echo 'tuned not installed'")

    current_params = _parse_sysctl(sysctl_all.stdout)

    checks: list[ParameterCheck] = []
    for rule in TUNING_RULES:
        if rule.applies_to(profile.type):
            current_val = current_params.get(rule.parameter, "N/A")
            status = rule.evaluate(current_val, profile.type)
            rec_val = rule.recommended_value(profile.type)
            checks.append(ParameterCheck(
                parameter=rule.parameter,
                current_value=current_val,
                recommended_value=rec_val,
                status=status,
                category=rule.category,
                reason=rule.reason,
            ))

    suboptimal = [c for c in checks if c.status != "optimal"]
    recommendations: list[TuningRecommendation] = []
    for c in suboptimal:
        priority = "high" if c.status == "risky" else "medium"
        recommendations.append(TuningRecommendation(
            priority=priority,
            category=c.category,
            title=f"调整 {c.parameter}",
            description=c.reason,
            current_state=f"当前值: {c.current_value}",
            recommended_action=f"sysctl -w {c.parameter}={c.recommended_value}",
            expected_effect=f"从 {c.current_value} 调整到 {c.recommended_value}，{c.reason}",
        ))

    priority_order = {"high": 0, "medium": 1, "low": 2}
    recommendations.sort(key=lambda r: priority_order.get(r.priority, 3))

    tuned_name = tuned_active.stdout.strip()
    if ":" in tuned_name:
        tuned_name = tuned_name.split(":")[-1].strip()

    return TuningReport(
        scan_time=_now(),
        workload_profile=profile,
        tuned_profile=tuned_name,
        recommended_profile=_recommend_tuned_profile(profile.type),
        parameter_checks=checks,
        total_recommendations=len(recommendations),
        recommendations=recommendations,
    )


@mcp.tool(
    title="Get workload profile",
    description=(
        "Detect the current workload type: CPU-intensive, IO-intensive, "
        "network-intensive, mixed, or idle. Based on real-time system metrics."
    ),
    tags={"tuning", "workload", "performance", "tencentos"},
    annotations=ToolAnnotations(readOnlyHint=True),
)
@log_tool_call
async def get_workload_profile() -> WorkloadProfile:
    return await _detect_workload(run_cmd)


@mcp.tool(
    title="Check kernel parameters",
    description=(
        "Check specific kernel parameters against recommended values for the current "
        "workload type. Shows current value, recommended value, and optimization status."
    ),
    tags={"tuning", "sysctl", "kernel", "tencentos"},
    annotations=ToolAnnotations(readOnlyHint=True),
)
@log_tool_call
async def check_kernel_parameters() -> list[ParameterCheck]:
    profile = await _detect_workload(run_cmd)
    sysctl_all = await run_cmd("sysctl -a 2>/dev/null")
    current_params = _parse_sysctl(sysctl_all.stdout)

    checks: list[ParameterCheck] = []
    for rule in TUNING_RULES:
        current_val = current_params.get(rule.parameter, "N/A")
        if rule.applies_to(profile.type):
            status = rule.evaluate(current_val, profile.type)
            rec_val = rule.recommended_value(profile.type)
        else:
            status = "optimal"
            rec_val = current_val

        checks.append(ParameterCheck(
            parameter=rule.parameter,
            current_value=current_val,
            recommended_value=rec_val,
            status=status,
            category=rule.category,
            reason=rule.reason,
        ))
    return checks
