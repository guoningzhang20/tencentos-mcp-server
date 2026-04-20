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


_VALID_WORKLOADS = {"cpu_intensive", "io_intensive", "network_intensive", "mixed", "idle"}


def _sanitize_workload_hint(hint: str | None) -> str | None:
    """仅允许白名单值，其他一律忽略（不报错，降级到自动检测）。"""
    if hint and hint in _VALID_WORKLOADS:
        return hint
    return None


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


async def _detect_workload(run, hint: str | None = None) -> WorkloadProfile:
    """Detect current workload profile.

    Args:
        run: run_cmd 函数
        hint: 用户显式声明（cpu_intensive / io_intensive / network_intensive / mixed / idle）。
              提供时跳过自动检测，但仍采集指标以供呈现。
    """
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

    # v0.5: 用户显式声明优先
    if hint and hint in _VALID_WORKLOADS:
        wl_type = hint
        desc = (
            f"[用户声明] 负载类型：{hint}（跳过自动检测）。"
            f"实测：load {load_val:.1f}/{cores_val} 核，iowait {iowait}%，连接数 {conn_count}"
        )
        return WorkloadProfile(
            type=wl_type, cpu_avg_load=load_val, memory_usage_pct=mem_pct,
            io_wait_pct=iowait, network_connections=conn_count,
            disk_io_read_mbps=0, disk_io_write_mbps=0, description=desc, hint_applied=True,
        )

    # v0.5: 自动检测 —— 多指标综合打分代替单阈值
    # 各维度打分（0-100）
    load_ratio = load_val / cores_val if cores_val > 0 else 0
    cpu_score = min(100, load_ratio * 100)                 # load/cores ~1.0 → 100 分
    io_score = min(100, iowait * 10)                        # iowait 10% → 100 分（旧逻辑 20 才满）
    net_score = min(100, conn_count / 100)                  # 1w 连接 → 100 分
    # idle 判断：所有维度都很低
    all_low = load_ratio < 0.1 and iowait < 1 and conn_count < 100

    if all_low:
        wl_type = "idle"
        desc = f"空闲状态 — load {load_val:.1f}/{cores_val} 核，iowait {iowait}%，连接 {conn_count}"
    else:
        # 取最高分的维度作为主导类型
        scores = {"cpu_intensive": cpu_score, "io_intensive": io_score, "network_intensive": net_score}
        top_type, top_score = max(scores.items(), key=lambda x: x[1])
        # 如果最高分也不足 30 且不是空闲，判 mixed
        if top_score < 30:
            wl_type = "mixed"
            desc = (
                f"混合型负载 — load {load_val:.1f}/{cores_val} 核，iowait {iowait}%，连接 {conn_count}。"
                f"无单一主导维度（最高分 {top_score:.0f}）"
            )
        else:
            wl_type = top_type
            label_map = {
                "cpu_intensive": "CPU 密集型",
                "io_intensive": "IO 密集型",
                "network_intensive": "网络密集型",
            }
            desc = (
                f"{label_map[top_type]}（评分 {top_score:.0f}/100）— "
                f"load {load_val:.1f}/{cores_val} 核，iowait {iowait}%，连接 {conn_count}。"
                f"如判断有误，可在调用时传入 workload_hint 显式声明"
            )

    return WorkloadProfile(
        type=wl_type,
        cpu_avg_load=load_val,
        memory_usage_pct=mem_pct,
        io_wait_pct=iowait,
        network_connections=conn_count,
        disk_io_read_mbps=0,
        disk_io_write_mbps=0,
        description=desc,
        hint_applied=False,
    )


@mcp.tool(
    title="Analyze system tuning",
    description=(
        "Comprehensive system tuning analysis: detect workload type, compare current "
        "kernel/sysctl parameters against best practices, and provide prioritized "
        "tuning recommendations. Advisory only — does NOT modify any settings. "
        "Optional: pass workload_hint to skip auto-detection when you know the workload type."
    ),
    tags={"tuning", "performance", "sysctl", "tencentos"},
    annotations=ToolAnnotations(readOnlyHint=True),
)
@log_tool_call
async def analyze_system_tuning(workload_hint: str | None = None) -> TuningReport:
    """Analyze system tuning.

    Args:
        workload_hint: Optional explicit workload type to skip auto-detection.
            Valid values: cpu_intensive / io_intensive / network_intensive / mixed / idle.
            Invalid values are silently ignored (falls back to auto-detection).
    """
    profile = await _detect_workload(run_cmd, hint=_sanitize_workload_hint(workload_hint))

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
        "network-intensive, mixed, or idle. Based on real-time system metrics. "
        "Pass workload_hint to skip auto-detection."
    ),
    tags={"tuning", "workload", "performance", "tencentos"},
    annotations=ToolAnnotations(readOnlyHint=True),
)
@log_tool_call
async def get_workload_profile(workload_hint: str | None = None) -> WorkloadProfile:
    return await _detect_workload(run_cmd, hint=_sanitize_workload_hint(workload_hint))


@mcp.tool(
    title="Check kernel parameters",
    description=(
        "Check specific kernel parameters against recommended values for the current "
        "workload type. Shows current value, recommended value, and optimization status. "
        "Pass workload_hint to pin the workload type."
    ),
    tags={"tuning", "sysctl", "kernel", "tencentos"},
    annotations=ToolAnnotations(readOnlyHint=True),
)
@log_tool_call
async def check_kernel_parameters(workload_hint: str | None = None) -> list[ParameterCheck]:
    profile = await _detect_workload(run_cmd, hint=_sanitize_workload_hint(workload_hint))
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
