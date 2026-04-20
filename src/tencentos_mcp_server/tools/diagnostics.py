"""② Diagnostics — multi-source log correlation and health assessment.

Tools:
- diagnose_system: Comprehensive system health check with scoring
- get_error_timeline: Multi-source error event timeline
- check_resource_pressure: CPU/memory/IO pressure indicators
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

from mcp.types import ToolAnnotations

from tencentos_mcp_server.audit import log_tool_call
from tencentos_mcp_server.executor import run_cmd
from tencentos_mcp_server.sanitize import safe_positive_int
from tencentos_mcp_server.models import (
    DiagnosticReport,
    ErrorEvent,
    Problem,
    Recommendation,
    ResourcePressure,
)
from tencentos_mcp_server.server import mcp


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _score_to_status(score: int) -> str:
    if score >= 90:
        return "healthy"
    elif score >= 70:
        return "degraded"
    elif score >= 40:
        return "unhealthy"
    return "critical"


def _parse_failed_services(text: str) -> list[str]:
    """Extract failed service names from systemctl --failed output."""
    services: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if ".service" in line and ("failed" in line.lower() or "loaded" in line.lower()):
            parts = line.split()
            if parts:
                services.append(parts[0].replace("●", "").strip())
    return services


def _parse_psi(text: str) -> str:
    """Parse PSI (Pressure Stall Information) output to a summary string."""
    if not text or text.strip() == "N/A":
        return "N/A"
    # Extract avg10 from: some avg10=0.00 avg60=0.00 avg300=0.00 total=0
    match = re.search(r"some avg10=([\d.]+)", text)
    if match:
        return f"avg10={match.group(1)}%"
    return text.strip().split("\n")[0][:80]


def _psi_avg10_value(psi_summary: str) -> float:
    """从 _parse_psi 的输出里抽 avg10 数值。拿不到返回 0。"""
    if not psi_summary or psi_summary == "N/A":
        return 0.0
    m = re.search(r"avg10=([\d.]+)", psi_summary)
    if m:
        try:
            return float(m.group(1))
        except ValueError:
            return 0.0
    return 0.0


def _parse_error_lines(text: str, source: str) -> list[ErrorEvent]:
    """Parse journal/dmesg output lines into ErrorEvent list, aggregating duplicates."""
    events: list[ErrorEvent] = []
    seen: dict[str, int] = {}

    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("--"):
            continue

        # Try to extract timestamp and message
        parts = line.split(None, 3)
        ts = parts[0] if parts else ""
        unit = ""
        msg = line

        if len(parts) >= 4:
            ts = parts[0]
            unit = parts[2].rstrip(":")
            msg = parts[3]
        elif len(parts) >= 2:
            ts = parts[0]
            msg = " ".join(parts[1:])

        # Aggregate duplicates by unit+message pattern (first 60 chars)
        key = f"{unit}:{msg[:60]}"
        if key in seen:
            events[seen[key]].count += 1
            continue

        seen[key] = len(events)
        events.append(ErrorEvent(
            timestamp=ts,
            source=source,
            unit=unit,
            message=msg[:300],
            count=1,
        ))

    return events


def _detect_problems(
    journal_errors: list[ErrorEvent],
    dmesg_errors: list[ErrorEvent],
    failed_services: list[str],
    pressure: ResourcePressure,
) -> list[Problem]:
    """Correlate data from multiple sources to identify problems."""
    problems: list[Problem] = []

    # 1. Failed services
    for svc in failed_services:
        problems.append(Problem(
            severity="critical",
            category="service",
            title=f"服务 {svc} 处于失败状态",
            detail=f"systemd 服务 {svc} 当前为 failed 状态，可能影响依赖它的业务",
            evidence=[f"systemctl --failed: {svc}"],
            suggested_fix=f"检查日志: journalctl -u {svc} -n 50 --no-pager，然后根据错误信息修复并重启",
        ))

    # 2. High memory usage
    if pressure.memory_usage_pct > 90:
        problems.append(Problem(
            severity="critical",
            category="memory",
            title=f"内存使用率过高: {pressure.memory_usage_pct:.1f}%",
            detail="内存使用超过 90%，系统面临 OOM 风险",
            evidence=[f"memory usage: {pressure.memory_usage_pct:.1f}%"],
            suggested_fix="排查内存占用最高的进程: ps aux --sort=-rss | head -10，考虑增加内存或优化应用",
        ))
    elif pressure.memory_usage_pct > 80:
        problems.append(Problem(
            severity="warning",
            category="memory",
            title=f"内存使用率偏高: {pressure.memory_usage_pct:.1f}%",
            detail="内存使用超过 80%，建议关注",
            evidence=[f"memory usage: {pressure.memory_usage_pct:.1f}%"],
            suggested_fix="监控内存趋势，考虑清理缓存或扩容",
        ))

    # 3. High CPU load
    if pressure.cpu_cores > 0:
        load_ratio = pressure.load_1 / pressure.cpu_cores
        if load_ratio > 2:
            problems.append(Problem(
                severity="critical",
                category="cpu",
                title=f"CPU 负载极高: load={pressure.load_1:.1f}, cores={pressure.cpu_cores}",
                detail=f"1 分钟负载是 CPU 核数的 {load_ratio:.1f} 倍",
                evidence=[f"loadavg: {pressure.load_1}/{pressure.load_5}/{pressure.load_15}"],
                suggested_fix="排查 CPU 占用最高的进程: top -bn1 | head -20",
            ))
        elif load_ratio > 1:
            problems.append(Problem(
                severity="warning",
                category="cpu",
                title=f"CPU 负载偏高: load={pressure.load_1:.1f}, cores={pressure.cpu_cores}",
                detail=f"1 分钟负载超过 CPU 核数",
                evidence=[f"loadavg: {pressure.load_1}/{pressure.load_5}/{pressure.load_15}"],
                suggested_fix="检查是否有异常进程占用 CPU",
            ))

    # 4. Disk usage
    if pressure.disk_usage_max_pct > 90:
        problems.append(Problem(
            severity="critical",
            category="disk",
            title=f"磁盘使用率过高: {pressure.disk_usage_max_pct:.0f}%",
            detail="最高分区使用率超过 90%，可能导致写入失败",
            evidence=[f"max disk usage: {pressure.disk_usage_max_pct:.0f}%"],
            suggested_fix="清理大文件: du -sh /* | sort -rh | head -10，或扩容磁盘",
        ))

    # 5. OOM in dmesg
    oom_events = [e for e in dmesg_errors if "oom" in e.message.lower() or "out of memory" in e.message.lower()]
    if oom_events:
        problems.append(Problem(
            severity="critical",
            category="memory",
            title=f"检测到 OOM Kill 事件（{len(oom_events)} 次）",
            detail="内核 OOM Killer 已触发，有进程被强制终止",
            evidence=[e.message[:100] for e in oom_events[:3]],
            suggested_fix="增加内存或限制应用内存使用（cgroup/ulimit）",
        ))

    # 6. Frequent errors from a single unit
    unit_error_counts: dict[str, int] = {}
    for e in journal_errors:
        if e.unit:
            unit_error_counts[e.unit] = unit_error_counts.get(e.unit, 0) + e.count
    for unit, count in unit_error_counts.items():
        if count >= 10:
            problems.append(Problem(
                severity="warning",
                category="service",
                title=f"服务 {unit} 频繁报错（{count} 次）",
                detail=f"最近时间窗口内，{unit} 产生了 {count} 条错误日志",
                evidence=[e.message[:100] for e in journal_errors if e.unit == unit][:3],
                suggested_fix=f"查看详细日志: journalctl -u {unit} -p err -n 50 --no-pager",
            ))

    # 7. v0.5: PSI (Pressure Stall Information) — TencentOS 内核增强卖点
    # PSI avg10 是现代 Linux 衡量资源饥饿的标准指标，比 load average 准确
    for resource, psi_str in (
        ("cpu", pressure.cpu_pressure),
        ("memory", pressure.memory_pressure),
        ("io", pressure.io_pressure),
    ):
        avg10 = _psi_avg10_value(psi_str)
        if avg10 >= 20:
            problems.append(Problem(
                severity="critical",
                category=resource,
                title=f"{resource.upper()} PSI 压力极高：avg10={avg10}%",
                detail=(
                    f"PSI (Pressure Stall Information) 显示过去 10 秒有 {avg10}% 的时间"
                    f"进程在等待 {resource} 资源。超过 20% 意味着严重资源饥饿"
                ),
                evidence=[f"/proc/pressure/{resource}: {psi_str}"],
                suggested_fix=(
                    f"用 `cat /proc/pressure/{resource}` 看具体数值；"
                    f"用 top/iostat/ss 定位占用 {resource} 最多的进程"
                ),
            ))
        elif avg10 >= 10:
            problems.append(Problem(
                severity="warning",
                category=resource,
                title=f"{resource.upper()} PSI 压力偏高：avg10={avg10}%",
                detail=(
                    f"PSI 显示过去 10 秒有 {avg10}% 的时间进程在等 {resource}。"
                    f"比 load average 更准确的资源饥饿信号"
                ),
                evidence=[f"/proc/pressure/{resource}: {psi_str}"],
                suggested_fix=f"持续观察 `watch -n1 cat /proc/pressure/{resource}` 的趋势",
            ))

    # Sort by severity
    severity_order = {"critical": 0, "warning": 1, "info": 2}
    problems.sort(key=lambda p: severity_order.get(p.severity, 3))
    return problems


def _build_recommendations(problems: list[Problem]) -> list[Recommendation]:
    """Build prioritized recommendations from problem list."""
    recs: list[Recommendation] = []
    for p in problems:
        priority = "high" if p.severity == "critical" else "medium" if p.severity == "warning" else "low"
        recs.append(Recommendation(
            priority=priority,
            title=p.title,
            description=p.detail,
            action=p.suggested_fix,
        ))
    return recs


# ───────────────────────── Tools ─────────────────────────

@mcp.tool(
    title="Diagnose system",
    description=(
        "Comprehensive system health diagnosis: collects logs from journalctl, dmesg, "
        "systemd, and /proc; correlates errors across sources; scores system health 0-100; "
        "returns prioritized problem list with fix recommendations."
    ),
    tags={"diagnostic", "health", "logs", "tencentos"},
    annotations=ToolAnnotations(readOnlyHint=True),
)
@log_tool_call
async def diagnose_system(hours: int = 1) -> DiagnosticReport:
    """Run comprehensive system diagnosis.

    Args:
        hours: Look-back window in hours. Default 1.
    """
    hours = safe_positive_int(hours, "hours", max_val=720)
    # 1. Collect from multiple sources
    journal = await run_cmd(
        f'journalctl -p err,warning --since "{hours} hour ago" --no-pager -o short-iso 2>/dev/null | tail -200'
    )
    dmesg = await run_cmd("dmesg -T --level=err,warn 2>/dev/null | tail -100")
    failed_svc = await run_cmd("systemctl --failed --no-pager --plain 2>/dev/null")

    # 2. Resource indicators
    loadavg = await run_cmd("cat /proc/loadavg")
    cores = await run_cmd("nproc 2>/dev/null || echo 1")
    mem = await run_cmd("free -m | awk '/^Mem:/ {printf \"%.1f %d %d\", $3/$2*100, $3, $2}'")
    disk = await run_cmd("df -h --output=pcent 2>/dev/null | tail -n+2 | sort -rn | head -1")
    connections = await run_cmd("ss -s 2>/dev/null | grep estab | head -1")

    # PSI (Pressure Stall Information)
    psi_cpu = await run_cmd("cat /proc/pressure/cpu 2>/dev/null || echo 'N/A'")
    psi_mem = await run_cmd("cat /proc/pressure/memory 2>/dev/null || echo 'N/A'")
    psi_io = await run_cmd("cat /proc/pressure/io 2>/dev/null || echo 'N/A'")

    # 3. Parse data
    journal_errors = _parse_error_lines(journal.stdout, "journalctl")
    dmesg_errors = _parse_error_lines(dmesg.stdout, "dmesg")
    failed_services = _parse_failed_services(failed_svc.stdout)

    # Parse resource values
    loads = loadavg.stdout.split()
    mem_parts = mem.stdout.split()
    disk_pct_str = disk.stdout.strip().rstrip("%")

    try:
        conn_count_match = re.search(r"estab\s+(\d+)", connections.stdout)
        conn_count = int(conn_count_match.group(1)) if conn_count_match else 0
    except (ValueError, AttributeError):
        conn_count = 0

    pressure = ResourcePressure(
        cpu_pressure=_parse_psi(psi_cpu.stdout),
        memory_pressure=_parse_psi(psi_mem.stdout),
        io_pressure=_parse_psi(psi_io.stdout),
        load_1=float(loads[0]) if loads else 0,
        load_5=float(loads[1]) if len(loads) > 1 else 0,
        load_15=float(loads[2]) if len(loads) > 2 else 0,
        cpu_cores=int(cores.stdout.strip() or 1),
        memory_usage_pct=float(mem_parts[0]) if mem_parts else 0,
        disk_usage_max_pct=float(disk_pct_str) if disk_pct_str.replace(".", "").isdigit() else 0,
        network_connections=conn_count,
    )

    # 4. Correlate and detect problems
    problems = _detect_problems(journal_errors, dmesg_errors, failed_services, pressure)

    # 5. Score
    score = 100
    for p in problems:
        if p.severity == "critical":
            score -= 25
        elif p.severity == "warning":
            score -= 10
        else:
            score -= 2
    score = max(0, score)

    # 6. Merge error timeline
    all_errors = sorted(
        journal_errors + dmesg_errors,
        key=lambda e: e.timestamp,
        reverse=True,
    )[:50]

    return DiagnosticReport(
        scan_time=_now(),
        health_score=score,
        status=_score_to_status(score),
        problems=problems,
        resource_pressure=pressure,
        failed_services=failed_services,
        recent_errors=all_errors,
        recommendations=_build_recommendations(problems),
    )


@mcp.tool(
    title="Get error timeline",
    description=(
        "Get a unified error timeline from journalctl and dmesg, sorted by time. "
        "Duplicate errors are aggregated with a count."
    ),
    tags={"diagnostic", "logs", "timeline", "tencentos"},
    annotations=ToolAnnotations(readOnlyHint=True),
)
@log_tool_call
async def get_error_timeline(hours: int = 1) -> list[ErrorEvent]:
    """Get multi-source error timeline.

    Args:
        hours: Look-back window in hours. Default 1.
    """
    hours = safe_positive_int(hours, "hours", max_val=720)
    journal = await run_cmd(
        f'journalctl -p err --since "{hours} hour ago" --no-pager -o short-iso 2>/dev/null | tail -100'
    )
    dmesg = await run_cmd("dmesg -T --level=err 2>/dev/null | tail -50")

    journal_events = _parse_error_lines(journal.stdout, "journalctl")
    dmesg_events = _parse_error_lines(dmesg.stdout, "dmesg")

    merged = sorted(
        journal_events + dmesg_events,
        key=lambda e: e.timestamp,
        reverse=True,
    )
    return merged[:100]


@mcp.tool(
    title="Check resource pressure",
    description=(
        "Check system resource pressure indicators including PSI (Pressure Stall Information), "
        "load averages, memory/disk usage, and network connection count."
    ),
    tags={"diagnostic", "performance", "pressure", "tencentos"},
    annotations=ToolAnnotations(readOnlyHint=True),
)
@log_tool_call
async def check_resource_pressure() -> ResourcePressure:
    loadavg = await run_cmd("cat /proc/loadavg")
    cores = await run_cmd("nproc 2>/dev/null || echo 1")
    mem = await run_cmd("free -m | awk '/^Mem:/ {printf \"%.1f\", $3/$2*100}'")
    disk = await run_cmd("df -h --output=pcent 2>/dev/null | tail -n+2 | sort -rn | head -1")
    connections = await run_cmd("ss -s 2>/dev/null | grep estab | head -1")

    psi_cpu = await run_cmd("cat /proc/pressure/cpu 2>/dev/null || echo 'N/A'")
    psi_mem = await run_cmd("cat /proc/pressure/memory 2>/dev/null || echo 'N/A'")
    psi_io = await run_cmd("cat /proc/pressure/io 2>/dev/null || echo 'N/A'")

    loads = loadavg.stdout.split()
    disk_pct_str = disk.stdout.strip().rstrip("%")

    try:
        conn_match = re.search(r"estab\s+(\d+)", connections.stdout)
        conn_count = int(conn_match.group(1)) if conn_match else 0
    except (ValueError, AttributeError):
        conn_count = 0

    return ResourcePressure(
        cpu_pressure=_parse_psi(psi_cpu.stdout),
        memory_pressure=_parse_psi(psi_mem.stdout),
        io_pressure=_parse_psi(psi_io.stdout),
        load_1=float(loads[0]) if loads else 0,
        load_5=float(loads[1]) if len(loads) > 1 else 0,
        load_15=float(loads[2]) if len(loads) > 2 else 0,
        cpu_cores=int(cores.stdout.strip() or 1),
        memory_usage_pct=float(mem.stdout) if mem.stdout else 0,
        disk_usage_max_pct=float(disk_pct_str) if disk_pct_str.replace(".", "").isdigit() else 0,
        network_connections=conn_count,
    )
