"""① Patch Impact Assessment — evaluate before you patch.

v0.4 — Runtime-aware 升级：从"包维度静态白名单"升级为"进程维度运行时事实"。

核心链路：
    /proc/<pid>/maps  →  .so 文件路径  →  rpm -qf  →  归属包
    ↓                                                     ↓
    关联 pid → comm → systemd unit                       → 每个包当前正被哪些进程加载

Tools:
- assess_patch_impact: 补丁影响全景分析（运行时事实驱动）
- list_security_advisories: 安全公告列表
- check_patch_dependencies: 单包依赖链 + 运行时进程视图

Data sources:
- Local: yum updateinfo list security / /proc/*/maps / rpm -qf
- Remote CVE DB: https://mirrors.tencent.com/tlinux/errata/cve.xml
"""

from __future__ import annotations

import re
from collections import defaultdict
from datetime import datetime, timezone

from mcp.types import ToolAnnotations

from tencentos_mcp_server.audit import log_tool_call
from tencentos_mcp_server.executor import run_cmd
from tencentos_mcp_server.models import ImpactSummary, PatchDetail, PatchImpactReport
from tencentos_mcp_server.sanitize import safe_name
from tencentos_mcp_server.server import mcp

CVE_DB_URL = "https://mirrors.tencent.com/tlinux/errata/cve.xml"

# 必须重启整机才能生效的核心包（内核 / C 运行时 / init / 总线）
_REBOOT_PACKAGES = {
    "kernel", "kernel-core", "kernel-modules", "kernel-modules-core",
    "glibc", "systemd", "dbus", "dbus-broker", "linux-firmware",
}

# 典型共享库包（白名单兜底，当运行时扫描失败时使用）
# 当 /proc 扫描可用时，此列表仅作辅助参考
_SHARED_LIB_PACKAGES = {
    "openssl", "openssl-libs",
    "zlib", "zlib-ng-compat",
    "libcurl", "libcurl-minimal",
    "nss", "nspr",
    "gnutls", "libxml2", "libssh2",
    "libpam", "pam",
    "libselinux", "libsepol",
    "krb5-libs", "cyrus-sasl-lib",
    "libgcrypt", "libssh",
    "python3-libs", "python3",
    "ncurses-libs", "readline",
}


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ───────────────────────── Parsing helpers ─────────────────────────

def _parse_updateinfo(text: str) -> list[dict]:
    """Parse 'yum updateinfo list security' output.

    只保留形如 `TLSA-2026:xxxx severity package-name` 的公告行，过滤 repo 刷新日志。
    """
    entries: list[dict] = []
    advisory_re = re.compile(
        r"^(TLSA|RHSA|CESA|ALSA|ELBA|ELSA)-\d{4}[:-]\d+"
    )
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split(None, 2)
        if len(parts) < 3:
            continue
        if not advisory_re.match(parts[0]):
            continue  # 过滤 "Loaded plugin" / "Updated ..." / repo 刷新日志
        entries.append({
            "advisory_id": parts[0],
            "severity": _normalize_severity(parts[1]),
            "package": parts[2],
        })
    return entries


def _normalize_severity(sev: str) -> str:
    sev_lower = sev.lower().strip("/:")
    mapping = {"critical": "Critical", "important": "Important", "moderate": "Moderate", "low": "Low"}
    for k, v in mapping.items():
        if k in sev_lower:
            return v
    return sev.capitalize()


def _parse_check_update(text: str) -> list[dict]:
    """Parse 'yum check-update' output into package list."""
    packages: list[dict] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("Loaded") or line.startswith("Last") or "=" in line:
            continue
        parts = line.split()
        if len(parts) >= 3:
            name_arch = parts[0]
            name = name_arch.rsplit(".", 1)[0] if "." in name_arch else name_arch
            packages.append({"name": name, "full": name_arch, "version": parts[1], "repo": parts[2]})
    return packages


def _extract_cves_from_changelog(changelog: str) -> list[str]:
    return list(set(re.findall(r"CVE-\d{4}-\d{4,}", changelog, re.IGNORECASE)))


# ───────────────────────── Package name matching ─────────────────────────

def _strip_rpm_version(nvr: str) -> str:
    """rpm 输出格式 'name-version-release.arch' → 'name'。

    示例:
        openssl-libs-3.0.12-1.tl4.x86_64  → openssl-libs
        python3-libs-3.11.7-1.tl4.x86_64  → python3-libs
        kernel-core-5.14.0-362.24.1.tl4.x86_64 → kernel-core

    规则：从右往左剥掉 "-<version>-<release>.<arch>"，剩下的就是包名。
    用正则匹配最后一段看起来像版本的部分。
    """
    # 去掉架构后缀
    for arch in (".x86_64", ".aarch64", ".noarch", ".i686"):
        if nvr.endswith(arch):
            nvr = nvr[: -len(arch)]
            break
    # 剥掉 "-<version>-<release>"：找最后两个 hyphen，前面的才是 name
    parts = nvr.rsplit("-", 2)
    if len(parts) == 3 and any(c.isdigit() for c in parts[1]):
        return parts[0]
    return nvr


def _match_package_family(pkg_name: str) -> tuple[str | None, str]:
    """按"最长前缀匹配"在白名单里查包族。

    返回 (family, category)，category ∈ {'reboot', 'shared_lib', None}。

    这是对原 `pkg_name.split('-')[0]` 的修正：
        python3-libs  原逻辑 → 'python' ❌（查不到）
        python3-libs  新逻辑 → ('python3-libs', 'shared_lib') ✅
        openssl-libs  新逻辑 → ('openssl-libs', 'shared_lib') ✅
        kernel-core   新逻辑 → ('kernel-core', 'reboot') ✅
    """
    # 先查精确匹配
    if pkg_name in _REBOOT_PACKAGES:
        return pkg_name, "reboot"
    if pkg_name in _SHARED_LIB_PACKAGES:
        return pkg_name, "shared_lib"
    # 最长前缀匹配（按长度倒序，避免 "kernel" 吃掉 "kernel-core"）
    for fam in sorted(_REBOOT_PACKAGES, key=len, reverse=True):
        if pkg_name.startswith(fam + "-"):
            return fam, "reboot"
    for fam in sorted(_SHARED_LIB_PACKAGES, key=len, reverse=True):
        if pkg_name.startswith(fam + "-"):
            return fam, "shared_lib"
    return None, ""


# ───────────────────────── Runtime mapping (核心新增) ─────────────────────────

async def _build_runtime_pkg_map() -> tuple[dict[str, list[dict]], int]:
    """构建"包 → 正在使用它的进程列表"映射。

    实现路径：
        1. 遍历 /proc/[0-9]*/maps 抓所有已加载的 .so 路径
        2. 批量 rpm -qf 查归属包
        3. 反向聚合：{package_name: [{pid, comm, service}, ...]}

    返回:
        (mapping, scanned_process_count)

    若环境不支持（容器内 /proc 受限、rpm 不可用），返回 ({}, 0)，由调用方降级到白名单模式。
    """
    # 第 1 步：抓所有 pid 对应的 so 加载情况
    # awk 按行扫 /proc/*/maps，从 FILENAME 切出 pid，输出 "pid so_path"
    # 注意转义：shell 单引号包裹 awk 脚本 → 脚本内可用 " 不需 \。
    awk_cmd = (
        r"""awk 'FNR==1{split(FILENAME,a,"/");pid=a[3]} """
        r"""/\.so/{print pid" "$6}' /proc/[0-9]*/maps 2>/dev/null"""
    )
    result = await run_cmd(awk_cmd, timeout=30)
    if not result.stdout.strip():
        return {}, 0

    # 解析 pid → [so_paths]
    pid_to_sos: dict[str, set[str]] = defaultdict(set)
    all_sos: set[str] = set()
    for line in result.stdout.splitlines():
        parts = line.split(None, 1)
        if len(parts) != 2:
            continue
        pid, so_path = parts
        if not so_path.startswith("/"):
            continue
        pid_to_sos[pid].add(so_path)
        all_sos.add(so_path)

    if not all_sos:
        return {}, 0

    # 第 2 步：批量 rpm -qf 查归属包（分批避免命令行过长）
    so_to_pkg: dict[str, str] = {}
    sos_list = sorted(all_sos)
    batch_size = 100
    for i in range(0, len(sos_list), batch_size):
        batch = sos_list[i:i + batch_size]
        # 用 null 分隔传参，避免特殊字符
        quoted = " ".join(f"'{p}'" for p in batch if "'" not in p)
        if not quoted:
            continue
        rpm_result = await run_cmd(
            f"rpm -qf --queryformat '%{{NAME}}\\n' {quoted} 2>/dev/null",
            timeout=30,
        )
        # rpm -qf 按输入顺序输出；"file not owned" 错误走 stderr
        # 但混合文件时行对齐可能错位，所以逐个查更稳
        lines = rpm_result.stdout.splitlines()
        if len(lines) == len(batch):
            for so, pkg_line in zip(batch, lines):
                pkg_line = pkg_line.strip()
                if pkg_line and "not owned" not in pkg_line.lower() and not pkg_line.startswith("error"):
                    so_to_pkg[so] = pkg_line
        else:
            # 行数不对齐，降级为逐个查
            for so in batch:
                single = await run_cmd(
                    f"rpm -qf --queryformat '%{{NAME}}' '{so}' 2>/dev/null",
                    timeout=5,
                )
                pkg_line = single.stdout.strip()
                if pkg_line and "not owned" not in pkg_line.lower() and not pkg_line.startswith("error"):
                    so_to_pkg[so] = pkg_line

    # 第 3 步：为每个 pid 拉 comm 和 systemd unit
    pid_meta: dict[str, dict] = {}
    for pid in pid_to_sos.keys():
        comm_result = await run_cmd(f"cat /proc/{pid}/comm 2>/dev/null", timeout=2)
        unit_result = await run_cmd(
            f"ps -o unit= -p {pid} 2>/dev/null | head -1",
            timeout=2,
        )
        pid_meta[pid] = {
            "comm": comm_result.stdout.strip() or "unknown",
            "service": unit_result.stdout.strip().replace(".service", "") or "",
        }

    # 第 4 步：反向聚合成 pkg → [processes]
    pkg_to_procs: dict[str, list[dict]] = defaultdict(list)
    seen_pairs: set[tuple[str, str]] = set()  # 去重 (pkg, pid)
    for pid, sos in pid_to_sos.items():
        for so in sos:
            pkg = so_to_pkg.get(so)
            if not pkg:
                continue
            key = (pkg, pid)
            if key in seen_pairs:
                continue
            seen_pairs.add(key)
            meta = pid_meta.get(pid, {"comm": "unknown", "service": ""})
            pkg_to_procs[pkg].append({
                "pid": int(pid),
                "comm": meta["comm"],
                "service": meta["service"],
            })

    return dict(pkg_to_procs), len(pid_to_sos)


# ───────────────────────── Impact classification (事实驱动) ─────────────────────────

def _classify_impact(
    pkg_name: str,
    runtime_pkg_map: dict[str, list[dict]],
    runtime_map_available: bool,
    needs_restart_services: list[str],
) -> tuple[str, list[dict], list[str], str]:
    """事实驱动的影响分级。

    判定优先级：
        1. 核心包（kernel/glibc/systemd）→ 必重启系统
        2. 运行时映射命中（有进程正在加载该包）→ 需重启对应服务
        3. 白名单共享库兜底（无运行时数据时）→ 需重启依赖服务
        4. 否则 → 无需重启

    Returns:
        (impact_level, active_processes, affected_service_names, evidence)
    """
    family, category = _match_package_family(pkg_name)

    # 事实 1：核心包铁律
    if category == "reboot":
        # 即使没有运行时数据，核心包也必重启
        return (
            "需重启系统",
            [],
            [],
            f"核心包 {family or pkg_name}（内核/C 运行时/systemd）更新必须重启整机生效",
        )

    # 事实 2：运行时事实（最强证据）
    if runtime_map_available:
        # 先查精确匹配
        active = runtime_pkg_map.get(pkg_name, [])
        # 再查包族匹配（比如补丁里的 openssl，运行时加载的是 openssl-libs）
        if not active and family:
            active = runtime_pkg_map.get(family, [])

        if active:
            services = sorted({
                p["service"] for p in active if p.get("service")
            })
            return (
                "需重启服务",
                active[:20],
                services,
                f"运行时事实：当前有 {len(active)} 个进程加载了该包的 .so 文件",
            )
        # 运行时可用但查不到加载记录 → 大概率真的没进程在用
        if category == "shared_lib":
            return (
                "无需重启",
                [],
                [],
                f"{family} 是共享库，但本机当前无运行进程加载其 .so 文件",
            )
        return ("无需重启", [], [], "运行时扫描未发现进程加载该包，可安全更新")

    # 事实 3：运行时扫描不可用 → 降级到白名单兜底
    if category == "shared_lib":
        affected = [s for s in needs_restart_services if s.strip()][:10]
        return (
            "需重启服务",
            [],
            affected,
            f"{family} 属共享库（白名单兜底判定，运行时扫描不可用）",
        )

    # 事实 4：跟运行中的服务名同名（比如 nginx 包 → nginx 服务）
    matched = [
        s for s in (needs_restart_services or [])
        if pkg_name.lower() in s.lower()
    ]
    if matched:
        return (
            "需重启服务",
            [],
            matched,
            "服务名与包名匹配",
        )

    return ("无需重启", [], [], "未匹配任何重启规则，判定为无需重启")


# ───────────────────────── Recommendations ─────────────────────────

def _build_recommendations(patches: list[PatchDetail], summary: ImpactSummary) -> list[str]:
    recs: list[str] = []

    critical_patches = [p for p in patches if p.severity == "Critical"]
    if critical_patches:
        recs.append(
            f"🚨 有 {len(critical_patches)} 个 Critical 级别安全补丁，建议优先处理："
            f"{', '.join(p.package_name for p in critical_patches[:3])}"
        )

    if summary.requires_reboot > 0:
        reboot_pkgs = [p.package_name for p in patches if p.impact_level == "需重启系统"]
        recs.append(
            f"⚠️ 有 {summary.requires_reboot} 个补丁需要重启系统才能生效"
            f"（{', '.join(reboot_pkgs[:3])}），建议在维护窗口执行"
        )

    if summary.requires_service_restart > 0:
        svc_set: set[str] = set()
        pid_count = 0
        for p in patches:
            if p.impact_level == "需重启服务":
                svc_set.update(p.affected_services)
                pid_count += len(p.active_processes)
        parts = [f"🔄 有 {summary.requires_service_restart} 个补丁需要重启依赖服务"]
        if svc_set:
            parts.append(f"涉及服务：{', '.join(list(svc_set)[:5])}")
        if pid_count > 0:
            parts.append(f"当前共 {pid_count} 个进程需要重启")
        recs.append("，".join(parts))

    if summary.no_restart_needed > 0:
        recs.append(f"✅ 有 {summary.no_restart_needed} 个补丁可直接安装，不影响运行中的业务")

    if summary.runtime_pkg_map_available:
        recs.append(
            f"📊 本次分析基于运行时事实（扫描了 {summary.runtime_scanned_processes} 个进程的 .so 加载情况），"
            f"判定结果以 active_processes 字段为准"
        )
    else:
        recs.append(
            "⚠️ 运行时扫描未启用（/proc 不可访问或 rpm 不可用），已降级为白名单兜底模式。"
            "建议在目标机上直接运行 MCP Server 以获得最准确的影响评估"
        )

    if not recs:
        recs.append("✅ 当前系统已是最新，无需更新")

    return recs


# ───────────────────────── Tools ─────────────────────────

@mcp.tool(
    title="Assess patch impact",
    description=(
        "Evaluate available security patches and their impact on running services. "
        "v0.4 runtime-aware: scans /proc/*/maps to identify which processes actually "
        "load each patched package's .so files, giving process-level evidence "
        "(pid/comm/service) rather than static whitelist guesses. "
        "Read-only — does NOT apply any patches."
    ),
    tags={"patch", "security", "impact", "tencentos"},
    annotations=ToolAnnotations(readOnlyHint=True),
)
@log_tool_call
async def assess_patch_impact() -> PatchImpactReport:
    # 1. 可用安全补丁
    updateinfo = await run_cmd("yum updateinfo list security 2>/dev/null || echo ''")
    check_update = await run_cmd("yum check-update --security 2>/dev/null; true")

    # 2. 上次更新后尚未重启的服务（作为辅助证据）
    needs_restart = await run_cmd("needs-restarting -s 2>/dev/null || echo ''")
    restart_services = [s.strip() for s in needs_restart.stdout.splitlines() if s.strip()]

    # 3. 运行时包映射（核心新增）
    runtime_pkg_map, scanned_procs = await _build_runtime_pkg_map()
    runtime_available = bool(runtime_pkg_map)

    # 4. 解析公告和可用更新
    advisories = _parse_updateinfo(updateinfo.stdout)
    available_updates = _parse_check_update(check_update.stdout)

    advisory_map: dict[str, dict] = {adv["package"]: adv for adv in advisories}

    # 5. 逐包分析
    patches: list[PatchDetail] = []
    for pkg in available_updates:
        pkg_name = pkg["name"]

        # 拉 changelog 抓 CVE
        changelog = await run_cmd(f"rpm -q --changelog {pkg_name} 2>/dev/null | head -30")
        cves = _extract_cves_from_changelog(changelog.stdout)

        adv = advisory_map.get(pkg.get("full", ""), {})
        severity = adv.get("severity", "Unknown")

        impact_level, active_procs, affected_svcs, evidence = _classify_impact(
            pkg_name, runtime_pkg_map, runtime_available, restart_services
        )

        patches.append(PatchDetail(
            advisory_id=adv.get("advisory_id", ""),
            package_name=pkg_name,
            current_version="",
            available_version=pkg["version"],
            severity=severity,
            cve_ids=cves,
            impact_level=impact_level,
            affected_services=affected_svcs,
            active_processes=active_procs,
            evidence=evidence,
            changelog_summary=changelog.stdout[:200] if changelog.stdout else "",
        ))

    # 6. 汇总
    summary = ImpactSummary(
        requires_reboot=sum(1 for p in patches if p.impact_level == "需重启系统"),
        requires_service_restart=sum(1 for p in patches if p.impact_level == "需重启服务"),
        no_restart_needed=sum(1 for p in patches if p.impact_level == "无需重启"),
        affected_running_services=sorted({
            svc for p in patches for svc in p.affected_services
        }),
        runtime_scanned_processes=scanned_procs,
        runtime_pkg_map_available=runtime_available,
    )

    return PatchImpactReport(
        scan_time=_now(),
        total_available_patches=len(patches),
        security_patches=sum(1 for p in patches if p.severity in ("Critical", "Important")),
        patches=patches,
        impact_summary=summary,
        recommendations=_build_recommendations(patches, summary),
    )


@mcp.tool(
    title="List security advisories",
    description=(
        "List available security fix advisories for this system, including "
        "advisory ID, severity, and affected package names."
    ),
    tags={"patch", "security", "cve", "tencentos"},
    annotations=ToolAnnotations(readOnlyHint=True),
)
@log_tool_call
async def list_security_advisories() -> dict:
    result = await run_cmd("yum updateinfo list security 2>/dev/null || echo 'No advisories available'")
    advisories = _parse_updateinfo(result.stdout)

    by_severity: dict[str, int] = {}
    for adv in advisories:
        sev = adv.get("severity", "Unknown")
        by_severity[sev] = by_severity.get(sev, 0) + 1

    return {
        "total": len(advisories),
        "by_severity": by_severity,
        "advisories": advisories[:50],
    }


@mcp.tool(
    title="Check patch dependencies",
    description=(
        "Analyze dependency chain + runtime process view for a specific package. "
        "Unlike plain `rpm --whatrequires` (static tree), this also shows which "
        "processes are CURRENTLY loading this package's .so files, answering "
        "'if I update openssl now, which 2 out of 20 dependent packages actually matter?'"
    ),
    tags={"patch", "dependency", "runtime", "tencentos"},
    annotations=ToolAnnotations(readOnlyHint=True),
)
@log_tool_call
async def check_patch_dependencies(package_name: str) -> dict:
    """Check dependency chain + runtime process view for a package.

    Args:
        package_name: Package to analyze, e.g. 'openssl', 'kernel'.
    """
    package_name = safe_name(package_name, "package_name")

    # 静态依赖图
    rdeps = await run_cmd(f"rpm -q --whatrequires {package_name} 2>/dev/null || echo 'Not installed'")
    deps = await run_cmd(f"rpm -q --requires {package_name} 2>/dev/null || echo 'Not installed'")
    update_check = await run_cmd(f"yum check-update {package_name} 2>/dev/null; true")
    current = await run_cmd(f"rpm -q {package_name} 2>/dev/null || echo 'Not installed'")

    # 运行时事实：哪些进程正在加载这个包的文件
    runtime_pkg_map, scanned_procs = await _build_runtime_pkg_map()
    active_processes: list[dict] = []
    if runtime_pkg_map:
        # 精确匹配 + 包族匹配都试一下
        active_processes = runtime_pkg_map.get(package_name, [])
        if not active_processes:
            family, _ = _match_package_family(package_name)
            if family:
                active_processes = runtime_pkg_map.get(family, [])

    # 分级
    family, category = _match_package_family(package_name)
    if category == "reboot":
        impact = "需重启系统"
        evidence = f"核心包 {family or package_name} 更新必须重启整机"
    elif active_processes:
        impact = "需重启依赖服务"
        evidence = f"运行时事实：当前有 {len(active_processes)} 个进程加载了该包"
    elif category == "shared_lib":
        impact = "可能需重启依赖服务"
        evidence = f"{family} 是共享库（白名单判定）"
    else:
        impact = "需重启该服务"
        evidence = "可能仅影响该服务自身"

    reverse_deps = [
        l.strip() for l in rdeps.stdout.splitlines()
        if l.strip() and "no package" not in l.lower()
    ]

    return {
        "package": package_name,
        "current_version": current.stdout.strip(),
        "update_available": bool(
            update_check.stdout.strip() and "No packages" not in update_check.stdout
        ),
        "impact_level": impact,
        "evidence": evidence,
        # 静态视图
        "reverse_dependencies_count": len(reverse_deps),
        "reverse_dependencies": reverse_deps[:20],
        "dependencies": [l.strip() for l in deps.stdout.splitlines() if l.strip()][:20],
        # 运行时视图（核心新增）
        "active_processes_count": len(active_processes),
        "active_processes": active_processes[:20],
        "runtime_scan_available": bool(runtime_pkg_map),
        "scanned_process_total": scanned_procs,
    }
