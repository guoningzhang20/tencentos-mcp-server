"""① Patch Impact Assessment — evaluate before you patch.

Tools:
- assess_patch_impact: Full impact analysis of available security patches
- list_security_advisories: List available security advisories with CVE details
- check_patch_dependencies: Check dependency chain of a specific package update

Data sources:
- Local: yum updateinfo list security
- Remote CVE DB: https://mirrors.tencent.com/tlinux/errata/cve.xml
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Optional
from urllib.request import urlopen

from mcp.types import ToolAnnotations

from tencentos_mcp_server.audit import log_tool_call
from tencentos_mcp_server.executor import run_cmd
from tencentos_mcp_server.models import ImpactSummary, PatchDetail, PatchImpactReport
from tencentos_mcp_server.server import mcp

CVE_DB_URL = "https://mirrors.tencent.com/tlinux/errata/cve.xml"

# Packages that require a full reboot when updated
_REBOOT_PACKAGES = {"kernel", "kernel-core", "kernel-modules", "glibc", "systemd", "dbus", "linux-firmware"}

# Shared library packages — services using them need restart
_SHARED_LIB_PACKAGES = {"openssl", "openssl-libs", "zlib", "libcurl", "nss", "gnutls", "libxml2", "libssh2"}


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_updateinfo(text: str) -> list[dict]:
    """Parse 'yum updateinfo list security' output."""
    entries: list[dict] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("Loaded") or line.startswith("Updated"):
            continue
        # Format: ADVISORY_ID  severity  package_name
        parts = line.split(None, 2)
        if len(parts) >= 3:
            entries.append({
                "advisory_id": parts[0],
                "severity": _normalize_severity(parts[1]),
                "package": parts[2],
            })
        elif len(parts) == 2:
            entries.append({"advisory_id": parts[0], "severity": "Unknown", "package": parts[1]})
    return entries


def _normalize_severity(sev: str) -> str:
    sev_lower = sev.lower().strip("/:")
    mapping = {
        "critical": "Critical",
        "important": "Important",
        "moderate": "Moderate",
        "low": "Low",
    }
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
    """Extract CVE IDs from changelog text."""
    return list(set(re.findall(r"CVE-\d{4}-\d{4,}", changelog, re.IGNORECASE)))


def _classify_impact(pkg_name: str, needs_restart_services: list[str], running_services: list[str]) -> tuple[str, list[str]]:
    """Classify the impact level of updating a package."""
    base_name = pkg_name.split("-")[0] if "-" in pkg_name else pkg_name

    if base_name in _REBOOT_PACKAGES:
        return "需重启系统", running_services[:5]  # All services affected

    if base_name in _SHARED_LIB_PACKAGES:
        affected = [s for s in needs_restart_services if s.strip()]
        return "需重启服务", affected[:10]

    # Check if this package name matches any running service
    matched_services = [s for s in running_services if base_name in s.lower()]
    if matched_services:
        return "需重启服务", matched_services

    return "无需重启", []


def _build_recommendations(patches: list[PatchDetail], summary: ImpactSummary) -> list[str]:
    """Generate human-readable recommendations."""
    recs: list[str] = []

    if summary.requires_reboot > 0:
        reboot_pkgs = [p.package_name for p in patches if p.impact_level == "需重启系统"]
        recs.append(
            f"⚠️ 有 {summary.requires_reboot} 个补丁需要重启系统才能生效"
            f"（{', '.join(reboot_pkgs[:3])}），建议在维护窗口执行"
        )

    if summary.requires_service_restart > 0:
        svc_set = set()
        for p in patches:
            if p.impact_level == "需重启服务":
                svc_set.update(p.affected_services)
        if svc_set:
            recs.append(
                f"🔄 有 {summary.requires_service_restart} 个补丁需要重启以下服务：{', '.join(list(svc_set)[:5])}"
            )

    if summary.no_restart_needed > 0:
        recs.append(f"✅ 有 {summary.no_restart_needed} 个低风险补丁可直接安装，不影响业务")

    critical_patches = [p for p in patches if p.severity == "Critical"]
    if critical_patches:
        recs.insert(0, f"🚨 有 {len(critical_patches)} 个 Critical 级别安全补丁，建议优先处理")

    if not recs:
        recs.append("✅ 当前系统已是最新，无需更新")

    return recs


# ───────────────────────── Tools ─────────────────────────

@mcp.tool(
    title="Assess patch impact",
    description=(
        "Evaluate available security patches and their impact on running services. "
        "Shows which patches require reboot, which need service restarts, and gives "
        "prioritized fix recommendations. Read-only — does NOT apply any patches."
    ),
    tags={"patch", "security", "impact", "tencentos"},
    annotations=ToolAnnotations(readOnlyHint=True),
)
@log_tool_call
async def assess_patch_impact() -> PatchImpactReport:
    # 1. Get available security patches
    updateinfo = await run_cmd("yum updateinfo list security 2>/dev/null || echo ''")
    check_update = await run_cmd("yum check-update --security 2>/dev/null; true")

    # 2. Get services that need restart (from previous updates)
    needs_restart = await run_cmd("needs-restarting -s 2>/dev/null || echo ''")
    restart_services = [s.strip() for s in needs_restart.stdout.splitlines() if s.strip()]

    # 3. Get currently running services
    running = await run_cmd(
        "systemctl list-units --type=service --state=running --no-pager --plain --no-legend 2>/dev/null"
    )
    running_services = []
    for line in running.stdout.splitlines():
        parts = line.split()
        if parts:
            running_services.append(parts[0].replace(".service", ""))

    # 4. Parse advisories and available updates
    advisories = _parse_updateinfo(updateinfo.stdout)
    available_updates = _parse_check_update(check_update.stdout)

    # Build advisory lookup
    advisory_map: dict[str, dict] = {}
    for adv in advisories:
        pkg = adv["package"]
        advisory_map[pkg] = adv

    # 5. Analyze each available update
    patches: list[PatchDetail] = []
    for pkg in available_updates:
        pkg_name = pkg["name"]

        # Get changelog for CVEs
        changelog = await run_cmd(f"rpm -q --changelog {pkg_name} 2>/dev/null | head -30")
        cves = _extract_cves_from_changelog(changelog.stdout)

        # Find matching advisory
        adv = advisory_map.get(pkg.get("full", ""), {})
        severity = adv.get("severity", "Unknown")

        # Classify impact
        impact_level, affected = _classify_impact(pkg_name, restart_services, running_services)

        patches.append(PatchDetail(
            advisory_id=adv.get("advisory_id", ""),
            package_name=pkg_name,
            current_version="",  # Would need rpm -q to get current
            available_version=pkg["version"],
            severity=severity,
            cve_ids=cves,
            impact_level=impact_level,
            affected_services=affected,
            changelog_summary=changelog.stdout[:200] if changelog.stdout else "",
        ))

    # 6. Build summary
    summary = ImpactSummary(
        requires_reboot=sum(1 for p in patches if p.impact_level == "需重启系统"),
        requires_service_restart=sum(1 for p in patches if p.impact_level == "需重启服务"),
        no_restart_needed=sum(1 for p in patches if p.impact_level == "无需重启"),
        affected_running_services=list(set(
            svc for p in patches for svc in p.affected_services
        )),
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

    # Group by severity
    by_severity: dict[str, int] = {}
    for adv in advisories:
        sev = adv.get("severity", "Unknown")
        by_severity[sev] = by_severity.get(sev, 0) + 1

    return {
        "total": len(advisories),
        "by_severity": by_severity,
        "advisories": advisories[:50],  # Cap at 50 for readability
    }


@mcp.tool(
    title="Check patch dependencies",
    description=(
        "Check the dependency chain and potential impact of updating a specific package. "
        "Shows what other packages depend on it and which running services use it."
    ),
    tags={"patch", "dependency", "tencentos"},
    annotations=ToolAnnotations(readOnlyHint=True),
)
@log_tool_call
async def check_patch_dependencies(package_name: str) -> dict:
    """Check dependency chain for a package.

    Args:
        package_name: Package to analyze, e.g. 'openssl', 'kernel'.
    """
    # What depends on this package
    rdeps = await run_cmd(f"rpm -q --whatrequires {package_name} 2>/dev/null || echo 'Not installed'")
    # What this package requires
    deps = await run_cmd(f"rpm -q --requires {package_name} 2>/dev/null || echo 'Not installed'")
    # Check if update is available
    update_check = await run_cmd(f"yum check-update {package_name} 2>/dev/null; true")
    # Current version
    current = await run_cmd(f"rpm -q {package_name} 2>/dev/null || echo 'Not installed'")

    # Classify impact
    base = package_name.split("-")[0]
    if base in _REBOOT_PACKAGES:
        impact = "需重启系统"
    elif base in _SHARED_LIB_PACKAGES:
        impact = "需重启依赖服务"
    else:
        impact = "需重启该服务"

    reverse_deps = [l.strip() for l in rdeps.stdout.splitlines() if l.strip() and "no package" not in l.lower()]

    return {
        "package": package_name,
        "current_version": current.stdout.strip(),
        "update_available": bool(update_check.stdout.strip() and "No packages" not in update_check.stdout),
        "impact_level": impact,
        "reverse_dependencies_count": len(reverse_deps),
        "reverse_dependencies": reverse_deps[:20],
        "dependencies": [l.strip() for l in deps.stdout.splitlines() if l.strip()][:20],
    }
