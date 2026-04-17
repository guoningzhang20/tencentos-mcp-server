"""④ Patch History — patch version management and gap analysis.

Tools:
- get_patch_history: Patch installation history timeline
- compare_patch_status: Gap analysis — current vs latest available
- get_kernel_history: Kernel version history + hotfix status
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from urllib.request import urlopen, Request
from urllib.error import URLError

from mcp.types import ToolAnnotations

from tencentos_mcp_server.audit import log_tool_call
from tencentos_mcp_server.executor import run_cmd
from tencentos_mcp_server.models import (
    CVEInfo,
    KernelVersion,
    OutdatedPackage,
    PackageChange,
    PatchGapReport,
    PatchHistoryReport,
    PatchTransaction,
)
from tencentos_mcp_server.server import mcp

CVE_DB_URL = "https://mirrors.tencent.com/tlinux/errata/cve.xml"


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_history_list(text: str) -> list[dict]:
    """Parse 'dnf history list' output into transaction dicts."""
    transactions: list[dict] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("ID") or line.startswith("=") or line.startswith("-"):
            continue
        parts = line.split("|")
        if len(parts) >= 4:
            try:
                tid = int(parts[0].strip())
            except ValueError:
                continue
            transactions.append({
                "id": tid,
                "user": parts[1].strip() if len(parts) > 1 else "",
                "date": parts[2].strip() if len(parts) > 2 else "",
                "action": parts[3].strip() if len(parts) > 3 else "",
                "packages": parts[4].strip() if len(parts) > 4 else "",
            })
        else:
            # Alternative format without pipes
            parts2 = line.split()
            if parts2 and parts2[0].isdigit():
                transactions.append({
                    "id": int(parts2[0]),
                    "user": parts2[1] if len(parts2) > 1 else "",
                    "date": " ".join(parts2[2:5]) if len(parts2) > 4 else "",
                    "action": parts2[5] if len(parts2) > 5 else "",
                    "packages": "",
                })
    return transactions


def _parse_history_info(text: str) -> PatchTransaction:
    """Parse 'dnf history info <id>' output into PatchTransaction."""
    tid = 0
    timestamp = ""
    user = ""
    action = ""
    return_code = ""
    packages: list[PackageChange] = []

    for line in text.splitlines():
        line = line.strip()
        if line.startswith("Transaction ID"):
            try:
                tid = int(line.split(":")[-1].strip())
            except ValueError:
                pass
        elif line.startswith("Begin time"):
            timestamp = line.split(":", 1)[-1].strip()
        elif line.startswith("User"):
            user = line.split(":", 1)[-1].strip()
        elif line.startswith("Return-Code") or line.startswith("Return code"):
            return_code = line.split(":", 1)[-1].strip()
        elif line.startswith("Command Line"):
            action = line.split(":", 1)[-1].strip()
        elif any(line.startswith(prefix) for prefix in ("Install", "Update", "Upgraded", "Erase", "Removed", "Downgrade")):
            pkg_action = line.split()[0] if line.split() else ""
            pkg_rest = line[len(pkg_action):].strip()
            # Parse package name-version.arch
            pkg_parts = pkg_rest.split()
            if pkg_parts:
                packages.append(PackageChange(
                    package_name=pkg_parts[0],
                    action=pkg_action,
                    version=pkg_parts[1] if len(pkg_parts) > 1 else "",
                    arch=pkg_parts[2] if len(pkg_parts) > 2 else "",
                    repo=pkg_parts[3] if len(pkg_parts) > 3 else "",
                ))

    return PatchTransaction(
        transaction_id=tid,
        timestamp=timestamp,
        user=user,
        action=action,
        packages=packages,
        return_code=return_code,
    )


def _parse_rpm_last(text: str) -> list[dict]:
    """Parse 'rpm -qa --last' output."""
    entries: list[dict] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        # Format: package-name-version.arch   date
        parts = line.split(None, 1)
        if len(parts) >= 2:
            entries.append({"package": parts[0], "date": parts[1].strip()})
        elif parts:
            entries.append({"package": parts[0], "date": ""})
    return entries


def _fetch_cve_database() -> list[CVEInfo]:
    """Fetch and parse TencentOS CVE database XML. Graceful on failure."""
    try:
        req = Request(CVE_DB_URL, headers={"User-Agent": "TencentOS-MCP-Server/0.1"})
        with urlopen(req, timeout=10) as resp:
            data = resp.read()
        root = ET.fromstring(data)

        cves: list[CVEInfo] = []
        # Parse XML — structure may vary, try common patterns
        for item in root.iter():
            if "cve" in item.tag.lower():
                cve_id = item.findtext("id", "") or item.get("id", "") or item.text or ""
                if cve_id and cve_id.startswith("CVE-"):
                    cves.append(CVEInfo(
                        cve_id=cve_id,
                        severity=item.findtext("severity", "Unknown") or "Unknown",
                        description=item.findtext("description", "")[:200] or "",
                        affected_package=item.findtext("package", "") or "",
                        fixed_version=item.findtext("fixed_version", "") or "",
                    ))
        return cves
    except (URLError, ET.ParseError, Exception):
        return []


def _parse_check_update_packages(text: str) -> list[OutdatedPackage]:
    """Parse yum check-update output."""
    packages: list[OutdatedPackage] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("Loaded") or line.startswith("Last") or "=" in line:
            continue
        parts = line.split()
        if len(parts) >= 3:
            name_arch = parts[0]
            name = name_arch.rsplit(".", 1)[0] if "." in name_arch else name_arch
            packages.append(OutdatedPackage(
                package_name=name,
                available_version=parts[1],
            ))
    return packages


# ───────────────────────── Tools ─────────────────────────

@mcp.tool(
    title="Get patch history",
    description=(
        "Query patch installation history: when each patch was applied, by whom, "
        "and what packages were changed. Includes kernel version timeline."
    ),
    tags={"patch", "history", "version", "tencentos"},
    annotations=ToolAnnotations(readOnlyHint=True),
)
@log_tool_call
async def get_patch_history(last_n: int = 20) -> PatchHistoryReport:
    """Get patch installation history.

    Args:
        last_n: Number of recent transactions to show. Default 20.
    """
    # Get history list
    history = await run_cmd(f"dnf history list 2>/dev/null || yum history list 2>/dev/null || echo ''")
    parsed = _parse_history_list(history.stdout)
    recent = parsed[:last_n]

    # Get details for each transaction
    transactions: list[PatchTransaction] = []
    for txn in recent[:10]:  # Limit detail queries to 10 for performance
        detail = await run_cmd(f"dnf history info {txn['id']} 2>/dev/null || yum history info {txn['id']} 2>/dev/null")
        transactions.append(_parse_history_info(detail.stdout))

    # Kernel history
    kernel_pkgs = await run_cmd("rpm -qa 'kernel*' --last 2>/dev/null || echo ''")
    current_kernel = await run_cmd("uname -r")
    hotfix = await run_cmd("kpatch list 2>/dev/null || echo ''")

    kernel_versions: list[KernelVersion] = []
    for entry in _parse_rpm_last(kernel_pkgs.stdout):
        pkg = entry["package"]
        if "kernel-core" in pkg or (pkg.startswith("kernel-") and "devel" not in pkg and "headers" not in pkg):
            version = pkg.replace("kernel-core-", "").replace("kernel-", "")
            kernel_versions.append(KernelVersion(
                version=version,
                install_time=entry["date"],
                is_running=current_kernel.stdout.strip() in version,
                hotfix_loaded="loaded" in hotfix.stdout.lower(),
                hotfix_detail=hotfix.stdout[:200] if hotfix.stdout and hotfix.stdout != "N/A" else "",
            ))

    return PatchHistoryReport(
        query_period=f"最近 {last_n} 次事务",
        total_transactions=len(parsed),
        transactions=transactions,
        kernel_history=kernel_versions[:10],
    )


@mcp.tool(
    title="Compare patch status",
    description=(
        "Gap analysis: compare currently installed package versions against latest "
        "available versions. Cross-references with TencentOS CVE database to show "
        "unfixed vulnerabilities."
    ),
    tags={"patch", "gap", "cve", "tencentos"},
    annotations=ToolAnnotations(readOnlyHint=True),
)
@log_tool_call
async def compare_patch_status() -> PatchGapReport:
    current_kernel = await run_cmd("uname -r")
    check_update = await run_cmd("yum check-update 2>/dev/null; true")
    security_info = await run_cmd("yum updateinfo list security 2>/dev/null || echo ''")

    # Parse available updates
    outdated = _parse_check_update_packages(check_update.stdout)

    # Get installed versions for outdated packages (batch)
    if outdated:
        pkg_names = " ".join(p.package_name for p in outdated[:30])
        installed = await run_cmd(f"rpm -q {pkg_names} 2>/dev/null || echo ''")
        installed_map: dict[str, str] = {}
        for line in installed.stdout.splitlines():
            if "not installed" not in line.lower() and line.strip():
                # Extract name and version from rpm output like: openssl-1.1.1k-7.el8
                name = line.rsplit("-", 2)[0] if line.count("-") >= 2 else line
                installed_map[name] = line.strip()
        for pkg in outdated:
            pkg.installed_version = installed_map.get(pkg.package_name, "")

    # Parse security advisories to enrich with severity
    for line in security_info.stdout.splitlines():
        parts = line.split(None, 2)
        if len(parts) >= 3:
            severity = parts[1].lower()
            pkg_str = parts[2]
            for pkg in outdated:
                if pkg.package_name in pkg_str:
                    if "critical" in severity:
                        pkg.severity = "Critical"
                    elif "important" in severity:
                        pkg.severity = "Important"
                    elif "moderate" in severity:
                        pkg.severity = "Moderate"
                    elif "low" in severity:
                        pkg.severity = "Low"

    # Fetch CVE database (best-effort)
    cve_data = _fetch_cve_database()

    # Cross-reference
    unfixed: list[CVEInfo] = []
    outdated_names = {p.package_name for p in outdated}
    for cve in cve_data:
        if cve.affected_package in outdated_names:
            unfixed.append(cve)
            # Add CVE to matching package
            for pkg in outdated:
                if pkg.package_name == cve.affected_package:
                    pkg.related_cves.append(cve.cve_id)

    # Detect latest kernel
    latest_kernel = ""
    for pkg in outdated:
        if "kernel" in pkg.package_name.lower():
            latest_kernel = pkg.available_version
            break

    return PatchGapReport(
        scan_time=_now(),
        current_kernel=current_kernel.stdout.strip(),
        latest_kernel=latest_kernel or current_kernel.stdout.strip(),
        total_outdated=len(outdated),
        critical_outdated=sum(1 for p in outdated if p.severity in ("Critical", "Important")),
        outdated_packages=outdated[:50],
        unfixed_cves=unfixed[:30],
    )


@mcp.tool(
    title="Get kernel history",
    description=(
        "Get kernel version change history, including installed kernels, "
        "currently running kernel, and kpatch hotfix status."
    ),
    tags={"patch", "kernel", "tencentos"},
    annotations=ToolAnnotations(readOnlyHint=True),
)
@log_tool_call
async def get_kernel_history() -> list[KernelVersion]:
    kernel_pkgs = await run_cmd("rpm -qa 'kernel*' --last 2>/dev/null || echo ''")
    current = await run_cmd("uname -r")
    hotfix = await run_cmd("kpatch list 2>/dev/null || echo ''")
    grub = await run_cmd("grubby --info=ALL 2>/dev/null | grep -E '^(index|kernel|title)' || echo ''")

    versions: list[KernelVersion] = []
    for entry in _parse_rpm_last(kernel_pkgs.stdout):
        pkg = entry["package"]
        if "kernel-core" in pkg or (
            pkg.startswith("kernel-") and "devel" not in pkg and "headers" not in pkg and "tools" not in pkg
        ):
            version = pkg.replace("kernel-core-", "").replace("kernel-", "").split(".")[0:4]
            ver_str = ".".join(version) if version else pkg
            versions.append(KernelVersion(
                version=ver_str,
                install_time=entry["date"],
                is_running=current.stdout.strip() in pkg,
                hotfix_loaded="loaded" in hotfix.stdout.lower() if current.stdout.strip() in pkg else False,
                hotfix_detail=hotfix.stdout[:200] if hotfix.stdout.strip() and hotfix.stdout.strip() != "N/A" else "",
            ))

    return versions[:20]
