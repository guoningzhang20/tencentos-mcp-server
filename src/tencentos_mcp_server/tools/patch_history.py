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
from tencentos_mcp_server.sanitize import safe_positive_int
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


def _cvss_to_vendor_severity(cvss: float) -> str:
    """CVSS 分数 → 厂商级别（当 vendor severity 缺失时兜底）。

    NVD/TencentOS 通用映射：
      Critical ≥ 9.0 / Important ≥ 7.0 / Moderate ≥ 4.0 / Low > 0 / Unknown = 0
    """
    if cvss >= 9.0:
        return "Critical"
    if cvss >= 7.0:
        return "Important"
    if cvss >= 4.0:
        return "Moderate"
    if cvss > 0:
        return "Low"
    return "Unknown"


def _normalize_cvss(raw: str) -> float:
    """把 XML 里的 cvss 字段（可能是 '9.8' / 'CVSS:3.1/9.8' / '' ）转成 float。"""
    if not raw:
        return 0.0
    # 提取第一个浮点数
    m = re.search(r"(\d+\.\d+|\d+)", raw)
    if not m:
        return 0.0
    try:
        val = float(m.group(1))
        # CVSS v3 最大 10
        return max(0.0, min(10.0, val))
    except ValueError:
        return 0.0


def _fetch_cve_database() -> tuple[list[CVEInfo], str, str]:
    """Fetch and parse TencentOS errata XML.

    Returns:
        (cves, status, detail)
        status ∈ {"loaded", "partial", "failed"}

    实际 XML 结构（https://mirrors.tencent.com/tlinux/errata/cve.xml）:
        <updates>
          <update type="security">
            <id>TSSA-2022:0001</id>
            <severity>Moderate</severity>
            <pkglist><package name="java-1.8.0-openjdk" .../></pkglist>
            <description>
              ... CVE-2021-35550: ... CVSS 3.1 Base Score 5.9 ...
              ... CVE-2021-35556: ... CVSS 3.1 Base Score 3.7 ...
            </description>
          </update>
          ...
        </updates>

    每个 <update> 可能包含多个 CVE（列在 description 里），我们把它展平成
    独立的 CVEInfo 条目，共享 vendor severity 但分别抽取 CVSS 分数。
    """
    try:
        req = Request(CVE_DB_URL, headers={"User-Agent": "TencentOS-MCP-Server/0.5"})
        with urlopen(req, timeout=15) as resp:
            data = resp.read()
    except URLError as e:
        return [], "failed", f"网络错误：{type(e).__name__}: {e}"
    except Exception as e:  # noqa: BLE001
        return [], "failed", f"下载 CVE XML 失败：{type(e).__name__}"

    try:
        root = ET.fromstring(data)
    except ET.ParseError as e:
        return [], "failed", f"XML 解析失败：{e}"

    updates = root.findall(".//update")
    if not updates:
        return [], "partial", "XML 结构异常：未找到 <update> 节点"

    # 正则：从 description 抽取 CVE-YYYY-NNNN: ...... 段落
    # 每段以 "CVE-xxxx-xxxx:" 开头，到下一个 CVE 开头或文本结束
    cve_section_re = re.compile(
        r"(CVE-\d{4}-\d{4,}):\s*(.*?)(?=CVE-\d{4}-\d{4,}:|$)",
        re.DOTALL,
    )
    # CVSS 分数正则：CVSS[空白]3.x Base Score N.N
    cvss_re = re.compile(r"CVSS[\s:.\dv]*Base Score\s*(\d+\.\d+)", re.IGNORECASE)

    cves: list[CVEInfo] = []
    errors = 0
    for upd in updates:
        try:
            vendor_sev = (upd.findtext("severity", "") or "").strip().capitalize() or "Unknown"
            description = upd.findtext("description", "") or ""
            # 包名：取 pkglist/package/@name，可能多个
            pkg_nodes = upd.findall(".//package")
            pkg_names = [p.get("name", "") for p in pkg_nodes if p.get("name")]
            primary_pkg = pkg_names[0] if pkg_names else ""
            # 修复版本：package 节点上的 version
            fixed_version = pkg_nodes[0].get("version", "") if pkg_nodes else ""

            matched = False
            for m in cve_section_re.finditer(description):
                cve_id = m.group(1)
                body = m.group(2)
                cvss_m = cvss_re.search(body)
                cvss_val = _normalize_cvss(cvss_m.group(1)) if cvss_m else 0.0
                # vendor severity 缺失时用 CVSS 回推
                sev = vendor_sev if vendor_sev != "Unknown" else _cvss_to_vendor_severity(cvss_val)

                cves.append(CVEInfo(
                    cve_id=cve_id,
                    vendor_severity=sev,
                    cvss_score=cvss_val,
                    severity=sev,  # 兼容旧字段
                    description=body.strip()[:200],
                    affected_package=primary_pkg,
                    fixed_version=fixed_version,
                ))
                matched = True

            # 如果 description 里没抽到 CVE，但 advisory 本身是 security 类型，
            # 至少保留一条以 TSSA id 为键的占位记录（避免丢 advisory）
            if not matched:
                tssa_id = upd.findtext("id", "") or ""
                if tssa_id:
                    # 不是 CVE 格式就跳过，保持"只存 CVE-*"的纯净
                    pass
        except Exception:  # noqa: BLE001
            errors += 1
            continue

    status = "loaded"
    if errors > 0 and errors >= len(updates) * 0.1:
        status = "partial"
    detail = f"解析 {len(updates)} 个 advisory，展平为 {len(cves)} 条 CVE"
    if errors:
        detail += f"，{errors} 条 advisory 解析失败"
    return cves, status, detail


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
    last_n = safe_positive_int(last_n, "last_n", max_val=100)
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

    # Fetch CVE database (best-effort) — v0.5: 带状态
    cve_data, cve_status, cve_detail = _fetch_cve_database()

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

    # v0.5: Top 3 风险 —— 按 CVSS 降序，CVSS 为 0 的用 vendor_severity 兜底排序
    severity_rank = {"Critical": 4, "Important": 3, "Moderate": 2, "Low": 1, "Unknown": 0}
    top_risks = sorted(
        unfixed,
        key=lambda c: (c.cvss_score, severity_rank.get(c.vendor_severity, 0)),
        reverse=True,
    )[:3]

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
        top_risks=top_risks,
        cve_db_status=cve_status,
        cve_db_entries=len(cve_data),
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
