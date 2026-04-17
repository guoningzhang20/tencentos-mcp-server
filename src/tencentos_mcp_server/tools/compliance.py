"""③ Compliance Audit — who did what, when, and is it compliant?

Tools:
- audit_operations: Query audit trail — who, when, what
- check_compliance: Check audit/security configuration against best practices
- get_privileged_operations: Get privileged (sudo/su/root) operation records
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

from mcp.types import ToolAnnotations

from tencentos_mcp_server.audit import log_tool_call
from tencentos_mcp_server.executor import run_cmd
from tencentos_mcp_server.models import (
    AuditEntry,
    AuditReport,
    ComplianceStatus,
    UserActivity,
)
from tencentos_mcp_server.sanitize import safe_positive_int
from tencentos_mcp_server.server import mcp


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _classify_risk(action_type: str, detail: str) -> str:
    """Classify risk level of an operation."""
    detail_lower = detail.lower()
    # High risk: root login, sensitive file changes, user management
    if any(kw in detail_lower for kw in [
        "root", "/etc/passwd", "/etc/shadow", "/etc/sudoers",
        "useradd", "userdel", "usermod", "chmod 777", "iptables",
        "firewall", "selinux",
    ]):
        return "high"
    # Medium risk: sudo, su, package operations, service changes
    if action_type in ("sudo", "su") or any(kw in detail_lower for kw in [
        "yum install", "dnf install", "rpm -i", "systemctl start",
        "systemctl stop", "systemctl restart",
    ]):
        return "medium"
    return "low"


def _parse_last_output(text: str) -> list[AuditEntry]:
    """Parse 'last' command output into AuditEntry list."""
    entries: list[AuditEntry] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("wtmp") or line.startswith("reboot"):
            continue
        parts = line.split()
        if len(parts) < 4:
            continue
        user = parts[0]
        source_ip = ""
        # Detect IP-like field
        for p in parts[1:4]:
            if re.match(r"\d+\.\d+\.\d+\.\d+", p):
                source_ip = p
                break

        entries.append(AuditEntry(
            timestamp=" ".join(parts[2:6]) if len(parts) > 5 else " ".join(parts[2:]),
            user=user,
            action_type="login",
            detail=line,
            source_ip=source_ip,
            risk_level=_classify_risk("login", line),
            raw_log=line,
        ))
    return entries


def _parse_sudo_logs(text: str) -> list[AuditEntry]:
    """Parse journalctl sudo output."""
    entries: list[AuditEntry] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or "sudo" not in line.lower():
            continue
        # Extract user and command from sudo log
        user_match = re.search(r"(\w+)\s*:\s*.*COMMAND=(.+)", line)
        user = user_match.group(1) if user_match else "unknown"
        command = user_match.group(2).strip() if user_match else line

        # Extract timestamp (first token if ISO format or date)
        parts = line.split(None, 3)
        ts = parts[0] if parts else ""

        entries.append(AuditEntry(
            timestamp=ts,
            user=user,
            action_type="sudo",
            detail=command[:200],
            source_ip="",
            risk_level=_classify_risk("sudo", command),
            raw_log=line[:300],
        ))
    return entries


def _parse_secure_log(text: str) -> list[AuditEntry]:
    """Parse /var/log/secure entries."""
    entries: list[AuditEntry] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        action_type = "other"
        if "session opened" in line.lower():
            action_type = "login"
        elif "session closed" in line.lower():
            action_type = "logout"
        elif "failed" in line.lower():
            action_type = "failed_login"
        elif "accepted" in line.lower():
            action_type = "login"

        user_match = re.search(r"for\s+(?:user\s+)?(\w+)", line)
        user = user_match.group(1) if user_match else ""
        ip_match = re.search(r"from\s+([\d.]+)", line)
        source_ip = ip_match.group(1) if ip_match else ""

        parts = line.split(None, 3)
        ts = " ".join(parts[:3]) if len(parts) >= 3 else ""

        entries.append(AuditEntry(
            timestamp=ts,
            user=user,
            action_type=action_type,
            detail=line[:200],
            source_ip=source_ip,
            risk_level=_classify_risk(action_type, line),
            raw_log=line[:300],
        ))
    return entries


def _aggregate_by_user(entries: list[AuditEntry]) -> list[UserActivity]:
    """Aggregate audit entries by user."""
    user_map: dict[str, UserActivity] = {}
    for e in entries:
        if not e.user:
            continue
        if e.user not in user_map:
            user_map[e.user] = UserActivity(username=e.user)
        ua = user_map[e.user]
        if e.action_type in ("login", "failed_login"):
            ua.login_count += 1
        if e.action_type == "sudo":
            ua.sudo_count += 1
        if e.timestamp and (not ua.last_login or e.timestamp > ua.last_login):
            ua.last_login = e.timestamp
        if e.source_ip and e.source_ip not in ua.source_ips:
            ua.source_ips.append(e.source_ip)
    return sorted(user_map.values(), key=lambda u: u.login_count + u.sudo_count, reverse=True)


def _parse_pwquality(text: str) -> dict:
    """Parse /etc/security/pwquality.conf."""
    policy: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" in line:
            k, _, v = line.partition("=")
            policy[k.strip()] = v.strip()
    return policy


async def _check_compliance_impl() -> ComplianceStatus:
    """Internal compliance check implementation."""
    auditd = await run_cmd("systemctl is-active auditd 2>/dev/null || echo inactive")
    audit_rules = await run_cmd("auditctl -l 2>/dev/null | wc -l || echo 0")
    pw_policy = await run_cmd("cat /etc/security/pwquality.conf 2>/dev/null || echo ''")
    ssh_config = await run_cmd("grep -i PermitRootLogin /etc/ssh/sshd_config 2>/dev/null | grep -v '^#' || echo ''")
    sudo_log_check = await run_cmd("grep -c sudo /var/log/secure 2>/dev/null || echo 0")
    failed_count = await run_cmd("lastb 2>/dev/null | tail -1 | awk '{print $1}' || echo 0")
    # Count failed logins properly
    failed_lines = await run_cmd("lastb 2>/dev/null | grep -c '' || echo 0")

    findings: list[str] = []
    score = 100

    # Check auditd
    auditd_active = auditd.stdout.strip() == "active"
    if not auditd_active:
        findings.append("auditd 服务未运行 — 无法记录系统级审计日志，建议启用: systemctl enable --now auditd")
        score -= 30

    # Check audit rules
    try:
        rules_count = int(audit_rules.stdout.strip())
    except ValueError:
        rules_count = 0
    if rules_count < 5:
        findings.append(f"审计规则仅 {rules_count} 条 — 建议添加关键文件和操作的审计规则")
        score -= 15

    # Check SSH root login
    ssh_root = ssh_config.stdout.strip()
    if "yes" in ssh_root.lower():
        findings.append("SSH 允许 root 直接登录 — 建议设为 PermitRootLogin prohibit-password 或 no")
        score -= 20

    # Check password policy
    pw_dict = _parse_pwquality(pw_policy.stdout)
    minlen = int(pw_dict.get("minlen", "0") or "0")
    if minlen < 8:
        findings.append(f"密码最小长度为 {minlen} — 建议设为 8 以上 (minlen = 8 in /etc/security/pwquality.conf)")
        score -= 10

    # Check sudo logging
    try:
        sudo_log_count = int(sudo_log_check.stdout.strip())
    except ValueError:
        sudo_log_count = 0
    sudo_logging = sudo_log_count > 0

    # Failed login count
    try:
        failed_login_count = max(0, int(failed_lines.stdout.strip()) - 2)  # subtract header/footer
    except ValueError:
        failed_login_count = 0
    if failed_login_count > 50:
        findings.append(f"失败登录记录 {failed_login_count} 次 — 可能存在暴力破解尝试，建议启用 fail2ban")
        score -= 10

    if not findings:
        findings.append("✅ 所有检查项均合规")

    return ComplianceStatus(
        auditd_enabled=auditd_active,
        audit_rules_loaded=rules_count,
        password_policy=pw_dict,
        ssh_root_login=ssh_root or "not configured",
        sudo_logging=sudo_logging,
        failed_login_count=failed_login_count,
        compliance_score=max(0, score),
        findings=findings,
    )


# ───────────────────────── Tools ─────────────────────────

@mcp.tool(
    title="Audit operations",
    description=(
        "Query operation audit trail: who logged in, who ran sudo, what was changed. "
        "Aggregates data from auditd, /var/log/secure, last/lastb, and sudo journal. "
        "Marks high-risk operations and provides per-user activity summary."
    ),
    tags={"compliance", "audit", "security", "tencentos"},
    annotations=ToolAnnotations(readOnlyHint=True),
)
@log_tool_call
async def audit_operations(days: int = 7) -> AuditReport:
    """Query audit trail.

    Args:
        days: Look-back period in days. Default 7.
    """
    days = safe_positive_int(days, "days", max_val=365)
    # Collect from multiple sources
    logins = await run_cmd(f"last -n 50 2>/dev/null || echo ''")
    failed_logins = await run_cmd("lastb -n 20 2>/dev/null || echo ''")
    sudo_logs = await run_cmd(
        f'journalctl _COMM=sudo --since "{days} days ago" --no-pager -n 200 2>/dev/null || echo ""'
    )
    secure_log = await run_cmd("tail -500 /var/log/secure 2>/dev/null || echo ''")

    # Parse all sources
    all_ops: list[AuditEntry] = []
    all_ops.extend(_parse_last_output(logins.stdout))
    all_ops.extend(_parse_last_output(failed_logins.stdout))
    all_ops.extend(_parse_sudo_logs(sudo_logs.stdout))
    all_ops.extend(_parse_secure_log(secure_log.stdout))

    # Deduplicate (rough — by raw_log hash)
    seen: set[str] = set()
    unique_ops: list[AuditEntry] = []
    for op in all_ops:
        key = op.raw_log[:100]
        if key not in seen:
            seen.add(key)
            unique_ops.append(op)

    high_risk = [op for op in unique_ops if op.risk_level == "high"]
    user_summary = _aggregate_by_user(unique_ops)
    compliance = await _check_compliance_impl()

    return AuditReport(
        query_period=f"最近 {days} 天",
        total_operations=len(unique_ops),
        operations=unique_ops[:100],  # Cap for readability
        high_risk_operations=high_risk,
        user_summary=user_summary,
        compliance_status=compliance,
    )


@mcp.tool(
    title="Check compliance",
    description=(
        "Check system security compliance: auditd status, audit rules count, "
        "password policy, SSH root login config, failed login attempts. "
        "Returns a compliance score (0-100) and list of findings."
    ),
    tags={"compliance", "security", "tencentos"},
    annotations=ToolAnnotations(readOnlyHint=True),
)
@log_tool_call
async def check_compliance() -> ComplianceStatus:
    return await _check_compliance_impl()


@mcp.tool(
    title="Get privileged operations",
    description=(
        "Get privileged operation records: sudo commands, su switches, and root logins. "
        "Useful for security audit and incident investigation."
    ),
    tags={"compliance", "security", "sudo", "tencentos"},
    annotations=ToolAnnotations(readOnlyHint=True),
)
@log_tool_call
async def get_privileged_operations(days: int = 7) -> list[AuditEntry]:
    """Get privileged operations.

    Args:
        days: Look-back period in days. Default 7.
    """
    days = safe_positive_int(days, "days", max_val=365)
    sudo_logs = await run_cmd(
        f'journalctl _COMM=sudo --since "{days} days ago" --no-pager -n 200 2>/dev/null || echo ""'
    )
    root_logins = await run_cmd("last root -n 20 2>/dev/null || echo ''")
    su_logs = await run_cmd(
        f'journalctl _COMM=su --since "{days} days ago" --no-pager -n 50 2>/dev/null || echo ""'
    )

    ops: list[AuditEntry] = []
    ops.extend(_parse_sudo_logs(sudo_logs.stdout))

    for line in root_logins.stdout.splitlines():
        line = line.strip()
        if line and not line.startswith("wtmp"):
            ip_match = re.search(r"([\d.]+)", line)
            ops.append(AuditEntry(
                timestamp="",
                user="root",
                action_type="login",
                detail=line[:200],
                source_ip=ip_match.group(1) if ip_match else "",
                risk_level="high",
                raw_log=line[:300],
            ))

    for line in su_logs.stdout.splitlines():
        line = line.strip()
        if line and "su" in line.lower():
            user_match = re.search(r"(\w+) to (\w+)", line)
            ops.append(AuditEntry(
                timestamp="",
                user=user_match.group(1) if user_match else "unknown",
                action_type="su",
                detail=line[:200],
                source_ip="",
                risk_level="medium",
                raw_log=line[:300],
            ))

    return ops
