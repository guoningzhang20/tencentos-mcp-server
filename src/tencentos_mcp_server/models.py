"""Pydantic data models for all MCP tools."""

from __future__ import annotations

from pydantic import BaseModel, Field


# ─────────────────────────────────────────────
# Base-layer models
# ─────────────────────────────────────────────

class SystemInfo(BaseModel):
    hostname: str
    os_name: str
    os_version: str
    kernel: str
    architecture: str
    uptime: str
    last_boot: str


class CpuInfo(BaseModel):
    model_name: str = ""
    cores: int = 0
    threads: int = 0
    architecture: str = ""
    frequency_mhz: str = ""
    load_1: float = 0.0
    load_5: float = 0.0
    load_15: float = 0.0


class MemoryInfo(BaseModel):
    total_mb: int = 0
    used_mb: int = 0
    free_mb: int = 0
    available_mb: int = 0
    usage_percent: float = 0.0
    swap_total_mb: int = 0
    swap_used_mb: int = 0
    swap_free_mb: int = 0


class DiskPartition(BaseModel):
    device: str
    mount_point: str
    fs_type: str
    size: str
    used: str
    available: str
    usage_percent: str


class DiskUsage(BaseModel):
    partitions: list[DiskPartition] = Field(default_factory=list)


class ProcessInfo(BaseModel):
    pid: int
    user: str
    cpu_percent: float
    mem_percent: float
    vsz_kb: int = 0
    rss_kb: int = 0
    stat: str = ""
    started: str = ""
    command: str = ""


class ServiceInfo(BaseModel):
    name: str
    load_state: str = ""
    active_state: str = ""
    sub_state: str = ""
    description: str = ""


class NetworkInterface(BaseModel):
    name: str
    state: str = ""
    ipv4: list[str] = Field(default_factory=list)
    ipv6: list[str] = Field(default_factory=list)
    mac: str = ""


class NetworkConnection(BaseModel):
    protocol: str
    local_addr: str
    local_port: int
    remote_addr: str = ""
    remote_port: int = 0
    state: str = ""
    process: str = ""


class BlockDevice(BaseModel):
    name: str
    size: str = ""
    device_type: str = ""
    mount_point: str = ""
    fs_type: str = ""


class LogEntry(BaseModel):
    timestamp: str = ""
    unit: str = ""
    priority: str = ""
    message: str = ""


# ─────────────────────────────────────────────
# ① Patch Impact models
# ─────────────────────────────────────────────

class PatchDetail(BaseModel):
    """Single patch detail."""
    advisory_id: str = ""
    package_name: str = ""
    current_version: str = ""
    available_version: str = ""
    severity: str = "Unknown"
    cve_ids: list[str] = Field(default_factory=list)
    impact_level: str = ""  # 需重启系统 / 需重启服务 / 无需重启
    affected_services: list[str] = Field(default_factory=list)
    changelog_summary: str = ""


class ImpactSummary(BaseModel):
    requires_reboot: int = 0
    requires_service_restart: int = 0
    no_restart_needed: int = 0
    affected_running_services: list[str] = Field(default_factory=list)


class PatchImpactReport(BaseModel):
    scan_time: str
    total_available_patches: int = 0
    security_patches: int = 0
    patches: list[PatchDetail] = Field(default_factory=list)
    impact_summary: ImpactSummary = Field(default_factory=ImpactSummary)
    recommendations: list[str] = Field(default_factory=list)


# ─────────────────────────────────────────────
# ② Diagnostics models
# ─────────────────────────────────────────────

class Problem(BaseModel):
    severity: str  # critical / warning / info
    category: str  # cpu / memory / disk / network / service / kernel
    title: str
    detail: str
    evidence: list[str] = Field(default_factory=list)
    suggested_fix: str = ""


class ResourcePressure(BaseModel):
    cpu_pressure: str = "N/A"
    memory_pressure: str = "N/A"
    io_pressure: str = "N/A"
    load_1: float = 0.0
    load_5: float = 0.0
    load_15: float = 0.0
    cpu_cores: int = 1
    memory_usage_pct: float = 0.0
    disk_usage_max_pct: float = 0.0
    network_connections: int = 0


class ErrorEvent(BaseModel):
    timestamp: str = ""
    source: str = ""  # journalctl / dmesg / systemd
    unit: str = ""
    message: str = ""
    count: int = 1


class Recommendation(BaseModel):
    priority: str  # high / medium / low
    title: str
    description: str
    action: str = ""


class DiagnosticReport(BaseModel):
    scan_time: str
    health_score: int = 100
    status: str = "healthy"  # healthy / degraded / unhealthy / critical
    problems: list[Problem] = Field(default_factory=list)
    resource_pressure: ResourcePressure = Field(default_factory=ResourcePressure)
    failed_services: list[str] = Field(default_factory=list)
    recent_errors: list[ErrorEvent] = Field(default_factory=list)
    recommendations: list[Recommendation] = Field(default_factory=list)


# ─────────────────────────────────────────────
# ③ Compliance models
# ─────────────────────────────────────────────

class AuditEntry(BaseModel):
    timestamp: str = ""
    user: str = ""
    action_type: str = ""  # login / sudo / file_change / service_op / package_op
    detail: str = ""
    source_ip: str = ""
    risk_level: str = "low"  # high / medium / low
    raw_log: str = ""


class UserActivity(BaseModel):
    username: str
    login_count: int = 0
    sudo_count: int = 0
    last_login: str = ""
    source_ips: list[str] = Field(default_factory=list)


class ComplianceStatus(BaseModel):
    auditd_enabled: bool = False
    audit_rules_loaded: int = 0
    password_policy: dict = Field(default_factory=dict)
    ssh_root_login: str = ""
    sudo_logging: bool = False
    failed_login_count: int = 0
    compliance_score: int = 0
    findings: list[str] = Field(default_factory=list)


class AuditReport(BaseModel):
    query_period: str
    total_operations: int = 0
    operations: list[AuditEntry] = Field(default_factory=list)
    high_risk_operations: list[AuditEntry] = Field(default_factory=list)
    user_summary: list[UserActivity] = Field(default_factory=list)
    compliance_status: ComplianceStatus = Field(default_factory=ComplianceStatus)


# ─────────────────────────────────────────────
# ④ Patch History models
# ─────────────────────────────────────────────

class PackageChange(BaseModel):
    package_name: str = ""
    action: str = ""  # Install / Update / Erase
    version: str = ""
    old_version: str = ""
    arch: str = ""
    repo: str = ""


class PatchTransaction(BaseModel):
    transaction_id: int = 0
    timestamp: str = ""
    user: str = ""
    action: str = ""
    packages: list[PackageChange] = Field(default_factory=list)
    return_code: str = ""


class KernelVersion(BaseModel):
    version: str = ""
    install_time: str = ""
    is_running: bool = False
    hotfix_loaded: bool = False
    hotfix_detail: str = ""


class PatchHistoryReport(BaseModel):
    query_period: str
    total_transactions: int = 0
    transactions: list[PatchTransaction] = Field(default_factory=list)
    kernel_history: list[KernelVersion] = Field(default_factory=list)


class OutdatedPackage(BaseModel):
    package_name: str
    installed_version: str = ""
    available_version: str = ""
    severity: str = "Unknown"
    related_cves: list[str] = Field(default_factory=list)


class CVEInfo(BaseModel):
    cve_id: str
    severity: str = "Unknown"
    description: str = ""
    affected_package: str = ""
    fixed_version: str = ""


class PatchGapReport(BaseModel):
    scan_time: str
    current_kernel: str = ""
    latest_kernel: str = ""
    total_outdated: int = 0
    critical_outdated: int = 0
    outdated_packages: list[OutdatedPackage] = Field(default_factory=list)
    unfixed_cves: list[CVEInfo] = Field(default_factory=list)


# ─────────────────────────────────────────────
# ⑤ System Tuning models
# ─────────────────────────────────────────────

class WorkloadProfile(BaseModel):
    type: str = "mixed"  # cpu_intensive / io_intensive / network_intensive / mixed / idle
    cpu_avg_load: float = 0.0
    memory_usage_pct: float = 0.0
    io_wait_pct: float = 0.0
    network_connections: int = 0
    disk_io_read_mbps: float = 0.0
    disk_io_write_mbps: float = 0.0
    description: str = ""


class ParameterCheck(BaseModel):
    parameter: str
    current_value: str = ""
    recommended_value: str = ""
    status: str = "optimal"  # optimal / suboptimal / risky
    category: str = ""  # network / memory / filesystem / kernel / security
    reason: str = ""


class TuningRecommendation(BaseModel):
    priority: str  # high / medium / low
    category: str
    title: str
    description: str
    current_state: str = ""
    recommended_action: str = ""
    expected_effect: str = ""


class TuningReport(BaseModel):
    scan_time: str
    workload_profile: WorkloadProfile = Field(default_factory=WorkloadProfile)
    tuned_profile: str = ""
    recommended_profile: str = ""
    parameter_checks: list[ParameterCheck] = Field(default_factory=list)
    total_recommendations: int = 0
    recommendations: list[TuningRecommendation] = Field(default_factory=list)
