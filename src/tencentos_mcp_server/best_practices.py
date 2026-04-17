"""Built-in best-practice tuning rules for system_tuning module.

Each rule defines a kernel/system parameter, its recommended value per workload
type, and evaluation logic. All recommendations are advisory — no changes are
applied automatically.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class TuningRule:
    """A single tuning rule."""

    parameter: str
    category: str  # network / memory / filesystem / kernel / security
    reason: str
    # recommended values keyed by workload type; None = not applicable
    recommended: dict[str, Optional[str]] = field(default_factory=dict)
    # comparison: "gte" (current should be >= recommended), "lte", "eq"
    compare: str = "gte"

    def applies_to(self, workload_type: str) -> bool:
        return workload_type in self.recommended and self.recommended[workload_type] is not None

    def recommended_value(self, workload_type: str) -> str:
        return self.recommended.get(workload_type) or self.recommended.get("default", "")

    def evaluate(self, current_value: str, workload_type: str) -> str:
        """Return 'optimal', 'suboptimal', or 'risky'."""
        rec = self.recommended_value(workload_type)
        if not rec or current_value in ("N/A", ""):
            return "optimal"
        try:
            cur = int(current_value)
            rec_int = int(rec)
        except (ValueError, TypeError):
            return "optimal"

        if self.compare == "gte":
            if cur >= rec_int:
                return "optimal"
            elif cur >= rec_int * 0.5:
                return "suboptimal"
            else:
                return "risky"
        elif self.compare == "lte":
            if cur <= rec_int:
                return "optimal"
            elif cur <= rec_int * 2:
                return "suboptimal"
            else:
                return "risky"
        elif self.compare == "eq":
            return "optimal" if cur == rec_int else "suboptimal"
        return "optimal"


# ─────────────────────────────────────────────
# Tuning rules table
# ─────────────────────────────────────────────

TUNING_RULES: list[TuningRule] = [
    TuningRule(
        parameter="net.core.somaxconn",
        category="network",
        reason="TCP 监听队列大小，高并发场景默认值 128 远远不够",
        recommended={"network_intensive": "65535", "mixed": "4096", "default": "4096"},
    ),
    TuningRule(
        parameter="net.ipv4.tcp_max_syn_backlog",
        category="network",
        reason="SYN 半连接队列，防止 SYN flood 丢包",
        recommended={"network_intensive": "65535", "mixed": "4096", "default": "4096"},
    ),
    TuningRule(
        parameter="net.ipv4.tcp_tw_reuse",
        category="network",
        reason="复用 TIME_WAIT 连接，短连接高并发场景推荐开启",
        recommended={"network_intensive": "1", "mixed": "1", "default": "1"},
        compare="gte",
    ),
    TuningRule(
        parameter="net.ipv4.tcp_fin_timeout",
        category="network",
        reason="FIN_WAIT_2 超时时间，缩短可加速连接回收",
        recommended={"network_intensive": "30", "mixed": "30", "default": "30"},
        compare="lte",
    ),
    TuningRule(
        parameter="vm.swappiness",
        category="memory",
        reason="交换倾向，服务器推荐低值减少 swap 使用",
        recommended={
            "cpu_intensive": "10",
            "io_intensive": "10",
            "network_intensive": "10",
            "mixed": "10",
            "default": "10",
        },
        compare="lte",
    ),
    TuningRule(
        parameter="vm.dirty_ratio",
        category="memory",
        reason="脏页占比上限，IO 密集场景可适当提高",
        recommended={"io_intensive": "40", "default": "20"},
        compare="gte",
    ),
    TuningRule(
        parameter="vm.dirty_background_ratio",
        category="memory",
        reason="后台刷脏页阈值",
        recommended={"io_intensive": "20", "default": "10"},
        compare="gte",
    ),
    TuningRule(
        parameter="fs.file-max",
        category="filesystem",
        reason="系统最大文件描述符数，高并发必须调大",
        recommended={
            "network_intensive": "1000000",
            "io_intensive": "1000000",
            "mixed": "500000",
            "default": "500000",
        },
    ),
    TuningRule(
        parameter="fs.inotify.max_user_watches",
        category="filesystem",
        reason="inotify 监控文件数上限，容器/构建场景常需调大",
        recommended={"io_intensive": "524288", "mixed": "524288", "default": "524288"},
    ),
    TuningRule(
        parameter="kernel.pid_max",
        category="kernel",
        reason="最大 PID 数，容器密集场景需调大",
        recommended={"network_intensive": "65536", "mixed": "65536", "default": "65536"},
    ),
    TuningRule(
        parameter="net.ipv4.ip_local_port_range",
        category="network",
        reason="本地端口范围，高并发外连场景需扩大",
        recommended={"network_intensive": "1024 65535", "default": "1024 65535"},
        compare="eq",  # special: we just check if the range is wide enough
    ),
    TuningRule(
        parameter="net.core.netdev_max_backlog",
        category="network",
        reason="网卡接收队列积压上限",
        recommended={"network_intensive": "65536", "default": "2048"},
    ),
]
