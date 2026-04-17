"""Configuration management — reads from environment variables."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Optional


@dataclass(frozen=True)
class ServerConfig:
    """Server configuration loaded from environment variables."""

    host: Optional[str] = field(default_factory=lambda: os.environ.get("TENCENTOS_MCP_HOST"))
    user: str = field(default_factory=lambda: os.environ.get("TENCENTOS_MCP_USER", "root"))
    ssh_key_path: Optional[str] = field(
        default_factory=lambda: os.environ.get(
            "TENCENTOS_MCP_SSH_KEY_PATH", os.path.expanduser("~/.ssh/id_rsa")
        )
    )
    ssh_port: int = field(
        default_factory=lambda: int(os.environ.get("TENCENTOS_MCP_SSH_PORT", "22"))
    )
    log_level: str = field(default_factory=lambda: os.environ.get("TENCENTOS_MCP_LOG_LEVEL", "INFO"))
    audit_enabled: bool = field(
        default_factory=lambda: os.environ.get("TENCENTOS_MCP_AUDIT", "true").lower() in ("true", "1", "yes")
    )

    @property
    def is_remote(self) -> bool:
        return self.host is not None


# Singleton
_config: Optional[ServerConfig] = None


def get_config() -> ServerConfig:
    global _config
    if _config is None:
        _config = ServerConfig()
    return _config
