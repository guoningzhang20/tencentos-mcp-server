"""Unified command executor — local subprocess or SSH remote."""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Optional

import asyncssh

from tencentos_mcp_server.config import get_config

logger = logging.getLogger(__name__)


@dataclass
class ExecutionResult:
    """Result of a command execution."""

    returncode: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0

    @property
    def output(self) -> str:
        """Return stdout, falling back to stderr if empty."""
        return self.stdout if self.stdout else self.stderr


class CommandExecutor:
    """Execute commands locally or via SSH."""

    def __init__(
        self,
        host: Optional[str] = None,
        user: str = "root",
        ssh_key_path: Optional[str] = None,
        ssh_port: int = 22,
    ):
        self.host = host
        self.user = user
        self.ssh_key_path = ssh_key_path
        self.ssh_port = ssh_port

    @classmethod
    def from_config(cls) -> "CommandExecutor":
        cfg = get_config()
        return cls(
            host=cfg.host,
            user=cfg.user,
            ssh_key_path=cfg.ssh_key_path,
            ssh_port=cfg.ssh_port,
        )

    @property
    def is_remote(self) -> bool:
        return self.host is not None

    async def run(self, command: str, timeout: int = 30) -> ExecutionResult:
        """Execute a command and return the result."""
        logger.debug("exec [%s]: %s", "remote" if self.is_remote else "local", command)
        try:
            if self.is_remote:
                return await self._run_remote(command, timeout)
            return await self._run_local(command, timeout)
        except Exception as exc:
            logger.error("Command failed: %s — %s", command, exc)
            return ExecutionResult(returncode=-1, stdout="", stderr=str(exc))

    async def _run_local(self, command: str, timeout: int) -> ExecutionResult:
        proc = await asyncio.create_subprocess_shell(
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            return ExecutionResult(returncode=-1, stdout="", stderr="Command timed out")
        return ExecutionResult(
            returncode=proc.returncode or 0,
            stdout=(stdout_bytes or b"").decode(errors="replace").strip(),
            stderr=(stderr_bytes or b"").decode(errors="replace").strip(),
        )

    async def _run_remote(self, command: str, timeout: int) -> ExecutionResult:
        connect_kwargs: dict = {
            "host": self.host,
            "port": self.ssh_port,
            "username": self.user,
            "known_hosts": None,
        }
        if self.ssh_key_path:
            connect_kwargs["client_keys"] = [self.ssh_key_path]
        async with asyncssh.connect(**connect_kwargs) as conn:
            result = await asyncio.wait_for(conn.run(command), timeout=timeout)
            return ExecutionResult(
                returncode=result.exit_status or 0,
                stdout=(result.stdout or "").strip(),
                stderr=(result.stderr or "").strip(),
            )


async def run_cmd(command: str, timeout: int = 30) -> ExecutionResult:
    """Convenience: run a command using global config."""
    executor = CommandExecutor.from_config()
    return await executor.run(command, timeout=timeout)


async def run_commands(**commands: str) -> dict[str, ExecutionResult]:
    """Run multiple commands concurrently. Returns {name: result}."""
    executor = CommandExecutor.from_config()
    tasks = {name: executor.run(cmd) for name, cmd in commands.items()}
    results = {}
    for name, coro in tasks.items():
        results[name] = await coro
    return results
