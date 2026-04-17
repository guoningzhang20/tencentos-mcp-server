"""Network tools — interfaces, connections, routes."""

from __future__ import annotations

import re

from mcp.types import ToolAnnotations

from tencentos_mcp_server.audit import log_tool_call
from tencentos_mcp_server.executor import run_cmd
from tencentos_mcp_server.models import NetworkConnection, NetworkInterface
from tencentos_mcp_server.server import mcp


@mcp.tool(
    title="Get network interfaces",
    description="List network interfaces with IP addresses and status.",
    tags={"network", "system"},
    annotations=ToolAnnotations(readOnlyHint=True),
)
@log_tool_call
async def get_network_info() -> list[NetworkInterface]:
    result = await run_cmd("ip -o addr show 2>/dev/null || ifconfig -a 2>/dev/null")
    interfaces: dict[str, NetworkInterface] = {}

    for line in result.stdout.splitlines():
        # ip -o addr format: 2: eth0    inet 10.0.0.5/24 ...
        match = re.match(r"\d+:\s+(\S+)\s+(\S+)\s+(\S+)", line)
        if not match:
            continue
        name, family, addr = match.group(1), match.group(2), match.group(3)
        if name not in interfaces:
            interfaces[name] = NetworkInterface(name=name)
        iface = interfaces[name]
        if family == "inet":
            iface.ipv4.append(addr)
        elif family == "inet6":
            iface.ipv6.append(addr)

    # Get link states
    link_result = await run_cmd("ip -o link show 2>/dev/null || echo ''")
    for line in link_result.stdout.splitlines():
        parts = line.split(":")
        if len(parts) >= 2:
            name = parts[1].strip().split("@")[0]
            if name in interfaces:
                state = "UP" if "UP" in line else "DOWN"
                interfaces[name].state = state
                mac_match = re.search(r"link/ether\s+(\S+)", line)
                if mac_match:
                    interfaces[name].mac = mac_match.group(1)

    return list(interfaces.values())


@mcp.tool(
    title="Get network connections",
    description="List active network connections and listening ports.",
    tags={"network", "connections"},
    annotations=ToolAnnotations(readOnlyHint=True),
)
@log_tool_call
async def get_network_connections(protocol: str = "all") -> list[NetworkConnection]:
    """List active connections.

    Args:
        protocol: 'tcp', 'udp', or 'all'. Default 'all'.
    """
    flag = {"tcp": "-tnp", "udp": "-unp", "all": "-tulnp"}.get(protocol, "-tulnp")
    result = await run_cmd(f"ss {flag} 2>/dev/null || netstat {flag} 2>/dev/null")
    connections: list[NetworkConnection] = []

    for line in result.stdout.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 5:
            continue
        proto = parts[0].lower()
        if proto not in ("tcp", "udp", "tcp6", "udp6"):
            continue
        local = parts[4] if len(parts) > 4 else ""
        # Split address:port
        local_addr, local_port = _split_addr(local)
        remote = parts[5] if len(parts) > 5 else ""
        remote_addr, remote_port = _split_addr(remote)
        state = parts[1] if "LISTEN" in line or "ESTAB" in line else ""
        for p in parts:
            if p in ("LISTEN", "ESTAB", "TIME-WAIT", "CLOSE-WAIT", "SYN-SENT"):
                state = p
                break
        proc = parts[-1] if len(parts) > 6 else ""

        connections.append(NetworkConnection(
            protocol=proto,
            local_addr=local_addr,
            local_port=local_port,
            remote_addr=remote_addr,
            remote_port=remote_port,
            state=state,
            process=proc,
        ))
    return connections


def _split_addr(addr_str: str) -> tuple[str, int]:
    """Split 'addr:port' or '[::]:port' into (addr, port)."""
    if not addr_str or addr_str == "*:*":
        return ("*", 0)
    if addr_str.startswith("["):
        # IPv6: [::]:port or [::]:*
        bracket_end = addr_str.rfind("]")
        if bracket_end > 0 and bracket_end + 1 < len(addr_str):
            port_str = addr_str[bracket_end + 2:]
            try:
                port = int(port_str) if port_str and port_str != "*" else 0
            except ValueError:
                port = 0
            return (addr_str[1:bracket_end], port)
    last_colon = addr_str.rfind(":")
    if last_colon > 0:
        addr = addr_str[:last_colon]
        try:
            port = int(addr_str[last_colon + 1:])
        except ValueError:
            port = 0
        return (addr, port)
    return (addr_str, 0)
