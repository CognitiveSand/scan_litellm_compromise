"""Structured network connection parsing — replaces substring matching.

Parses ss/lsof/netstat output into typed ConnectionRecord objects,
enabling precise IP:port matching with PID and process attribution.
"""

from __future__ import annotations

import logging
import os
import re
import sys
from dataclasses import dataclass

logger = logging.getLogger(__name__)

_SS_PROCESS_RE = re.compile(r'"([^"]+)",pid=(\d+)')

# Bracketed IPv6 peer: ``[2001:db8::1]:443``. Brackets are stripped so
# the returned host matches the bare-IP form used in threat-profile
# ``c2.ips`` lists; without this, IPv6 C2 traffic is silently missed
# because ``rpartition(":")`` leaves the closing bracket in the host.
_IPV6_BRACKETED_PEER_RE = re.compile(r"^\[([^\]]+)\]:(\d+)$")


def _split_host_port(peer: str) -> tuple[str, int] | None:
    """Split ``host:port`` from a connection-peer string.

    Handles plain IPv4 (``1.2.3.4:443``) and bracketed IPv6
    (``[2001:db8::1]:443``). Returns ``None`` when the format is
    unrecognised or the port is not numeric.
    """
    bracketed_match = _IPV6_BRACKETED_PEER_RE.match(peer)
    if bracketed_match:
        return bracketed_match.group(1), int(bracketed_match.group(2))
    host, sep, port_str = peer.rpartition(":")
    if not sep or not port_str.isdigit():
        return None
    return host, int(port_str)


@dataclass(frozen=True)
class ConnectionRecord:
    """A single active TCP connection."""

    peer_ip: str
    peer_port: int
    pid: int = 0
    process_name: str = ""
    exe_path: str = ""


def parse_ss_output(raw: str) -> list[ConnectionRecord]:
    """Parse Linux 'ss -tnp' output into connection records."""
    records: list[ConnectionRecord] = []
    for line in raw.strip().splitlines()[1:]:  # skip header
        parts = line.split()
        if len(parts) < 5:
            continue
        host_port = _split_host_port(parts[4])
        if host_port is None:
            continue
        peer_ip, peer_port = host_port
        proc_match = _SS_PROCESS_RE.search(line)
        records.append(
            ConnectionRecord(
                peer_ip=peer_ip,
                peer_port=peer_port,
                pid=int(proc_match.group(2)) if proc_match else 0,
                process_name=proc_match.group(1) if proc_match else "",
            )
        )
    return records


def parse_lsof_output(raw: str) -> list[ConnectionRecord]:
    """Parse macOS 'lsof -i -P -n' output into connection records."""
    records: list[ConnectionRecord] = []
    for line in raw.strip().splitlines()[1:]:  # skip header
        parts = line.split()
        if len(parts) < 9:
            continue
        process_name = parts[0]
        pid_str = parts[1]
        name_field = parts[8]  # e.g. "10.0.0.1:54321->142.11.206.73:8000"
        if "->" not in name_field:
            continue
        remote = name_field.split("->")[1]
        host_port = _split_host_port(remote)
        if host_port is None:
            continue
        peer_ip, peer_port = host_port
        records.append(
            ConnectionRecord(
                peer_ip=peer_ip,
                peer_port=peer_port,
                pid=int(pid_str) if pid_str.isdigit() else 0,
                process_name=process_name,
            )
        )
    return records


def enrich_from_proc(record: ConnectionRecord) -> ConnectionRecord:
    """On Linux, read /proc/{pid}/exe to get the executable path."""
    if sys.platform == "win32" or record.pid == 0:
        return record
    try:
        exe = os.readlink(f"/proc/{record.pid}/exe")
        return ConnectionRecord(
            peer_ip=record.peer_ip,
            peer_port=record.peer_port,
            pid=record.pid,
            process_name=record.process_name,
            exe_path=exe,
        )
    except (PermissionError, OSError):
        return record


def find_c2_connections(
    records: list[ConnectionRecord],
    domain_ips: dict[str, list[str]],
    ports: list[int],
) -> list[tuple[ConnectionRecord, str]]:
    """Match connection records against C2 infrastructure.

    Returns (record, domain) pairs for each match.
    """
    matches: list[tuple[ConnectionRecord, str]] = []
    for domain, ips in domain_ips.items():
        for record in records:
            if record.peer_ip not in ips:
                continue
            if ports and record.peer_port not in ports:
                continue
            matches.append((record, domain))
            break  # one match per domain is enough
    return matches
