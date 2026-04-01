"""Phase 3: Scan for Indicators of Compromise (IOC) artifacts."""

from __future__ import annotations

import hashlib
import logging
import os
import shutil
import socket
import subprocess
from pathlib import Path
from typing import TYPE_CHECKING, Iterable

from .config import IOC_WALK_SKIP_DIRS
from .formatting import (
    BOLD,
    RED,
    RESET,
    YELLOW,
    print_check_header,
    print_clean,
    print_ioc_found,
)
from .models import ScanResults

if TYPE_CHECKING:
    from .ecosystem_base import EcosystemPlugin
    from .platform_policy import PlatformPolicy
    from .threat_profile import ThreatProfile

logger = logging.getLogger(__name__)


# ── DRY helper for path-based IOC checks ────────────────────────────────


def _expand_path(raw: str) -> Path:
    """Expand ~ and %VAR% in a path string."""
    expanded = os.path.expanduser(os.path.expandvars(raw))
    return Path(expanded)


def _check_known_paths(
    description: str,
    paths: Iterable[Path],
    results: ScanResults,
) -> None:
    """Check a list of known paths for IOC artifacts."""
    print_check_header(description)
    found = False
    for path in paths:
        try:
            if path.exists():
                print_ioc_found(str(path))
                results.iocs.append(str(path))
                found = True
        except PermissionError:
            logger.debug("Permission denied checking %s", path)
    if not found:
        print_clean()


# ── Individual IOC scanners ──────────────────────────────────────────────


def _scan_walk_files(
    results: ScanResults,
    threat: ThreatProfile,
    roots: list[str],
) -> None:
    """Walk filesystem looking for IOC files by name (and optionally hash)."""
    for walk_ioc in threat.walk_files:
        print_check_header(walk_ioc.description)
        found = False
        target_names = set(walk_ioc.filenames)
        known_hashes = set(walk_ioc.sha256)

        for root in roots:
            root_path = Path(root)
            if not root_path.is_dir():
                continue
            try:
                for dirpath, dirnames, filenames in os.walk(root_path):
                    dirnames[:] = [
                        d for d in dirnames if d not in IOC_WALK_SKIP_DIRS
                    ]
                    for fn in filenames:
                        if fn not in target_names:
                            continue
                        file_path = Path(dirpath) / fn
                        # If hashes are specified, verify
                        if known_hashes:
                            try:
                                digest = hashlib.sha256(
                                    file_path.read_bytes()
                                ).hexdigest()
                                if digest not in known_hashes:
                                    continue
                            except (PermissionError, OSError):
                                # Can't read — still report as suspicious
                                pass
                        print_ioc_found(str(file_path))
                        results.iocs.append(str(file_path))
                        found = True
            except PermissionError:
                logger.debug("Permission denied walking %s", root)
        if not found:
            print_clean()


def _scan_known_paths(
    results: ScanResults,
    threat: ThreatProfile,
) -> None:
    """Check per-platform known paths from the threat profile."""
    for kp in threat.known_paths:
        paths = [_expand_path(p) for p in kp.paths_for_platform()]
        _check_known_paths(kp.description, paths, results)


def _resolve_c2_ips(threat: ThreatProfile, resolve_dns: bool) -> dict[str, list[str]]:
    """Build domain -> IPs mapping. Uses known IPs; optionally adds live DNS."""
    result: dict[str, list[str]] = {d: list(ips) for d, ips in threat.c2.ips.items()}
    if resolve_dns:
        for domain in threat.c2.domains:
            try:
                live_ip = socket.gethostbyname(domain)
                ips = result.setdefault(domain, [])
                if live_ip not in ips:
                    ips.append(live_ip)
            except socket.gaierror:
                logger.debug("Cannot resolve C2 domain %s", domain)
    return result


def _ip_matches_output(ip: str, ports: list[int], output: str) -> bool:
    """Check if an IP (optionally with specific ports) appears in socket output."""
    if not ports:
        return ip in output
    return any(f"{ip}:{port}" in output for port in ports)


def _scan_for_c2_connections(
    results: ScanResults,
    threat: ThreatProfile,
    policy: PlatformPolicy,
    resolve_c2: bool = False,
) -> None:
    """Check active network connections for C2 domain communication."""
    if not threat.c2.domains and not threat.c2.ips:
        return

    print_check_header("active network connections for C2 domains")
    if resolve_c2:
        print(
            f"  {YELLOW}{BOLD}NOTE:{RESET} --resolve-c2 enabled "
            f"-- making live DNS queries to C2 domains"
        )
    command = policy.network_check_command
    if command is None or not shutil.which(command[0]):
        print_clean(
            f"{command[0] if command else 'network tool'} not available, skipping"
        )
        return

    found = False
    domain_ips = _resolve_c2_ips(threat, resolve_c2)
    c2_ports = threat.c2.ports
    try:
        socket_output = subprocess.run(
            command, capture_output=True, timeout=5
        ).stdout.decode(errors="replace")

        for domain, ips in domain_ips.items():
            for ip in ips:
                if _ip_matches_output(ip, c2_ports, socket_output):
                    port_info = f" port {c2_ports}" if c2_ports else ""
                    print(
                        f"  {RED}{BOLD}! ACTIVE CONNECTION "
                        f"to {domain} ({ip}{port_info}){RESET}"
                    )
                    results.iocs.append(f"connection:{domain}:{ip}")
                    found = True
                    break  # one match per domain is enough
    except (subprocess.TimeoutExpired, OSError):
        logger.debug("Failed to run network check command")

    if not found:
        print_clean("No suspicious connections")


def _scan_for_malicious_pods(results: ScanResults, threat: ThreatProfile) -> None:
    """Check Kubernetes for suspicious pods defined in the threat profile."""
    if not threat.kubernetes.pod_patterns:
        return
    if not shutil.which("kubectl"):
        return

    namespace = threat.kubernetes.namespace or "kube-system"
    print_check_header(f"Kubernetes malicious pods ({namespace})")
    try:
        kubectl_output = subprocess.run(
            ["kubectl", "get", "pods", "-n", namespace, "--no-headers"],
            capture_output=True,
            text=True,
            timeout=10,
        ).stdout

        suspicious_pods = [
            line
            for line in kubectl_output.splitlines()
            if any(
                line.strip().startswith(pattern)
                for pattern in threat.kubernetes.pod_patterns
            )
        ]

        if suspicious_pods:
            print(f"  {RED}{BOLD}! SUSPICIOUS PODS in {namespace}:{RESET}")
            for pod in suspicious_pods:
                print(f"    {RED}{pod}{RESET}")
            results.iocs.append(f"k8s-pods:{len(suspicious_pods)}")
        else:
            print_clean("No suspicious pods")
    except (subprocess.TimeoutExpired, OSError):
        logger.debug("Failed to query Kubernetes pods")


def _scan_phantom_deps(
    results: ScanResults,
    threat: ThreatProfile,
    ecosystem: EcosystemPlugin,
    roots: list[str],
) -> None:
    """Check for phantom dependencies that should not exist."""
    if not threat.phantom_deps:
        return

    print_check_header("phantom dependencies (should not exist)")
    found_iocs = ecosystem.find_phantom_deps(
        threat.phantom_deps,
        roots,
    )
    if found_iocs:
        for ioc in found_iocs:
            print_ioc_found(ioc)
            results.iocs.append(ioc)
    else:
        print_clean("No phantom dependencies found")


def _scan_windows_extras(
    results: ScanResults,
    threat: ThreatProfile,
) -> None:
    """Run Windows-specific IOC checks if applicable."""
    import sys

    if sys.platform != "win32":
        return

    registry_kw = threat.windows_ioc.registry_keywords
    schtask_kw = threat.windows_ioc.schtask_keywords
    if not registry_kw and not schtask_kw:
        return

    from .ioc_windows import run_windows_ioc_checks

    run_windows_ioc_checks(results, registry_kw, schtask_kw)


# ── Public entry point ───────────────────────────────────────────────────


def scan_iocs(
    results: ScanResults,
    threat: ThreatProfile,
    ecosystem: EcosystemPlugin,
    policy: PlatformPolicy,
    roots: list[str],
    resolve_c2: bool = False,
) -> None:
    """Run all IOC artifact scans for a single threat profile."""
    if threat.walk_files:
        _scan_walk_files(results, threat, roots)
        print()

    if threat.known_paths:
        _scan_known_paths(results, threat)
        print()

    _scan_for_c2_connections(results, threat, policy, resolve_c2=resolve_c2)

    _scan_for_malicious_pods(results, threat)

    _scan_phantom_deps(results, threat, ecosystem, roots)

    _scan_windows_extras(results, threat)
