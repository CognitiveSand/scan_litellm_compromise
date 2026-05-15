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

from .config import IOC_WALK_SKIP_DIRS, pruned_walk
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
    from .network_scanner import ConnectionRecord
    from .scan_context import ScanContext
    from .skip_report import SkipReport

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
    skip_report: SkipReport,
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
            skip_report.record_permission(path)
    if not found:
        print_clean()


# ── Individual IOC scanners ──────────────────────────────────────────────


def _hash_matches(
    file_path: Path,
    known_hashes: set[str],
    skip_report: SkipReport,
) -> bool:
    """Return True if *file_path*'s sha256 is in *known_hashes*.

    Unreadable files (PermissionError / OSError) are recorded in
    ``skip_report`` and return True — the file matched by name, so the
    walker still reports it as suspicious; the operator sees in the
    skip-summary why no hash comparison happened.
    """
    try:
        digest = hashlib.sha256(file_path.read_bytes()).hexdigest()
    except PermissionError:
        skip_report.record_permission(file_path)
        return True
    except OSError as exc:
        skip_report.record_read_error(file_path, type(exc).__name__)
        return True
    return digest in known_hashes


def _scan_walk_files(results: ScanResults, ctx: ScanContext) -> None:
    """Walk filesystem looking for IOC files by name (and optionally hash)."""
    for walk_ioc in ctx.threat.walk_files:
        print_check_header(walk_ioc.description)
        found = False
        target_names = set(walk_ioc.filenames)
        known_hashes = set(walk_ioc.sha256)

        for root in ctx.roots:
            root_path = Path(root)
            if not root_path.is_dir():
                continue
            for dirpath, _, filenames in pruned_walk(
                root_path, IOC_WALK_SKIP_DIRS, ctx.skip_report
            ):
                for fn in filenames:
                    if fn not in target_names:
                        continue
                    file_path = Path(dirpath) / fn
                    if known_hashes and not _hash_matches(
                        file_path, known_hashes, ctx.skip_report
                    ):
                        continue
                    print_ioc_found(str(file_path))
                    results.iocs.append(str(file_path))
                    found = True
        if not found:
            print_clean()


def _scan_known_paths(results: ScanResults, ctx: ScanContext) -> None:
    """Check per-platform known paths from the threat profile."""
    for kp in ctx.threat.known_paths:
        paths = [_expand_path(p) for p in kp.paths_for_platform()]
        _check_known_paths(kp.description, paths, results, ctx.skip_report)


def _resolve_c2_ips(ctx: ScanContext) -> dict[str, list[str]]:
    """Build domain -> IPs mapping. Uses known IPs; optionally adds live DNS.

    When ``ctx.resolve_c2`` is set, NXDOMAIN failures are tallied and
    surfaced so the operator does not silently get partial coverage if
    a takedown removed every C2 domain from public DNS.
    """
    result: dict[str, list[str]] = {
        d: list(ips) for d, ips in ctx.threat.c2.ips.items()
    }
    if not ctx.resolve_c2 or not ctx.threat.c2.domains:
        return result

    resolved = 0
    failed: list[str] = []
    for domain in ctx.threat.c2.domains:
        try:
            live_ip = socket.gethostbyname(domain)
        except socket.gaierror:
            logger.debug("Cannot resolve C2 domain %s", domain)
            failed.append(domain)
            continue
        ips = result.setdefault(domain, [])
        if live_ip not in ips:
            ips.append(live_ip)
        resolved += 1

    total = len(ctx.threat.c2.domains)
    print(f"  Resolved {resolved}/{total} C2 domain(s) via DNS")
    if failed:
        preview = ", ".join(failed[:3])
        suffix = f" (+{len(failed) - 3} more)" if len(failed) > 3 else ""
        print(
            f"  {YELLOW}{BOLD}NOTE:{RESET} {len(failed)} domain(s) failed to "
            f"resolve: {preview}{suffix} — coverage incomplete"
        )
    return result


def _run_network_probe(command: list[str]) -> list[ConnectionRecord] | None:
    """Run the platform network-listing command and parse its output.

    Returns the parsed ``ConnectionRecord`` list, or ``None`` if the
    subprocess timed out or errored — callers report that as 'no
    suspicious connections' rather than crashing the scan.
    """
    from .network_scanner import parse_lsof_output, parse_ss_output

    try:
        raw_output = subprocess.run(
            command, capture_output=True, timeout=5
        ).stdout.decode(errors="replace")
    except (subprocess.TimeoutExpired, OSError):
        logger.debug("Failed to run network check command")
        return None

    parser = parse_lsof_output if command[0] == "lsof" else parse_ss_output
    return parser(raw_output)


def _emit_c2_finding(
    results: ScanResults, record: ConnectionRecord, domain: str
) -> None:
    """Print + record one matched C2 connection."""
    from .models import Finding, FindingCategory
    from .network_scanner import enrich_from_proc

    record = enrich_from_proc(record)
    proc = record.process_name or "unknown"
    pid_str = f" (PID {record.pid})" if record.pid else ""
    exe_str = f" [{record.exe_path}]" if record.exe_path else ""
    desc = f"{proc}{pid_str}{exe_str} -> {domain} ({record.peer_ip}:{record.peer_port})"
    print(f"  {RED}{BOLD}! ACTIVE CONNECTION: {desc}{RESET}")
    results.iocs.append(f"connection:{domain}:{record.peer_ip}")
    results.findings.append(
        Finding(
            category=FindingCategory.C2_CONNECTION,
            description=desc,
            evidence=f"{record.peer_ip}:{record.peer_port}",
            weight=4,
        )
    )


def _scan_for_c2_connections(results: ScanResults, ctx: ScanContext) -> None:
    """Check active network connections for C2 domain communication."""
    from .network_scanner import find_c2_connections

    threat = ctx.threat
    if not threat.c2.domains and not threat.c2.ips:
        return

    print_check_header("active network connections for C2 domains")
    if ctx.resolve_c2:
        print(
            f"  {YELLOW}{BOLD}NOTE:{RESET} --resolve-c2 enabled "
            f"-- making live DNS queries to C2 domains"
        )
    command = ctx.policy.network_check_command
    if command is None or not shutil.which(command[0]):
        print_clean(
            f"{command[0] if command else 'network tool'} not available, skipping"
        )
        return

    records = _run_network_probe(command)
    if records is None:
        print_clean("No suspicious connections")
        return

    domain_ips = _resolve_c2_ips(ctx)
    matches = find_c2_connections(records, domain_ips, threat.c2.ports)
    for record, domain in matches:
        _emit_c2_finding(results, record, domain)
    if not matches:
        print_clean("No suspicious connections")


def _scan_for_malicious_pods(results: ScanResults, ctx: ScanContext) -> None:
    """Check Kubernetes for suspicious pods defined in the threat profile."""
    kubernetes = ctx.threat.kubernetes
    if not kubernetes.pod_patterns:
        return
    if not shutil.which("kubectl"):
        return

    namespace = kubernetes.namespace or "kube-system"
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
                line.strip().startswith(pattern) for pattern in kubernetes.pod_patterns
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


def _scan_phantom_deps(results: ScanResults, ctx: ScanContext) -> None:
    """Check for phantom dependencies that should not exist."""
    if not ctx.threat.phantom_deps:
        return

    print_check_header("phantom dependencies (should not exist)")
    found_iocs = ctx.ecosystem.find_phantom_deps(
        ctx.threat.phantom_deps,
        ctx.roots,
        ctx.skip_report,
    )
    if found_iocs:
        for ioc in found_iocs:
            print_ioc_found(ioc)
            results.iocs.append(ioc)
    else:
        print_clean("No phantom dependencies found")


def _scan_windows_extras(results: ScanResults, ctx: ScanContext) -> None:
    """Run Windows-specific IOC checks if applicable."""
    import sys

    if sys.platform != "win32":
        return

    registry_kw = ctx.threat.windows_ioc.registry_keywords
    schtask_kw = ctx.threat.windows_ioc.schtask_keywords
    if not registry_kw and not schtask_kw:
        return

    from .ioc_windows import run_windows_ioc_checks

    run_windows_ioc_checks(results, registry_kw, schtask_kw)


# ── Public scanners ──────────────────────────────────────────────────────
#
# Phase-3 IOC scanners are exposed individually. Orchestration (which
# scanners run in what order for a given threat) lives in
# ``scanner._run_phase3_iocs`` so the static dependency graph shows
# every scanner this module triggers.

scan_walk_files = _scan_walk_files
scan_known_paths = _scan_known_paths
scan_for_c2_connections = _scan_for_c2_connections
scan_for_malicious_pods = _scan_for_malicious_pods
scan_phantom_deps = _scan_phantom_deps
scan_windows_extras = _scan_windows_extras
