"""Main orchestrator for the supply chain compromise scanner."""

import argparse
import logging
import sys
from pathlib import Path

from . import __version__
from .anti_worm_scanner import aggregate_indicators, scan_anti_worm
from .discovery import find_package_metadata
from .ecosystem_base import get_ecosystem
from .formatting import (
    BOLD,
    CYAN,
    RESET,
    YELLOW,
    print_banner,
    print_phase_header,
    print_separator,
)
from .git_repo_index import build_repo_index
from .ioc_scanner import scan_iocs
from .models import ScanResults
from .platform_policy import detect_platform
from .report import (
    print_anti_worm_report,
    print_config_refs,
    print_multi_threat_summary,
    print_source_refs,
)
from .search_roots import build_search_roots, deduplicate_roots
from .source_scanner import scan_source_and_configs
from .threat_profile import (
    ThreatProfile,
    list_available_threats,
    load_all_threats,
    load_threat_by_id,
    load_threat_file,
)
from .version_checker import scan_environments


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Scan for known supply chain compromises "
            "(PyPI, npm). Scans all known threats by default."
        ),
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--threat",
        metavar="ID",
        help="Scan for a specific threat only (e.g. litellm-2026-03)",
    )
    group.add_argument(
        "--threat-file",
        metavar="PATH",
        help="Load a custom threat profile from a TOML file",
    )
    group.add_argument(
        "--list-threats",
        action="store_true",
        help="List all available threat profiles and exit",
    )
    parser.add_argument(
        "--resolve-c2",
        action="store_true",
        help="Enable live DNS queries to C2 domains (default: use known IPs only)",
    )
    return parser.parse_args()


def _do_list_threats() -> None:
    """Print available threat profiles and exit."""
    threats = list_available_threats()
    if not threats:
        print("No threat profiles found.")
        sys.exit(0)
    print(f"\n{BOLD}Supply Chain Compromise Scanner v{__version__}{RESET}")
    print(f"\n{BOLD}Available threat profiles:{RESET}\n")
    for t in threats:
        compromised_str = ", ".join(sorted(t.compromised))
        print(f"  {BOLD}{t.id}{RESET}")
        print(f"    {t.name}")
        print(f"    Ecosystem: {t.ecosystem}  Package: {t.package}")
        print(f"    Compromised: {compromised_str}")
        print(f"    Date: {t.date}")
        print()
    sys.exit(0)


def _resolve_threats(args: argparse.Namespace) -> list[ThreatProfile]:
    """Determine which threat profiles to scan."""
    if args.threat_file:
        path = Path(args.threat_file)
        if not path.is_file():
            print(f"Error: threat file not found: {path}", file=sys.stderr)
            sys.exit(2)
        return [load_threat_file(path)]

    if args.threat:
        profile = load_threat_by_id(args.threat)
        if profile is None:
            print(
                f"Error: unknown threat id: {args.threat!r}\n"
                f"Run with --list-threats to see available profiles.",
                file=sys.stderr,
            )
            sys.exit(2)
        return [profile]

    # Default: all threats
    return load_all_threats()


def _scan_single_threat(
    threat: ThreatProfile,
    policy,
    roots: list[str],
    resolve_c2: bool,
) -> ScanResults:
    """Run the full 5-phase pipeline for one threat profile."""
    ecosystem = get_ecosystem(threat.ecosystem)
    results = ScanResults(compromised_versions=threat.compromised)

    print_separator()
    print(f"\n{BOLD}Scanning for: {threat.name}{RESET}")
    print(f"  Package: {threat.package} ({threat.ecosystem.upper()})")
    compromised_str = ", ".join(sorted(threat.compromised))
    print(f"  Compromised versions: {compromised_str}\n")

    # Phase 1: Discover installations
    print_phase_header(1, f"Discovering {threat.package} installations...")
    metadata_dirs = find_package_metadata(roots, ecosystem, threat.package)
    print(
        f"  Found {BOLD}{len(metadata_dirs)}{RESET} "
        f"{threat.package} metadata directories"
    )

    # Phase 2: Check versions
    print_separator()
    print_phase_header(
        2,
        f"Checking {threat.package} versions from metadata...",
    )
    scan_environments(metadata_dirs, results, ecosystem, threat)

    # Phase 3: IOC artifact scan
    print_phase_header(3, "Scanning for IOC artifacts...")
    scan_iocs(results, threat, ecosystem, policy, roots, resolve_c2=resolve_c2)

    # Phase 4: Source & config scan
    print_phase_header(
        4,
        f"Scanning source files for {threat.package} usage...",
    )
    files_scanned = scan_source_and_configs(results, threat, ecosystem, roots)
    print(f"  Files scanned: {BOLD}{files_scanned}{RESET}\n")
    print_source_refs(results.source_refs, threat.package)
    print_config_refs(
        results.config_refs,
        threat.package,
        threat.compromised,
    )

    return results


def main():
    logging.basicConfig(
        level=logging.WARNING,
        format="%(levelname)s: %(message)s",
    )

    args = _parse_args()

    if args.list_threats:
        _do_list_threats()

    threats = _resolve_threats(args)
    if not threats:
        print("No threat profiles found. Nothing to scan.")
        sys.exit(0)

    policy = detect_platform()

    print_banner(__version__)
    print(f"  {BOLD}Platform:{RESET} {policy.name}")
    print(f"  {BOLD}NOTE:{RESET} {policy.exclusion_note}\n")

    print(f"  {BOLD}Threat profiles ({len(threats)}):{RESET}")
    for t in threats:
        versions = ", ".join(sorted(t.compromised))
        print(
            f"    {CYAN}{t.id}{RESET}  "
            f"{t.ecosystem.upper()}:{BOLD}{t.package}{RESET} "
            f"{YELLOW}[{versions}]{RESET}"
        )
    print()

    roots_cache: dict[str, list[str]] = {}
    for threat in threats:
        ecosystem = get_ecosystem(threat.ecosystem)
        if threat.ecosystem not in roots_cache:
            roots_cache[threat.ecosystem] = build_search_roots(policy, ecosystem)

    # Anti-worm pre-pass: one filesystem walk across the union of all
    # ecosystem roots, matched against the aggregated worm indicators
    # from every loaded threat profile.
    anti_worm_results = _run_anti_worm_pass(threats, roots_cache)

    # Run pipeline for each threat
    all_results: list[tuple[ThreatProfile, ScanResults]] = []
    for threat in threats:
        roots = roots_cache[threat.ecosystem]
        results = _scan_single_threat(
            threat,
            policy,
            roots,
            args.resolve_c2,
        )
        all_results.append((threat, results))

    # Final combined report — anti-worm section first, then per-threat
    print()
    print_anti_worm_report(anti_worm_results)
    print_multi_threat_summary(all_results)

    any_compromised = any(not r.is_clean for _, r in all_results)
    any_worm_signals = not anti_worm_results.is_clean
    sys.exit(1 if (any_compromised or any_worm_signals) else 0)


def _run_anti_worm_pass(
    threats: list[ThreatProfile],
    roots_cache: dict[str, list[str]],
) -> ScanResults:
    """Run the anti-worm pre-pass and return its findings as a ScanResults.

    Returns an empty (clean) ScanResults if no loaded threat defines any
    worm indicators.
    """
    indicators = aggregate_indicators(threats)
    results = ScanResults()
    if indicators.is_empty:
        return results

    print_phase_header(0, "Anti-worm pre-pass: scanning local git repos...")
    union_roots = deduplicate_roots(
        [root for roots in roots_cache.values() for root in roots]
    )
    snapshots = build_repo_index(union_roots)
    print(
        f"  Scanned {BOLD}{len(snapshots)}{RESET} local git repo(s) "
        f"against {BOLD}{_indicator_count(indicators)}{RESET} worm indicator(s)\n"
    )
    scan_anti_worm(results, indicators, snapshots)
    return results


def _indicator_count(indicators) -> int:
    return (
        len(indicators.workflow_filenames)
        + len(indicators.workflow_name_regexes)
        + len(indicators.branch_names)
        + len(indicators.branch_name_regexes)
        + len(indicators.commit_author_emails)
        + len(indicators.repo_descriptions)
    )
