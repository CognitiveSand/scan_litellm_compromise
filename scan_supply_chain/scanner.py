"""Main orchestrator for the supply chain compromise scanner."""

import argparse
import logging
import sys
from pathlib import Path

from . import __version__
from .anti_worm_scanner import WormIndicators, aggregate_indicators, scan_anti_worm
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
from .cache_scanner import scan_caches
from .git_repo_index import build_repo_index
from .history_scanner import scan_history
from .ioc_scanner import (
    scan_for_c2_connections,
    scan_for_malicious_pods,
    scan_known_paths,
    scan_phantom_deps,
    scan_walk_files,
    scan_windows_extras,
)
from .models import ScanResults
from .persistence_scanner import scan_persistence
from .platform_policy import PlatformPolicy, detect_platform
from .scan_context import ScanContext
from .report import (
    print_anti_worm_report,
    print_config_refs,
    print_multi_threat_summary,
    print_skip_summary,
    print_source_refs,
)
from .search_roots import build_search_roots, deduplicate_roots
from .skip_report import SkipReport
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


def _scan_single_threat(ctx: ScanContext) -> ScanResults:
    """Run the full 5-phase pipeline for one threat profile."""
    threat = ctx.threat
    results = ScanResults(compromised_versions=threat.compromised)

    print_separator()
    print(f"\n{BOLD}Scanning for: {threat.name}{RESET}")
    print(f"  Package: {threat.package} ({threat.ecosystem.upper()})")
    compromised_str = ", ".join(sorted(threat.compromised))
    print(f"  Compromised versions: {compromised_str}\n")

    # Phase 1: Discover installations
    print_phase_header(1, f"Discovering {threat.package} installations...")
    metadata_dirs = find_package_metadata(
        ctx.roots, ctx.ecosystem, threat.package, ctx.skip_report
    )
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
    scan_environments(metadata_dirs, results, ctx.ecosystem, threat, ctx.skip_report)

    # Phase 3: IOC artifact scan
    print_phase_header(3, "Scanning for IOC artifacts...")
    _run_phase3_iocs(results, ctx)

    # Phase 4: Source & config scan
    print_phase_header(
        4,
        f"Scanning source files for {threat.package} usage...",
    )
    files_scanned = scan_source_and_configs(results, ctx)
    print(f"  Files scanned: {BOLD}{files_scanned}{RESET}\n")
    print_source_refs(results.source_refs, threat.package)
    print_config_refs(
        results.config_refs,
        threat.package,
        threat.compromised,
    )

    return results


def _configure_logging() -> None:
    logging.basicConfig(
        level=logging.WARNING,
        format="%(levelname)s: %(message)s",
    )


def _print_run_banner(policy: PlatformPolicy, threats: list[ThreatProfile]) -> None:
    """Print the top-of-scan banner: version, platform, threat list."""
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


def _cache_search_roots(
    threats: list[ThreatProfile], policy: PlatformPolicy
) -> dict[str, list[str]]:
    """Build one search-root list per distinct ecosystem in *threats*."""
    roots_cache: dict[str, list[str]] = {}
    for threat in threats:
        if threat.ecosystem not in roots_cache:
            ecosystem = get_ecosystem(threat.ecosystem)
            roots_cache[threat.ecosystem] = build_search_roots(policy, ecosystem)
    return roots_cache


def _dispatch_threats(
    threats: list[ThreatProfile],
    policy: PlatformPolicy,
    roots_cache: dict[str, list[str]],
    resolve_c2: bool,
    skip_report: SkipReport,
) -> list[tuple[ThreatProfile, ScanResults]]:
    """Run the 5-phase pipeline for each threat and collect results."""
    all_results: list[tuple[ThreatProfile, ScanResults]] = []
    for threat in threats:
        ctx = ScanContext(
            threat=threat,
            ecosystem=get_ecosystem(threat.ecosystem),
            policy=policy,
            roots=roots_cache[threat.ecosystem],
            resolve_c2=resolve_c2,
            skip_report=skip_report,
        )
        results = _scan_single_threat(ctx)
        all_results.append((threat, results))
    return all_results


def _compute_exit_code(
    anti_worm_results: ScanResults,
    all_results: list[tuple[ThreatProfile, ScanResults]],
) -> int:
    any_compromised = any(not r.is_clean for _, r in all_results)
    any_worm_signals = not anti_worm_results.is_clean
    return 1 if (any_compromised or any_worm_signals) else 0


def main() -> int:
    _configure_logging()
    args = _parse_args()

    if args.list_threats:
        _do_list_threats()

    threats = _resolve_threats(args)
    if not threats:
        print("No threat profiles found. Nothing to scan.")
        return 0

    # Single SkipReport for the whole scan — shared across every threat's
    # per-threat ScanContext and the anti-worm pre-pass so the post-scan
    # summary aggregates skips from every filesystem walk.
    skip_report = SkipReport()
    policy = detect_platform()

    _print_run_banner(policy, threats)
    roots_cache = _cache_search_roots(threats, policy)

    anti_worm_results = _run_anti_worm_pass(threats, roots_cache, skip_report)
    all_results = _dispatch_threats(
        threats, policy, roots_cache, args.resolve_c2, skip_report
    )

    # Final combined report — anti-worm section first, then per-threat,
    # then the skip-report telling the operator what coverage was missed.
    print()
    print_anti_worm_report(anti_worm_results)
    print_multi_threat_summary(all_results)
    print_skip_summary(skip_report)

    return _compute_exit_code(anti_worm_results, all_results)


def _run_phase3_iocs(results: ScanResults, ctx: ScanContext) -> None:
    """Run every phase-3 IOC scanner for a single threat profile.

    Lives here rather than in ``ioc_scanner`` so the full set of
    scanners triggered for one threat is visible at module top of
    ``scanner.py`` (the orchestration layer), and so cache / history /
    persistence scanners do not have to be lazy-imported from inside
    ``ioc_scanner.scan_iocs``.
    """
    threat = ctx.threat
    if threat.walk_files:
        scan_walk_files(results, ctx)
        print()

    if threat.known_paths:
        scan_known_paths(results, ctx)
        print()

    scan_for_c2_connections(results, ctx)
    scan_for_malicious_pods(results, ctx)
    scan_phantom_deps(results, ctx)
    scan_windows_extras(results, ctx)

    scan_persistence(
        results, threat.package, threat.persistence_keywords, ctx.skip_report
    )
    scan_caches(results, threat.package, threat.ecosystem, ctx.skip_report)
    scan_history(results, threat.package, threat.ecosystem, ctx.skip_report)


def _run_anti_worm_pass(
    threats: list[ThreatProfile],
    roots_cache: dict[str, list[str]],
    skip_report: SkipReport,
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
    snapshots = build_repo_index(union_roots, skip_report)
    print(
        f"  Scanned {BOLD}{len(snapshots)}{RESET} local git repo(s) "
        f"against {BOLD}{_indicator_count(indicators)}{RESET} worm indicator(s)\n"
    )
    scan_anti_worm(results, indicators, snapshots)
    return results


def _indicator_count(indicators: WormIndicators) -> int:
    return (
        len(indicators.workflow_filenames)
        + len(indicators.workflow_name_regexes)
        + len(indicators.branch_names)
        + len(indicators.branch_name_regexes)
        + len(indicators.commit_author_emails)
        + len(indicators.repo_descriptions)
    )
