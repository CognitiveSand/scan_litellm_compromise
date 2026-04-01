"""Phase 5: Summary report and remediation guidance."""

from __future__ import annotations

from typing import TYPE_CHECKING

from .formatting import BOLD, GREEN, RED, RESET, YELLOW, print_separator
from .models import ConfigReference, ScanResults, SourceReference

if TYPE_CHECKING:
    from .threat_profile import ThreatProfile

_MAX_LINES_PER_FILE = 5


# ── Reference display ───────────────────────────────────────────────────


def _file_path_key(ref):
    return ref.file_path


def _group_by_file(refs, key=None):
    """Group references by file path, preserving order."""
    if key is None:
        key = _file_path_key
    grouped: dict[str, list] = {}
    for ref in refs:
        grouped.setdefault(key(ref), []).append(ref)
    return grouped


def _format_version_tag(
    ref: ConfigReference,
    compromised: frozenset[str],
) -> str:
    """Format a version annotation for a config reference."""
    if ref.pinned_version and ref.pinned_version in compromised:
        return f"  {RED}{BOLD}! PINNED TO COMPROMISED VERSION{RESET}"
    if ref.pinned_version:
        return f"  {GREEN}(v{ref.pinned_version}){RESET}"
    return ""


def print_source_refs(
    refs: list[SourceReference],
    package: str,
) -> None:
    """Print grouped source file references."""
    if not refs:
        print(f"  {GREEN}+ No {package} imports found in source files{RESET}\n")
        return

    by_file = _group_by_file(refs)
    print(
        f"  {BOLD}Source files referencing {package} ({len(by_file)} files):{RESET}\n"
    )

    for file_path, file_refs in sorted(by_file.items()):
        print(f"    {YELLOW}{file_path}{RESET}")
        for ref in file_refs[:_MAX_LINES_PER_FILE]:
            print(f"      L{ref.line_number}: {ref.line_content}")
        remaining = len(file_refs) - _MAX_LINES_PER_FILE
        if remaining > 0:
            print(f"      ... and {remaining} more references")
        print()


def print_config_refs(
    refs: list[ConfigReference],
    package: str,
    compromised: frozenset[str],
) -> None:
    """Print grouped config file references with version annotations."""
    if not refs:
        print(
            f"  {GREEN}+ No {package} dependencies found in "
            f"config/requirements files{RESET}\n"
        )
        return

    by_file = _group_by_file(refs)
    print(
        f"  {BOLD}Config/dependency files referencing {package} "
        f"({len(by_file)} files):{RESET}\n"
    )

    for file_path, file_refs in sorted(by_file.items()):
        print(f"    {YELLOW}{file_path}{RESET}")
        for ref in file_refs:
            version_tag = _format_version_tag(ref, compromised)
            print(f"      L{ref.line_number}: {ref.line_content}{version_tag}")
        print()


# ── Stats ────────────────────────────────────────────────────────────────


def _print_stats(results: ScanResults, threat: ThreatProfile) -> None:
    """Print scan statistics."""
    pkg = threat.package
    print(f"  Environments scanned:         {BOLD}{results.envs_scanned}{RESET}")
    print(f"  {pkg} installations found:  {BOLD}{len(results.installations)}{RESET}")

    compromised = results.compromised_installations
    if compromised:
        print(f"  {RED}{BOLD}Compromised versions found:     {len(compromised)}{RESET}")
    else:
        print(f"  Compromised versions found:    {GREEN}0{RESET}")

    if results.iocs:
        print(
            f"  {RED}{BOLD}IOC artifacts found:            {len(results.iocs)}{RESET}"
        )
    else:
        print(f"  IOC artifacts found:           {GREEN}0{RESET}")

    print(
        f"  Source files using {pkg}:    {BOLD}{len(results.source_files)}{RESET} files"
    )
    print(
        f"  Config files with {pkg}:     {BOLD}{len(results.config_files)}{RESET} files"
    )

    compromised_configs = results.compromised_configs
    if compromised_configs:
        print(
            f"  {RED}{BOLD}Configs pinned to bad version:   "
            f"{len(compromised_configs)}{RESET}"
        )


# ── Verdicts ─────────────────────────────────────────────────────────────


def _print_remediation(
    results: ScanResults,
    threat: ThreatProfile,
) -> None:
    """Print remediation steps for a compromised system."""
    remediation = threat.remediation
    print()
    print(f"  {RED}{BOLD}!  COMPROMISE DETECTED -- REMEDIATION STEPS:{RESET}\n")

    step = 1
    if remediation.rotate_secrets:
        print(
            f"  {step}. {BOLD}Assume ALL secrets on this machine are compromised{RESET}"
        )
        print("     -> Rotate SSH keys, cloud credentials (AWS/GCP/Azure), API keys")
        print("     -> Revoke and regenerate .env files and tokens")
        print()
        step += 1

    artifact_lines = remediation.artifact_lines_for_platform()
    if artifact_lines:
        print(f"  {step}. {BOLD}Remove malicious artifacts:{RESET}")
        for line in artifact_lines:
            print(f"     -> {line}")
        print()
        step += 1

    if remediation.install_command:
        print(f"  {step}. {BOLD}Fix {threat.package}:{RESET}")
        print(f"     -> {remediation.install_command}")
        print("     -> Or upgrade past compromised range once verified")
        print()
        step += 1

    compromised_configs = results.compromised_configs
    if compromised_configs:
        print(f"  {step}. {BOLD}Update pinned versions in config files:{RESET}")
        for ref in compromised_configs:
            print(f"     -> {ref.file_path}:{ref.line_number}")
            print(f"       Change: {ref.line_content}")
        print()
        step += 1

    persistence_steps = remediation.persistence_steps_for_platform()
    if persistence_steps:
        print(f"  {step}. {BOLD}Check persistence mechanisms:{RESET}")
        for ps in persistence_steps:
            print(f"     -> {ps}")
        print()

    if threat.advisory:
        print(f"  Reference: {threat.advisory}")


def _print_clean_verdict(
    results: ScanResults,
    threat: ThreatProfile,
) -> None:
    """Print the all-clear verdict with optional warnings."""
    print()
    print(f"  {GREEN}{BOLD}+ No compromise detected. System appears clean.{RESET}")

    if results.source_refs or results.config_refs:
        compromised_str = ", ".join(sorted(threat.compromised))
        print()
        print(
            f"  {YELLOW}{BOLD}NOTE:{RESET} {threat.package} references were "
            f"found in source or config files."
        )
        print(
            f"  Verify they use a safe version "
            f"(not {compromised_str}) and update if needed."
        )


# ── Per-threat report ───────────────────────────────────────────────────


def print_threat_report(
    results: ScanResults,
    threat: ThreatProfile,
) -> None:
    """Print the scan report for a single threat."""
    print(
        f"\n{BOLD}--- {threat.id} "
        f"({threat.ecosystem.upper()}: {threat.package}) ---{RESET}\n"
    )
    _print_stats(results, threat)

    if results.is_clean:
        _print_clean_verdict(results, threat)
    else:
        _print_remediation(results, threat)


# ── Multi-threat summary ────────────────────────────────────────────────


def print_multi_threat_summary(
    threat_results: list[tuple[ThreatProfile, ScanResults]],
) -> None:
    """Print the combined summary across all threat scans."""
    print_separator()
    print(
        f"\n{BOLD}SCAN RESULTS -- "
        f"{len(threat_results)} threat profile(s) checked{RESET}\n"
    )

    any_compromised = False
    for threat, results in threat_results:
        print_threat_report(results, threat)
        if not results.is_clean:
            any_compromised = True
        print()

    print_separator()
    if any_compromised:
        print(
            f"\n{RED}{BOLD}!! ONE OR MORE COMPROMISES DETECTED -- "
            f"SEE REMEDIATION ABOVE !!{RESET}\n"
        )
    else:
        print(
            f"\n{GREEN}{BOLD}All checks passed. "
            f"No known supply chain compromises detected.{RESET}\n"
        )
    print_separator()
