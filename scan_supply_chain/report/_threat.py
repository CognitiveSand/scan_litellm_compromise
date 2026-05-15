"""Per-threat report — stats block plus clean / remediation verdict."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..formatting import BOLD, GREEN, RED, RESET, YELLOW
from ..models import Confidence, ScanResults
from ..scoring import compute_confidence

if TYPE_CHECKING:
    from ..threat_profile import ThreatProfile


_CONFIDENCE_COLORS = {
    Confidence.LOW: YELLOW,
    Confidence.MEDIUM: YELLOW + BOLD,
    Confidence.HIGH: RED,
    Confidence.CRITICAL: RED + BOLD,
}


def _confidence_color(confidence: Confidence) -> str:
    return _CONFIDENCE_COLORS.get(confidence, BOLD)


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

    confidence = compute_confidence(results.findings)
    if confidence is not None:
        color = _confidence_color(confidence)
        print(f"  {color}Confidence:                     {confidence.value}{RESET}")


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
