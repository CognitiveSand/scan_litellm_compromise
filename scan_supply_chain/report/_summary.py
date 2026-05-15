"""Combined multi-threat scan summary."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..formatting import BOLD, GREEN, RED, RESET, print_separator
from ..models import ScanResults
from ._threat import print_threat_report

if TYPE_CHECKING:
    from ..threat_profile import ThreatProfile


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
