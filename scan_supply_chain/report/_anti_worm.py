"""Anti-worm pre-pass report — worm-class git-artifact findings."""

from __future__ import annotations

from ..formatting import BOLD, RED, RESET, YELLOW, print_separator
from ..models import Finding, ScanResults


def print_anti_worm_report(results: ScanResults) -> None:
    """Print the dedicated worm-class indicators section.

    Called once per scan, before the per-threat summary. Silent when
    no findings were recorded.
    """
    if not results.findings:
        return

    by_repo: dict[str, list[Finding]] = {}
    for f in results.findings:
        by_repo.setdefault(f.evidence, []).append(f)

    repo_count = len(by_repo)
    print_separator()
    print(f"\n{RED}{BOLD}!! WORM-CLASS GIT ARTIFACTS in {repo_count} repo(s){RESET}\n")
    for repo_path, repo_findings in sorted(by_repo.items()):
        max_weight = max(f.weight for f in repo_findings)
        tier = "HIGH" if max_weight >= 3 else "LOW"
        color = RED if max_weight >= 3 else YELLOW
        print(f"  {color}{BOLD}{repo_path}{RESET} ({color}{tier}{RESET})")
        for f in repo_findings:
            print(f"    - {f.description}")
        print()
