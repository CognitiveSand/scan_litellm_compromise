"""Post-scan skipped-paths summary."""

from __future__ import annotations

from pathlib import Path

from ..formatting import BOLD, RESET, YELLOW, print_separator
from ..skip_report import SkipReport

_SKIP_SUMMARY_HEAD = 5


def _print_path_head(paths: list[Path]) -> None:
    """Print the first few paths plus a count of the rest."""
    for p in paths[:_SKIP_SUMMARY_HEAD]:
        print(f"    {p}")
    remaining = len(paths) - _SKIP_SUMMARY_HEAD
    if remaining > 0:
        print(f"    ... and {remaining} more")
    print()


def print_skip_summary(report: SkipReport) -> None:
    """Render the per-scan skip report. Silent when empty.

    Filesystem paths the scanner couldn't walk or read are listed here
    so the operator knows how much of the disk was actually inspected —
    a partial scan from missing privileges is not a clean scan.
    """
    if report.is_empty:
        return

    print_separator()
    print(f"\n{YELLOW}{BOLD}Skipped {report.total} path(s) during this scan{RESET}\n")

    if report.permission_errors:
        print(
            f"  {YELLOW}{BOLD}Permission denied "
            f"({len(report.permission_errors)}):{RESET}"
        )
        _print_path_head(sorted(report.permission_errors))

    if report.read_errors:
        print(f"  {YELLOW}{BOLD}Read errors ({len(report.read_errors)}):{RESET}")
        for path, reason in sorted(report.read_errors.items())[:_SKIP_SUMMARY_HEAD]:
            print(f"    {path}  ({reason})")
        remaining = len(report.read_errors) - _SKIP_SUMMARY_HEAD
        if remaining > 0:
            print(f"    ... and {remaining} more")
        print()

    print(
        f"  {YELLOW}Hint: re-run with elevated privileges to cover paths "
        f"the current user cannot access.{RESET}\n"
    )
