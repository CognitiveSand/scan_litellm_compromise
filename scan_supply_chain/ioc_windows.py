"""Windows-only IOC checks: Registry Run keys, Scheduled Tasks."""

from .formatting import (
    BOLD,
    RED,
    RESET,
    print_check_header,
    print_clean,
)
from .models import ScanResults
from .subprocess_utils import run_safe


def _check_registry_run_keys(
    results: ScanResults,
    keywords: list[str],
) -> None:
    """Check HKCU and HKLM Run keys for suspicious entries."""
    if not keywords:
        return
    print_check_header("Registry Run keys for persistence")
    found = False
    run_keys = [
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
        r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
    ]
    for key_path in run_keys:
        output = run_safe(["reg", "query", key_path], timeout=10)
        if output is None:
            continue
        output = output.lower()
        for keyword in keywords:
            if keyword.lower() in output:
                print(
                    f"  {RED}{BOLD}! SUSPICIOUS REGISTRY ENTRY "
                    f"in {key_path} (matched: {keyword}){RESET}"
                )
                results.iocs.append(f"registry:{key_path}:{keyword}")
                found = True
    if not found:
        print_clean("No suspicious Run key entries")


def _check_scheduled_tasks(
    results: ScanResults,
    keywords: list[str],
) -> None:
    """Check Task Scheduler for suspicious tasks."""
    if not keywords:
        return
    print_check_header("Scheduled Tasks for persistence")
    found = False
    output = run_safe(["schtasks", "/query", "/fo", "CSV"], timeout=15)
    if output is not None:
        output = output.lower()
        for keyword in keywords:
            if keyword.lower() in output:
                print(
                    f"  {RED}{BOLD}! SUSPICIOUS SCHEDULED TASK "
                    f"(matched: {keyword}){RESET}"
                )
                results.iocs.append(f"schtask:{keyword}")
                found = True
    if not found:
        print_clean("No suspicious scheduled tasks")


def run_windows_ioc_checks(
    results: ScanResults,
    registry_keywords: list[str],
    schtask_keywords: list[str],
) -> None:
    """Run all Windows-specific IOC checks."""
    print()
    _check_registry_run_keys(results, registry_keywords)
    print()
    _check_scheduled_tasks(results, schtask_keywords)
