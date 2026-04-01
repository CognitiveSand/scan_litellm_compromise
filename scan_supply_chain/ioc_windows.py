"""Windows-only IOC checks: Registry Run keys, Scheduled Tasks."""

import logging
import subprocess

from .formatting import (
    BOLD,
    RED,
    RESET,
    print_check_header,
    print_clean,
)

logger = logging.getLogger(__name__)


def _check_registry_run_keys(
    results,
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
        try:
            output = subprocess.run(
                ["reg", "query", key_path],
                capture_output=True,
                text=True,
                timeout=10,
            ).stdout.lower()
            for keyword in keywords:
                if keyword.lower() in output:
                    print(
                        f"  {RED}{BOLD}! SUSPICIOUS REGISTRY ENTRY "
                        f"in {key_path} (matched: {keyword}){RESET}"
                    )
                    results.iocs.append(f"registry:{key_path}:{keyword}")
                    found = True
        except (subprocess.TimeoutExpired, OSError):
            logger.debug("Failed to query registry key %s", key_path)
    if not found:
        print_clean("No suspicious Run key entries")


def _check_scheduled_tasks(
    results,
    keywords: list[str],
) -> None:
    """Check Task Scheduler for suspicious tasks."""
    if not keywords:
        return
    print_check_header("Scheduled Tasks for persistence")
    found = False
    try:
        output = subprocess.run(
            ["schtasks", "/query", "/fo", "CSV"],
            capture_output=True,
            text=True,
            timeout=15,
        ).stdout.lower()
        for keyword in keywords:
            if keyword.lower() in output:
                print(
                    f"  {RED}{BOLD}! SUSPICIOUS SCHEDULED TASK "
                    f"(matched: {keyword}){RESET}"
                )
                results.iocs.append(f"schtask:{keyword}")
                found = True
    except (subprocess.TimeoutExpired, OSError):
        logger.debug("Failed to query scheduled tasks")
    if not found:
        print_clean("No suspicious scheduled tasks")


def run_windows_ioc_checks(
    results,
    registry_keywords: list[str],
    schtask_keywords: list[str],
) -> None:
    """Run all Windows-specific IOC checks."""
    print()
    _check_registry_run_keys(results, registry_keywords)
    print()
    _check_scheduled_tasks(results, schtask_keywords)
