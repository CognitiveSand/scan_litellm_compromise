"""Generic persistence location scanner.

Checks common persistence mechanisms that any supply chain attack
might abuse, independent of the specific threat profile.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
import sys
from pathlib import Path

from .formatting import print_check_header, print_clean, print_ioc_found
from .models import Finding, FindingCategory, ScanResults

logger = logging.getLogger(__name__)


def scan_persistence(results: ScanResults, package: str) -> None:
    """Scan common persistence locations for package references."""
    print_check_header("generic persistence locations")
    count_before = len(results.findings)

    _check_crontab(results, package)
    _check_shell_rc(results, package)
    _check_tmp_scripts(results)

    if sys.platform == "linux":
        _check_systemd_user(results, package)
        _check_xdg_autostart(results)
    elif sys.platform == "darwin":
        _check_launch_agents(results, package)

    if len(results.findings) == count_before:
        print_clean("No suspicious persistence found")


def _add_persistence(results: ScanResults, description: str, evidence: str) -> None:
    print_ioc_found(description)
    results.iocs.append(f"persistence:{description}")
    results.findings.append(
        Finding(
            category=FindingCategory.PERSISTENCE,
            description=description,
            evidence=evidence,
            weight=2,
        )
    )


def _check_crontab(results: ScanResults, package: str) -> None:
    if not shutil.which("crontab"):
        return
    try:
        output = subprocess.run(
            ["crontab", "-l"], capture_output=True, text=True, timeout=5
        ).stdout
        for line in output.splitlines():
            if package in line and not line.strip().startswith("#"):
                _add_persistence(results, f"crontab: {line.strip()}", "crontab -l")
    except (subprocess.TimeoutExpired, OSError):
        logger.debug("Failed to read crontab")


def _check_shell_rc(results: ScanResults, package: str) -> None:
    home = Path.home()
    for rc_name in (".bashrc", ".zshrc", ".profile", ".bash_profile"):
        rc_path = home / rc_name
        if not rc_path.is_file():
            continue
        try:
            text = rc_path.read_text(errors="ignore")
            for i, line in enumerate(text.splitlines(), 1):
                if package in line and not line.strip().startswith("#"):
                    _add_persistence(
                        results,
                        f"{rc_name}:{i} mentions {package}",
                        str(rc_path),
                    )
        except (PermissionError, OSError):
            logger.debug("Cannot read %s", rc_path)


def _check_tmp_scripts(results: ScanResults) -> None:
    tmp = Path("/tmp") if sys.platform != "win32" else None
    if tmp is None or not tmp.is_dir():
        return
    try:
        for f in tmp.iterdir():
            if f.is_file() and f.suffix in (".py", ".sh", ".bash"):
                _add_persistence(
                    results,
                    f"/tmp script: {f.name}",
                    str(f),
                )
    except (PermissionError, OSError):
        logger.debug("Cannot read /tmp")


def _check_systemd_user(results: ScanResults, package: str) -> None:
    systemd_dir = Path.home() / ".config" / "systemd" / "user"
    if not systemd_dir.is_dir():
        return
    try:
        for service_file in systemd_dir.glob("*.service"):
            text = service_file.read_text(errors="ignore")
            if package in text:
                _add_persistence(
                    results,
                    f"systemd user service: {service_file.name}",
                    str(service_file),
                )
    except (PermissionError, OSError):
        logger.debug("Cannot read systemd user dir")


def _check_xdg_autostart(results: ScanResults) -> None:
    autostart = Path.home() / ".config" / "autostart"
    if not autostart.is_dir():
        return
    try:
        for desktop_file in autostart.glob("*.desktop"):
            _add_persistence(
                results,
                f"XDG autostart: {desktop_file.name}",
                str(desktop_file),
            )
    except (PermissionError, OSError):
        logger.debug("Cannot read autostart dir")


def _check_launch_agents(results: ScanResults, package: str) -> None:
    agents_dir = Path.home() / "Library" / "LaunchAgents"
    if not agents_dir.is_dir():
        return
    try:
        for plist in agents_dir.glob("*.plist"):
            text = plist.read_text(errors="ignore")
            if package in text:
                _add_persistence(
                    results,
                    f"LaunchAgent: {plist.name}",
                    str(plist),
                )
    except (PermissionError, OSError):
        logger.debug("Cannot read LaunchAgents")
