"""Generic persistence location scanner.

Checks common persistence mechanisms that any supply chain attack
might abuse, independent of the specific threat profile.
Every checker filters by the target package name — no generic noise.
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
    _check_tmp_scripts(results, package)

    if sys.platform == "linux":
        _check_config_dir(
            results,
            Path.home() / ".config" / "systemd" / "user",
            "*.service",
            "systemd user service",
            package,
        )
        _check_config_dir(
            results,
            Path.home() / ".config" / "autostart",
            "*.desktop",
            "XDG autostart",
            package,
        )
    elif sys.platform == "darwin":
        _check_config_dir(
            results,
            Path.home() / "Library" / "LaunchAgents",
            "*.plist",
            "LaunchAgent",
            package,
        )

    if len(results.findings) == count_before:
        print_clean("No suspicious persistence found")


# ── Helpers ─────────────────────────────────────────────────────────────


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


def _check_config_dir(
    results: ScanResults,
    directory: Path,
    glob_pattern: str,
    label: str,
    package: str,
) -> None:
    """Glob a config directory for files mentioning the package."""
    if not directory.is_dir():
        return
    try:
        for config_file in directory.glob(glob_pattern):
            text = config_file.read_text(errors="ignore")
            if package in text:
                _add_persistence(
                    results,
                    f"{label}: {config_file.name}",
                    str(config_file),
                )
    except (PermissionError, OSError):
        logger.debug("Cannot read %s", directory)


# ── Individual checkers ─────────────────────────────────────────────────


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


def _check_tmp_scripts(results: ScanResults, package: str) -> None:
    """Check /tmp for scripts that actually import the package."""
    tmp = Path("/tmp") if sys.platform != "win32" else None
    if tmp is None or not tmp.is_dir():
        return
    try:
        for f in tmp.iterdir():
            if not f.is_file():
                continue
            if f.suffix == ".py":
                _check_tmp_python_file(results, f, package)
            elif f.suffix in (".sh", ".bash"):
                _check_tmp_shell_file(results, f, package)
    except (PermissionError, OSError):
        logger.debug("Cannot read /tmp")


def _check_tmp_python_file(results: ScanResults, path: Path, package: str) -> None:
    """Flag a /tmp .py file only if it actually imports the package."""
    try:
        text = path.read_text(errors="ignore")
    except (PermissionError, OSError):
        return

    if package not in text:
        return

    from .ast_scanner import scan_python_imports

    lines = text.splitlines()
    ast_refs = scan_python_imports(text, lines, package, str(path))

    if ast_refs is not None:
        # AST parsed successfully — trust its result
        if ast_refs:
            _add_persistence(results, f"/tmp script: {path.name}", str(path))
    else:
        # SyntaxError fallback — check non-comment lines
        if _has_active_reference(text, package):
            _add_persistence(results, f"/tmp script: {path.name}", str(path))


def _check_tmp_shell_file(results: ScanResults, path: Path, package: str) -> None:
    """Flag a /tmp shell script only if it references the package."""
    try:
        text = path.read_text(errors="ignore")
    except (PermissionError, OSError):
        return

    if _has_active_reference(text, package):
        _add_persistence(results, f"/tmp script: {path.name}", str(path))


def _has_active_reference(text: str, package: str) -> bool:
    """Check if any non-comment line contains the package name."""
    return any(
        package in line and not line.strip().startswith("#")
        for line in text.splitlines()
    )
