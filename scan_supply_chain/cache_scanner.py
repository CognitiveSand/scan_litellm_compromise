"""Package cache scanner — checks pip/npm/pnpm caches for compromised packages."""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path

from .models import FindingCategory, ScanResults, scanner_check
from .skip_report import SkipReport

logger = logging.getLogger(__name__)


def scan_caches(
    results: ScanResults,
    package: str,
    ecosystem: str,
    skip_report: SkipReport | None = None,
) -> None:
    """Check package manager caches for traces of the compromised package.

    ``skip_report`` defaults to a throwaway instance so legacy unit
    tests keep the simple signature.
    """
    if skip_report is None:
        skip_report = SkipReport()
    with scanner_check(results, "package manager caches", "No cache traces found"):
        if ecosystem == "pypi":
            _scan_pip_cache(results, package, skip_report)
        elif ecosystem == "npm":
            _scan_npm_cache(results, package, skip_report)
            _scan_pnpm_store(results, package, skip_report)


# ── Helpers ─────────────────────────────────────────────────────────────


def _pip_cache_dir() -> Path:
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Caches" / "pip"
    if sys.platform == "win32":
        local = os.environ.get("LOCALAPPDATA", "")
        return (
            Path(local) / "pip" / "Cache" if local else Path.home() / ".cache" / "pip"
        )
    return Path.home() / ".cache" / "pip"


def _scan_cache_dir(
    results: ScanResults,
    cache_dir: Path,
    package: str,
    label: str,
    skip_report: SkipReport,
    *,
    check_dirs: bool = False,
    check_files: bool = True,
) -> None:
    """Walk a cache directory for entries matching the package name."""
    if not cache_dir.is_dir():
        return
    try:
        for dirpath, dirnames, filenames in os.walk(cache_dir):
            items: list[str] = []
            if check_dirs:
                items.extend(dirnames)
            if check_files:
                items.extend(filenames)
            for name in items:
                if package in name.lower():
                    results.add_finding(
                        FindingCategory.CACHE_TRACE,
                        f"{label}: {name}",
                        os.path.join(dirpath, name),
                        1,
                    )
                    return  # one hit per cache is enough
    except PermissionError:
        skip_report.record_permission(cache_dir)
    except OSError as exc:
        skip_report.record_read_error(cache_dir, type(exc).__name__)


def _scan_pip_cache(
    results: ScanResults, package: str, skip_report: SkipReport
) -> None:
    _scan_cache_dir(
        results,
        _pip_cache_dir(),
        package,
        "pip cache",
        skip_report,
        check_dirs=True,
        check_files=True,
    )


def _scan_npm_cache(
    results: ScanResults, package: str, skip_report: SkipReport
) -> None:
    _scan_cache_dir(
        results,
        Path.home() / ".npm" / "_cacache",
        package,
        "npm cache",
        skip_report,
    )


def _scan_pnpm_store(
    results: ScanResults, package: str, skip_report: SkipReport
) -> None:
    _scan_cache_dir(
        results,
        Path.home() / ".local" / "share" / "pnpm" / "store",
        package,
        "pnpm store",
        skip_report,
        check_dirs=True,
        check_files=False,
    )
