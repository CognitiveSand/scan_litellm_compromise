"""Package cache scanner — checks pip/npm/pnpm caches for compromised packages."""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path

from .formatting import print_check_header
from .models import FindingCategory, ScanResults, track_findings

logger = logging.getLogger(__name__)


def scan_caches(results: ScanResults, package: str, ecosystem: str) -> None:
    """Check package manager caches for traces of the compromised package."""
    print_check_header("package manager caches")
    with track_findings(results, "No cache traces found"):
        if ecosystem == "pypi":
            _scan_pip_cache(results, package)
        elif ecosystem == "npm":
            _scan_npm_cache(results, package)
            _scan_pnpm_store(results, package)


def _add_cache_finding(results: ScanResults, description: str, evidence: str) -> None:
    results.add_finding(FindingCategory.CACHE_TRACE, description, evidence, 1)


def _pip_cache_dir() -> Path:
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Caches" / "pip"
    if sys.platform == "win32":
        local = os.environ.get("LOCALAPPDATA", "")
        return (
            Path(local) / "pip" / "Cache" if local else Path.home() / ".cache" / "pip"
        )
    return Path.home() / ".cache" / "pip"


def _scan_pip_cache(results: ScanResults, package: str) -> None:
    cache_dir = _pip_cache_dir()
    if not cache_dir.is_dir():
        return
    try:
        for dirpath, dirnames, filenames in os.walk(cache_dir):
            for name in dirnames + filenames:
                if package in name.lower():
                    _add_cache_finding(
                        results,
                        f"pip cache: {name}",
                        os.path.join(dirpath, name),
                    )
                    return  # one hit per cache is enough
    except (PermissionError, OSError):
        logger.debug("Cannot read pip cache at %s", cache_dir)


def _scan_npm_cache(results: ScanResults, package: str) -> None:
    cache_dir = Path.home() / ".npm" / "_cacache"
    if not cache_dir.is_dir():
        return
    try:
        for dirpath, _, filenames in os.walk(cache_dir):
            for fn in filenames:
                if package in fn:
                    _add_cache_finding(
                        results,
                        f"npm cache: {fn}",
                        os.path.join(dirpath, fn),
                    )
                    return
    except (PermissionError, OSError):
        logger.debug("Cannot read npm cache")


def _scan_pnpm_store(results: ScanResults, package: str) -> None:
    store = Path.home() / ".local" / "share" / "pnpm" / "store"
    if not store.is_dir():
        return
    try:
        for dirpath, dirnames, _ in os.walk(store):
            for d in dirnames:
                if package in d:
                    _add_cache_finding(
                        results,
                        f"pnpm store: {d}",
                        os.path.join(dirpath, d),
                    )
                    return
    except (PermissionError, OSError):
        logger.debug("Cannot read pnpm store")
