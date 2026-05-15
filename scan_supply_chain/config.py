"""Generic constants and shared walk utilities.

All threat-specific values (package name, compromised versions, C2 info,
IOC paths, remediation) live in threats/*.toml and are loaded via
threat_profile.py.  This module holds only ecosystem-neutral defaults.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Generator
from pathlib import Path

from .skip_report import SkipReport

logger = logging.getLogger(__name__)

# Directories always skipped during any filesystem walk
_COMMON_SKIP_DIRS = frozenset(
    {
        "__pycache__",
        ".git",
        ".tox",
        ".mypy_cache",
        ".pytest_cache",
        ".venv-bak",
        "dist",
        "build",
        ".eggs",
        ".cache",
    }
)

# Phase 1/2 discovery needs to enter site-packages / node_modules
DISCOVERY_SKIP_DIRS = _COMMON_SKIP_DIRS

# Phase 3 IOC walk skips unproductive trees (but keeps site-packages
# because .pth backdoors live there)
IOC_WALK_SKIP_DIRS = _COMMON_SKIP_DIRS | {"node_modules"}

# Phantom dep walks need to enter node_modules (npm) and site-packages (pypi)
# but should skip common unproductive dirs
PHANTOM_WALK_SKIP_DIRS = _COMMON_SKIP_DIRS

# Phase 4 source scanner skips third-party code
SOURCE_SCAN_SKIP_DIRS = _COMMON_SKIP_DIRS | {"site-packages", "node_modules"}

# Anti-worm git-repo discovery: same as the common skip set, but
# `.git` is allowed through (the walk looks *for* `.git/` directories).
# Heavy third-party trees are still pruned.
GIT_REPO_WALK_SKIP_DIRS = (_COMMON_SKIP_DIRS - {".git"}) | {
    "node_modules",
    "site-packages",
}


def read_if_contains(path: Path, keyword: str, skip_report: SkipReport) -> str | None:
    """Read a text file if it mentions *keyword*; return text or ``None``.

    Permission and read failures are recorded on ``skip_report`` so the
    post-scan summary can show them.
    """
    if not path.is_file():
        return None
    try:
        text = path.read_text(errors="ignore")
    except PermissionError:
        skip_report.record_permission(path)
        return None
    except OSError as exc:
        skip_report.record_read_error(path, type(exc).__name__)
        return None
    return text if keyword in text else None


def pruned_walk(
    root: Path, skip_dirs: frozenset[str], skip_report: SkipReport
) -> Generator[tuple[str, list[str], list[str]], None, None]:
    """os.walk with directory pruning and skip-report instrumentation.

    Per-directory ``OSError``s (typically ``PermissionError`` on
    inaccessible sub-trees) are routed through the ``onerror`` callback
    so each one is recorded individually — by default ``os.walk``
    silently drops them.
    """

    def _on_error(exc: OSError) -> None:
        path = Path(exc.filename) if exc.filename else root
        if isinstance(exc, PermissionError):
            skip_report.record_permission(path)
        else:
            skip_report.record_read_error(path, type(exc).__name__)

    try:
        for dirpath, dirnames, filenames in os.walk(root, onerror=_on_error):
            dirnames[:] = [d for d in dirnames if d not in skip_dirs]
            yield dirpath, dirnames, filenames
    except PermissionError:
        skip_report.record_permission(root)
