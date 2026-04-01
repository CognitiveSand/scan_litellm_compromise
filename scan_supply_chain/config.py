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


def pruned_walk(
    root: Path, skip_dirs: frozenset[str]
) -> Generator[tuple[str, list[str], list[str]], None, None]:
    """os.walk with directory pruning and PermissionError handling."""
    try:
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in skip_dirs]
            yield dirpath, dirnames, filenames
    except PermissionError:
        logger.debug("Permission denied walking %s", root)
