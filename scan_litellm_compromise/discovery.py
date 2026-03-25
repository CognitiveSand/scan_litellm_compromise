"""Phase 1: Discover litellm installations via filesystem metadata."""

from __future__ import annotations

import glob as globmod
import logging
import os
from pathlib import Path
from typing import TYPE_CHECKING

from .config import DISCOVERY_SKIP_DIRS, DIST_INFO_PATTERN, EGG_INFO_PATTERN

if TYPE_CHECKING:
    from .platform_policy import PlatformPolicy

logger = logging.getLogger(__name__)


def _build_search_roots(policy: PlatformPolicy) -> list[str]:
    """Combine platform roots with user-local conda/pipx directories."""
    roots = list(policy.search_roots)
    home = Path.home()

    for extra_dir in policy.home_conda_dirs():
        candidate = home / extra_dir
        if candidate.is_dir():
            roots.append(str(candidate))

    pipx_dir = policy.home_pipx_dir()
    if pipx_dir is not None:
        roots.append(str(pipx_dir))

    for pattern in policy.conda_globs:
        roots.extend(globmod.glob(pattern))

    return roots


def _is_litellm_metadata_dir(dirname: str) -> bool:
    """Check if a directory name is a litellm dist-info or egg-info."""
    return bool(
        DIST_INFO_PATTERN.match(dirname) or EGG_INFO_PATTERN.match(dirname)
    )


def _walk_for_litellm_metadata(root: Path) -> list[Path]:
    """Walk a directory tree looking for litellm metadata directories."""
    found = []
    try:
        for dirpath, dirnames, _ in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in DISCOVERY_SKIP_DIRS]
            for dirname in dirnames:
                if _is_litellm_metadata_dir(dirname):
                    found.append(Path(dirpath) / dirname)
    except PermissionError:
        logger.debug("Permission denied walking %s", root)
    return found


def _deduplicate_by_realpath(paths: list[Path]) -> list[Path]:
    """Remove duplicates that resolve to the same real path."""
    seen: set[Path] = set()
    unique: list[Path] = []
    for path in paths:
        try:
            resolved = path.resolve()
        except OSError:
            resolved = path
        if resolved not in seen:
            seen.add(resolved)
            unique.append(path)
    return unique


def find_litellm_metadata(policy: PlatformPolicy) -> list[Path]:
    """Find all litellm dist-info/egg-info directories on the system."""
    roots = _build_search_roots(policy)
    found: list[Path] = []

    for root in roots:
        root_path = Path(root)
        if root_path.is_dir():
            found.extend(_walk_for_litellm_metadata(root_path))

    return _deduplicate_by_realpath(found)
