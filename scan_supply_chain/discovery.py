"""Phase 1: Discover package installations via filesystem metadata."""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import TYPE_CHECKING

from .config import DISCOVERY_SKIP_DIRS

if TYPE_CHECKING:
    from .ecosystem_base import EcosystemPlugin

logger = logging.getLogger(__name__)


def _walk_for_metadata(
    root: Path,
    metadata_pattern,
    package: str,
) -> list[Path]:
    """Walk a directory tree looking for package metadata directories."""
    found = []
    try:
        for dirpath, dirnames, _ in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in DISCOVERY_SKIP_DIRS]
            for dirname in dirnames:
                if metadata_pattern.match(dirname):
                    found.append(Path(dirpath) / dirname)
    except PermissionError:
        logger.debug("Permission denied walking %s", root)
    return found


def _walk_for_node_modules(
    root: Path,
    package: str,
) -> list[Path]:
    """Walk a directory tree looking for node_modules/{package}/."""
    found = []
    try:
        for dirpath, dirnames, _ in os.walk(root):
            dp = Path(dirpath)
            if dp.name == "node_modules":
                pkg_dir = dp / package
                if pkg_dir.is_dir() and (pkg_dir / "package.json").is_file():
                    found.append(pkg_dir)
            dirnames[:] = [d for d in dirnames if d not in DISCOVERY_SKIP_DIRS]
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


def find_package_metadata(
    roots: list[str],
    ecosystem: EcosystemPlugin,
    package: str,
) -> list[Path]:
    """Find all metadata directories for the given package."""
    found: list[Path] = []

    is_npm = ecosystem.name == "npm"

    if is_npm:
        for root in roots:
            root_path = Path(root)
            if root_path.is_dir():
                found.extend(_walk_for_node_modules(root_path, package))
    else:
        metadata_pattern = ecosystem.metadata_dir_pattern(package)
        for root in roots:
            root_path = Path(root)
            if root_path.is_dir():
                found.extend(_walk_for_metadata(root_path, metadata_pattern, package))

    return _deduplicate_by_realpath(found)
