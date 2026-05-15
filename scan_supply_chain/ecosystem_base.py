"""Ecosystem plugin protocol — abstracts PyPI vs npm package discovery."""

from __future__ import annotations

import functools
import re
from pathlib import Path
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from .skip_report import SkipReport


class EcosystemPlugin(Protocol):
    """Defines how the scanner interacts with a package ecosystem.

    Two concrete implementations: PyPIPlugin (pypi) and NpmPlugin (npm).
    Selected at runtime based on the threat profile's ecosystem field.
    """

    @property
    def name(self) -> str:
        """Human-readable ecosystem name (e.g. 'PyPI', 'npm')."""
        ...

    @property
    def source_extensions(self) -> frozenset[str]:
        """File extensions for source files to scan (e.g. {'.py'})."""
        ...

    @property
    def config_filenames(self) -> frozenset[str]:
        """Config/dependency filenames to scan (e.g. {'pyproject.toml'})."""
        ...

    @property
    def config_extensions(self) -> frozenset[str]:
        """Extra extensions treated as config when name contains 'require'."""
        ...

    def metadata_dir_pattern(self, package: str) -> re.Pattern[str]:
        """Regex matching a metadata directory name for the given package."""
        ...

    def extract_version(
        self, metadata_path: Path, skip_report: "SkipReport"
    ) -> str | None:
        """Extract the package version from a metadata directory or file.

        ``skip_report`` receives any permission / read errors so the
        operator sees in the post-scan summary which install directories
        could not be inspected. JSON / METADATA parse errors are not
        skip-worthy (they indicate content issues, not access) and are
        logged at debug only.
        """
        ...

    def import_patterns(self, package: str) -> list[re.Pattern[str]]:
        """Regex patterns matching source-level import/usage of the package."""
        ...

    def dep_patterns(self, package: str) -> list[re.Pattern[str]]:
        """Regex patterns matching the package in dependency/config files."""
        ...

    def pinned_version_pattern(self, package: str) -> re.Pattern[str]:
        """Regex that captures a pinned version (e.g. pkg==1.2.3 -> '1.2.3')."""
        ...

    def config_filename_pattern(self) -> re.Pattern[str] | None:
        """Regex for dynamic config filenames (e.g. requirements*.txt)."""
        ...

    def extra_search_roots(self) -> list[str]:
        """Ecosystem-specific directories to add to search roots."""
        ...

    def find_phantom_deps(
        self,
        names: list[str],
        search_roots: list[str],
        skip_report: "SkipReport",
    ) -> list[str]:
        """Check for phantom dependencies that should not exist.

        Returns list of IOC description strings for each found phantom dep.
        ``skip_report`` is used to record any permission / read errors
        encountered while walking the dependency trees.
        """
        ...


@functools.lru_cache(maxsize=None)
def get_ecosystem(ecosystem_name: str) -> EcosystemPlugin:
    """Factory: return a cached plugin for the ecosystem name.

    Plugins are stateless — one instance per ecosystem suffices.
    For npm, this avoids re-running 'npm root -g' on each call (the
    side effect lives in ``NpmPlugin.extra_search_roots``; the plugin
    object itself is cheap to construct but cheap to cache too).
    """
    if ecosystem_name == "pypi":
        from .ecosystem_pypi import PyPIPlugin

        plugin: EcosystemPlugin = PyPIPlugin()
    elif ecosystem_name == "npm":
        from .ecosystem_npm import NpmPlugin

        plugin = NpmPlugin()
    else:
        raise ValueError(f"Unknown ecosystem: {ecosystem_name!r}")

    return plugin
