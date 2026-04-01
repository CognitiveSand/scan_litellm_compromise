"""Ecosystem plugin protocol — abstracts PyPI vs npm package discovery."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Protocol


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

    def metadata_dir_pattern(self, package: str) -> re.Pattern:
        """Regex matching a metadata directory name for the given package."""
        ...

    def extract_version(self, metadata_path: Path) -> str | None:
        """Extract the package version from a metadata directory or file."""
        ...

    def import_patterns(self, package: str) -> list[re.Pattern]:
        """Regex patterns matching source-level import/usage of the package."""
        ...

    def dep_patterns(self, package: str) -> list[re.Pattern]:
        """Regex patterns matching the package in dependency/config files."""
        ...

    def pinned_version_pattern(self, package: str) -> re.Pattern:
        """Regex that captures a pinned version (e.g. pkg==1.2.3 -> '1.2.3')."""
        ...

    def config_filename_pattern(self) -> re.Pattern | None:
        """Regex for dynamic config filenames (e.g. requirements*.txt)."""
        ...

    def extra_search_roots(self) -> list[str]:
        """Ecosystem-specific directories to add to search roots."""
        ...

    def find_phantom_deps(
        self,
        names: list[str],
        search_roots: list[str],
    ) -> list[str]:
        """Check for phantom dependencies that should not exist.

        Returns list of IOC description strings for each found phantom dep.
        """
        ...


def get_ecosystem(ecosystem_name: str) -> EcosystemPlugin:
    """Factory: return the correct plugin for the ecosystem name."""
    if ecosystem_name == "pypi":
        from .ecosystem_pypi import PyPIPlugin

        return PyPIPlugin()
    if ecosystem_name == "npm":
        from .ecosystem_npm import NpmPlugin

        return NpmPlugin()
    raise ValueError(f"Unknown ecosystem: {ecosystem_name!r}")
