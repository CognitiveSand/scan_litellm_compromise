"""Platform abstraction — Strategy pattern for OS-specific behavior."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Protocol


class PlatformPolicy(Protocol):
    """OS-specific infrastructure the scanner needs.

    Threat-specific IOC paths and remediation steps are NOT here —
    they live in the ThreatProfile loaded from TOML.
    """

    @property
    def name(self) -> str:
        """Human-readable platform name (e.g. 'Linux', 'Windows')."""
        ...

    @property
    def platform_key(self) -> str:
        """Key used to select per-platform values from threat profiles.

        One of: 'linux', 'darwin', 'windows'.
        """
        ...

    @property
    def search_roots(self) -> list[str]:
        """Top-level directories to scan for Python envs and source files."""
        ...

    @property
    def conda_globs(self) -> list[str]:
        """Glob patterns for system-wide conda installations."""
        ...

    @property
    def network_check_command(self) -> list[str] | None:
        """Command to list active TCP connections, or None if unavailable."""
        ...

    @property
    def exclusion_note(self) -> str:
        """Note about excluded paths, shown at startup."""
        ...

    def home_conda_dirs(self) -> list[str]:
        """Subdirectory names under $HOME that may contain conda envs."""
        ...

    def home_pipx_dir(self) -> Path | None:
        """Path to pipx virtual envs directory, or None."""
        ...


def detect_platform() -> PlatformPolicy:
    """Return the correct PlatformPolicy for the current OS."""
    if sys.platform == "win32":
        from .platform_windows import WindowsPolicy

        return WindowsPolicy()
    elif sys.platform == "darwin":
        from .platform_darwin import DarwinPolicy

        return DarwinPolicy()
    else:
        from .platform_linux import LinuxPolicy

        return LinuxPolicy()
