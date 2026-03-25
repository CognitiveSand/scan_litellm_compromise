"""Platform abstraction — Strategy pattern for OS-specific behavior."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Protocol


class PlatformPolicy(Protocol):
    """Defines what the scanner needs from the OS.

    Two concrete implementations exist: LinuxPolicy and WindowsPolicy.
    The orchestrator constructs one at startup and passes it down.
    """

    @property
    def name(self) -> str:
        """Human-readable platform name (e.g. 'Linux', 'Windows')."""
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
    def persistence_paths(self) -> list[str]:
        """Paths where the sysmon backdoor may be installed."""
        ...

    @property
    def persistence_description(self) -> str:
        """Label for the persistence mechanism (e.g. 'systemd backdoor')."""
        ...

    @property
    def tmp_iocs(self) -> list[str]:
        """Paths to temporary exfiltration artifacts."""
        ...

    @property
    def tmp_description(self) -> str:
        """Label for the temp artifacts location."""
        ...

    @property
    def pth_search_roots(self) -> list[str]:
        """Directories to walk when searching for litellm_init.pth."""
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

    def extra_ioc_checks(self, results: object) -> None:
        """Run platform-specific IOC checks beyond the common ones."""
        ...

    def remediation_persistence_steps(self) -> list[str]:
        """Platform-specific steps to check/remove persistence mechanisms."""
        ...

    def remediation_artifact_lines(self) -> list[str]:
        """Platform-specific lines describing which artifacts to remove."""
        ...


def detect_platform() -> PlatformPolicy:
    """Return the correct PlatformPolicy for the current OS."""
    if sys.platform == "win32":
        from .platform_windows import WindowsPolicy
        return WindowsPolicy()
    else:
        from .platform_linux import LinuxPolicy
        return LinuxPolicy()
