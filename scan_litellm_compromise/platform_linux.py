"""Linux platform policy — extracts existing Linux-specific constants."""

import os
from pathlib import Path


class LinuxPolicy:
    """All Linux-specific paths, commands, and behavior."""

    @property
    def name(self) -> str:
        return "Linux"

    @property
    def search_roots(self) -> list[str]:
        # NOTE: /root is intentionally excluded.
        return ["/home", "/opt", "/usr/local", "/usr/lib", "/srv", "/var"]

    @property
    def conda_globs(self) -> list[str]:
        return ["/opt/conda", "/opt/miniconda*", "/opt/miniforge*"]

    @property
    def persistence_paths(self) -> list[str]:
        # NOTE: /root sysmon paths excluded.
        return [
            "~/.config/sysmon/sysmon.py",
            "~/.config/systemd/user/sysmon.service",
        ]

    @property
    def persistence_description(self) -> str:
        return "sysmon persistence (systemd backdoor)"

    @property
    def tmp_iocs(self) -> list[str]:
        return ["/tmp/pglog", "/tmp/.pg_state", "/tmp/tpcp.tar.gz"]

    @property
    def tmp_description(self) -> str:
        return "exfiltration artifacts (/tmp)"

    @property
    def pth_search_roots(self) -> list[str]:
        # NOTE: /root is intentionally excluded.
        return ["/home", "/opt", "/usr", "/var", "/srv"]

    @property
    def network_check_command(self) -> list[str] | None:
        return ["ss", "-tnp"]

    @property
    def exclusion_note(self) -> str:
        return "/root is excluded -- this scanner only inspects user-accessible paths."

    def home_conda_dirs(self) -> list[str]:
        return ["miniconda3", "miniforge3", "anaconda3", ".conda"]

    def home_pipx_dir(self) -> Path | None:
        candidate = Path.home() / ".local" / "share" / "pipx"
        return candidate if candidate.is_dir() else None

    def extra_ioc_checks(self, results: object) -> None:
        pass  # No extra checks on Linux beyond the common ones.

    def remediation_persistence_steps(self) -> list[str]:
        return [
            "Check systemd for persistence:",
            "  -> systemctl --user list-units | grep sysmon",
            "  -> systemctl list-units | grep sysmon",
        ]

    def remediation_artifact_lines(self) -> list[str]:
        return [
            "-> Delete any litellm_init.pth files from site-packages/",
            "-> Remove ~/.config/sysmon/ and sysmon.service",
            "-> Remove /tmp/pglog, /tmp/.pg_state, /tmp/tpcp.tar.gz",
        ]
