"""Linux platform policy — OS infrastructure only."""

from pathlib import Path


class LinuxPolicy:
    """Linux-specific paths and commands."""

    @property
    def name(self) -> str:
        return "Linux"

    @property
    def platform_key(self) -> str:
        return "linux"

    @property
    def search_roots(self) -> list[str]:
        return ["/home", "/opt", "/usr/local", "/usr/lib", "/srv", "/var"]

    @property
    def conda_globs(self) -> list[str]:
        return ["/opt/conda", "/opt/miniconda*", "/opt/miniforge*"]

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
