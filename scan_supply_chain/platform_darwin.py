"""macOS (Darwin) platform policy — OS infrastructure only."""

from pathlib import Path


class DarwinPolicy:
    """macOS-specific paths and commands."""

    @property
    def name(self) -> str:
        return "macOS"

    @property
    def platform_key(self) -> str:
        return "darwin"

    @property
    def search_roots(self) -> list[str]:
        return ["/Users", "/opt/homebrew", "/usr/local", "/Library"]

    @property
    def conda_globs(self) -> list[str]:
        return [
            "/opt/homebrew/Caskroom/miniconda*",
            "/opt/homebrew/Caskroom/miniforge*",
            "/opt/homebrew/Caskroom/anaconda*",
        ]

    @property
    def network_check_command(self) -> list[str] | None:
        return ["lsof", "-i", "-P", "-n"]

    @property
    def exclusion_note(self) -> str:
        return "Scanning user-accessible paths (/Users, /opt/homebrew, /Library)."

    def home_conda_dirs(self) -> list[str]:
        return ["miniconda3", "miniforge3", "anaconda3", ".conda"]

    def home_pipx_dir(self) -> Path | None:
        xdg = Path.home() / ".local" / "share" / "pipx"
        if xdg.is_dir():
            return xdg
        native = Path.home() / "Library" / "Application Support" / "pipx" / "venvs"
        if native.is_dir():
            return native
        return None
