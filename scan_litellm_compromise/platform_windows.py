"""Windows 10/11 platform policy."""

import os
import shutil
from pathlib import Path


class WindowsPolicy:
    """All Windows-specific paths, commands, and behavior."""

    @property
    def name(self) -> str:
        return "Windows"

    @property
    def search_roots(self) -> list[str]:
        roots = []
        for env_var in ("USERPROFILE", "APPDATA", "LOCALAPPDATA"):
            val = os.environ.get(env_var)
            if val and Path(val).is_dir():
                roots.append(val)
        for pf_var in ("ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"):
            val = os.environ.get(pf_var)
            if val and Path(val).is_dir():
                roots.append(val)
        return roots

    @property
    def conda_globs(self) -> list[str]:
        globs = []
        for env_var in ("USERPROFILE", "LOCALAPPDATA", "ProgramData"):
            base = os.environ.get(env_var)
            if base:
                for name in ("Miniconda3", "Miniforge3", "Anaconda3"):
                    globs.append(str(Path(base) / name))
        return globs

    @property
    def persistence_paths(self) -> list[str]:
        paths = []
        appdata = os.environ.get("APPDATA", "")
        localappdata = os.environ.get("LOCALAPPDATA", "")
        if appdata:
            paths.append(str(Path(appdata) / "sysmon" / "sysmon.py"))
            startup = (
                Path(appdata)
                / "Microsoft" / "Windows" / "Start Menu"
                / "Programs" / "Startup" / "sysmon.py"
            )
            paths.append(str(startup))
        if localappdata:
            paths.append(str(Path(localappdata) / "sysmon" / "sysmon.py"))
        temp = os.environ.get("TEMP", os.environ.get("TMP", ""))
        if temp:
            paths.append(str(Path(temp) / "sysmon.py"))
        return paths

    @property
    def persistence_description(self) -> str:
        return "sysmon persistence (Startup folder / AppData backdoor)"

    @property
    def tmp_iocs(self) -> list[str]:
        temp = os.environ.get("TEMP", os.environ.get("TMP", ""))
        if not temp:
            return []
        base = Path(temp)
        return [
            str(base / "pglog"),
            str(base / ".pg_state"),
            str(base / "tpcp.tar.gz"),
        ]

    @property
    def tmp_description(self) -> str:
        temp = os.environ.get("TEMP", "%TEMP%")
        return f"exfiltration artifacts ({temp})"

    @property
    def pth_search_roots(self) -> list[str]:
        roots = []
        for env_var in (
            "USERPROFILE", "APPDATA", "LOCALAPPDATA",
            "ProgramFiles", "ProgramFiles(x86)",
        ):
            val = os.environ.get(env_var)
            if val and Path(val).is_dir():
                roots.append(val)
        return roots

    @property
    def network_check_command(self) -> list[str] | None:
        if shutil.which("netstat"):
            return ["netstat", "-ano"]
        return None

    @property
    def exclusion_note(self) -> str:
        return (
            "Scanning user-accessible paths "
            "(%USERPROFILE%, %APPDATA%, Program Files)."
        )

    def home_conda_dirs(self) -> list[str]:
        return ["Miniconda3", "Miniforge3", "Anaconda3", ".conda"]

    def home_pipx_dir(self) -> Path | None:
        localappdata = os.environ.get("LOCALAPPDATA", "")
        if localappdata:
            candidate = Path(localappdata) / "pipx" / "venvs"
            if candidate.is_dir():
                return candidate
        return None

    def extra_ioc_checks(self, results: object) -> None:
        from .ioc_windows import run_windows_ioc_checks
        run_windows_ioc_checks(results)

    def remediation_persistence_steps(self) -> list[str]:
        return [
            "Check Windows persistence mechanisms:",
            "  -> schtasks /query | findstr sysmon",
            "  -> Check Startup folder: %APPDATA%\\Microsoft\\Windows\\"
            "Start Menu\\Programs\\Startup\\",
            "  -> Check Registry Run keys:",
            "     reg query HKCU\\Software\\Microsoft\\Windows\\"
            "CurrentVersion\\Run",
            "     reg query HKLM\\Software\\Microsoft\\Windows\\"
            "CurrentVersion\\Run",
            "  -> Check %APPDATA%\\sysmon\\ and %LOCALAPPDATA%\\sysmon\\",
        ]

    def remediation_artifact_lines(self) -> list[str]:
        return [
            "-> Delete any litellm_init.pth files from site-packages/",
            "-> Remove sysmon.py from %APPDATA%, %LOCALAPPDATA%, and Startup folder",
            "-> Remove pglog, .pg_state, tpcp.tar.gz from %TEMP%",
        ]
