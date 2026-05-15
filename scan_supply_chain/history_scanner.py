"""Shell history scanner — searches for package install commands."""

from __future__ import annotations

from pathlib import Path

from .config import read_if_contains
from .models import FindingCategory, ScanResults, scanner_check
from .skip_report import SkipReport

_PYPI_INSTALL_CMDS = ("pip install", "pip3 install", "uv pip install", "uv add")
_NPM_INSTALL_CMDS = ("npm install", "npm i ", "yarn add", "pnpm add", "pnpm install")


def scan_history(
    results: ScanResults,
    package: str,
    ecosystem: str,
    skip_report: SkipReport | None = None,
) -> None:
    """Search shell history for install commands mentioning the package.

    ``skip_report`` defaults to a throwaway instance to keep legacy
    unit tests calling this helper with the simple signature.
    """
    if skip_report is None:
        skip_report = SkipReport()
    with scanner_check(
        results,
        "shell history for install commands",
        "No install commands found in shell history",
    ):
        install_cmds = _PYPI_INSTALL_CMDS if ecosystem == "pypi" else _NPM_INSTALL_CMDS

        home = Path.home()
        for hist_name in (".bash_history", ".zsh_history"):
            hist_path = home / hist_name
            _scan_history_file(results, hist_path, package, install_cmds, skip_report)


def _scan_history_file(
    results: ScanResults,
    path: Path,
    package: str,
    install_cmds: tuple[str, ...],
    skip_report: SkipReport,
) -> None:
    text = read_if_contains(path, package, skip_report)
    if text is None:
        return

    for line in text.splitlines():
        stripped = line.strip()
        if package not in stripped:
            continue
        if any(cmd in stripped for cmd in install_cmds):
            description = f"{path.name}: {stripped[:120]}"
            results.add_finding(FindingCategory.HISTORY, description, str(path), 1)
