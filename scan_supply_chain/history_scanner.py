"""Shell history scanner — searches for package install commands."""

from __future__ import annotations

import logging
from pathlib import Path

from .formatting import print_check_header
from .models import FindingCategory, ScanResults, track_findings

logger = logging.getLogger(__name__)

_PYPI_INSTALL_CMDS = ("pip install", "pip3 install", "uv pip install", "uv add")
_NPM_INSTALL_CMDS = ("npm install", "npm i ", "yarn add", "pnpm add", "pnpm install")


def scan_history(results: ScanResults, package: str, ecosystem: str) -> None:
    """Search shell history for install commands mentioning the package."""
    print_check_header("shell history for install commands")
    with track_findings(results, "No install commands found in shell history"):
        install_cmds = _PYPI_INSTALL_CMDS if ecosystem == "pypi" else _NPM_INSTALL_CMDS

        home = Path.home()
        for hist_name in (".bash_history", ".zsh_history"):
            hist_path = home / hist_name
            _scan_history_file(results, hist_path, package, install_cmds)


def _scan_history_file(
    results: ScanResults,
    path: Path,
    package: str,
    install_cmds: tuple[str, ...],
) -> None:
    if not path.is_file():
        return
    try:
        text = path.read_text(errors="ignore")
    except (PermissionError, OSError):
        logger.debug("Cannot read %s", path)
        return

    for line in text.splitlines():
        stripped = line.strip()
        if package not in stripped:
            continue
        if any(cmd in stripped for cmd in install_cmds):
            description = f"{path.name}: {stripped[:120]}"
            results.add_finding(FindingCategory.HISTORY, description, str(path), 1)
