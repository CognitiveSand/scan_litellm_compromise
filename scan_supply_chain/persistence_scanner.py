"""Generic persistence location scanner.

Checks common persistence mechanisms that any supply chain attack
might abuse, independent of the specific threat profile.

Most checkers filter by a list of search terms — typically the target
package name plus any profile-supplied persistence keywords (e.g. names
of standalone daemons that the payload installs but that don't carry
the package name itself). The /tmp Python check is an exception: it
remains anchored to the package name because it relies on AST import
matching, which has no meaning for arbitrary keywords.
"""

from __future__ import annotations

import logging
import shutil
import sys
from collections.abc import Sequence
from pathlib import Path

from .config import read_if_contains
from .models import FindingCategory, ScanResults, scanner_check
from .skip_report import SkipReport
from .subprocess_utils import run_safe

logger = logging.getLogger(__name__)


def scan_persistence(
    results: ScanResults,
    package: str,
    extra_keywords: Sequence[str] = (),
    skip_report: SkipReport | None = None,
) -> None:
    """Scan common persistence locations for package or keyword references.

    ``skip_report`` is recorded into for any permission or read errors
    that abort a sub-check. A ``None`` default is accepted so legacy
    unit tests need not construct one; in that case a throwaway report
    is used. The orchestrator always passes the shared scan report.
    """
    if skip_report is None:
        skip_report = SkipReport()
    search_terms: list[str] = [package, *extra_keywords]
    with scanner_check(
        results, "generic persistence locations", "No suspicious persistence found"
    ):
        _check_crontab(results, search_terms)
        _check_shell_rc(results, search_terms, skip_report)
        _check_tmp_scripts(results, package, skip_report)

        if sys.platform == "linux":
            _check_config_dir(
                results,
                Path.home() / ".config" / "systemd" / "user",
                "*.service",
                "systemd user service",
                search_terms,
                skip_report,
            )
            _check_config_dir(
                results,
                Path.home() / ".config" / "autostart",
                "*.desktop",
                "XDG autostart",
                search_terms,
                skip_report,
            )
        elif sys.platform == "darwin":
            _check_config_dir(
                results,
                Path.home() / "Library" / "LaunchAgents",
                "*.plist",
                "LaunchAgent",
                search_terms,
                skip_report,
            )


# ── Helpers ─────────────────────────────────────────────────────────────


def _matched_term(text: str, terms: Sequence[str]) -> str | None:
    """Return the first search term present in `text`, or None."""
    for term in terms:
        if term and term in text:
            return term
    return None


def _check_config_dir(
    results: ScanResults,
    directory: Path,
    glob_pattern: str,
    label: str,
    search_terms: Sequence[str],
    skip_report: SkipReport,
) -> None:
    """Glob a config directory for files mentioning any search term.

    Errors are attributed to the file that produced them, not to the
    parent directory: a per-file try/except wraps each ``read_text``,
    and the glob enumeration is wrapped separately so a permission
    denial on ``directory`` itself is still recorded against that
    directory.
    """
    if not directory.is_dir():
        return
    try:
        config_files = list(directory.glob(glob_pattern))
    except PermissionError:
        skip_report.record_permission(directory)
        return
    except OSError as exc:
        skip_report.record_read_error(directory, type(exc).__name__)
        return

    for config_file in config_files:
        try:
            text = config_file.read_text(errors="ignore")
        except PermissionError:
            skip_report.record_permission(config_file)
            continue
        except OSError as exc:
            skip_report.record_read_error(config_file, type(exc).__name__)
            continue
        matched = _matched_term(text, search_terms)
        if matched is not None:
            results.add_finding(
                FindingCategory.PERSISTENCE,
                f"{label}: {config_file.name} mentions {matched}",
                str(config_file),
                2,
            )


# ── Individual checkers ─────────────────────────────────────────────────


def _check_crontab(results: ScanResults, search_terms: Sequence[str]) -> None:
    if not shutil.which("crontab"):
        return
    output = run_safe(["crontab", "-l"])
    if output is None:
        return
    for line in output.splitlines():
        if line.strip().startswith("#"):
            continue
        matched = _matched_term(line, search_terms)
        if matched is not None:
            results.add_finding(
                FindingCategory.PERSISTENCE,
                f"crontab: {line.strip()}",
                "crontab -l",
                2,
            )


def _check_shell_rc(
    results: ScanResults,
    search_terms: Sequence[str],
    skip_report: SkipReport,
) -> None:
    home = Path.home()
    for rc_name in (".bashrc", ".zshrc", ".profile", ".bash_profile"):
        rc_path = home / rc_name
        if not rc_path.is_file():
            continue
        try:
            text = rc_path.read_text(errors="ignore")
            for i, line in enumerate(text.splitlines(), 1):
                if line.strip().startswith("#"):
                    continue
                matched = _matched_term(line, search_terms)
                if matched is not None:
                    results.add_finding(
                        FindingCategory.PERSISTENCE,
                        f"{rc_name}:{i} mentions {matched}",
                        str(rc_path),
                        2,
                    )
        except PermissionError:
            skip_report.record_permission(rc_path)
        except OSError as exc:
            skip_report.record_read_error(rc_path, type(exc).__name__)


def _check_tmp_scripts(
    results: ScanResults, package: str, skip_report: SkipReport | None = None
) -> None:
    """Check /tmp for scripts that actually import the package.

    Stays anchored to the package name — AST import matching has no
    meaning for arbitrary keywords. ``skip_report`` defaults to a
    throwaway instance to keep legacy unit tests calling this helper
    directly with the simple signature.
    """
    if skip_report is None:
        skip_report = SkipReport()
    tmp = Path("/tmp") if sys.platform != "win32" else None
    if tmp is None or not tmp.is_dir():
        return
    try:
        for f in tmp.iterdir():
            if not f.is_file():
                continue
            if f.suffix == ".py":
                _check_tmp_python_file(results, f, package, skip_report)
            elif f.suffix in (".sh", ".bash"):
                _check_tmp_shell_file(results, f, package, skip_report)
    except PermissionError:
        skip_report.record_permission(tmp)
    except OSError as exc:
        skip_report.record_read_error(tmp, type(exc).__name__)


def _check_tmp_python_file(
    results: ScanResults, path: Path, package: str, skip_report: SkipReport
) -> None:
    """Flag a /tmp .py file only if it actually imports the package."""
    text = read_if_contains(path, package, skip_report)
    if text is None:
        return

    from .ast_scanner import scan_python_imports

    lines = text.splitlines()
    ast_refs = scan_python_imports(text, lines, package, str(path))

    if ast_refs is not None:
        # AST parsed successfully — trust its result
        if ast_refs:
            results.add_finding(
                FindingCategory.PERSISTENCE,
                f"/tmp script: {path.name}",
                str(path),
                2,
            )
    else:
        # SyntaxError fallback — check non-comment lines
        if _has_active_reference(text, package):
            results.add_finding(
                FindingCategory.PERSISTENCE,
                f"/tmp script: {path.name}",
                str(path),
                2,
            )


def _check_tmp_shell_file(
    results: ScanResults, path: Path, package: str, skip_report: SkipReport
) -> None:
    """Flag a /tmp shell script only if it references the package."""
    text = read_if_contains(path, package, skip_report)
    if text is not None and _has_active_reference(text, package):
        results.add_finding(
            FindingCategory.PERSISTENCE,
            f"/tmp script: {path.name}",
            str(path),
            2,
        )


def _has_active_reference(text: str, package: str) -> bool:
    """Check if any non-comment line contains the package name."""
    return any(
        package in line and not line.strip().startswith("#")
        for line in text.splitlines()
    )
