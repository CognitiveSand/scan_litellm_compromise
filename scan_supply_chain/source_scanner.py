"""Phase 4: Scan source files and configs for package usage."""

from __future__ import annotations

import logging
import os
import re
from pathlib import Path
from typing import TYPE_CHECKING

from .config import SOURCE_SCAN_SKIP_DIRS
from .models import ConfigReference, ScanResults, SourceReference

if TYPE_CHECKING:
    from .ecosystem_base import EcosystemPlugin
    from .threat_profile import ThreatProfile

logger = logging.getLogger(__name__)


# ── File classification ──────────────────────────────────────────────────


def _is_config_file(
    filename: str,
    extension: str,
    config_filenames: frozenset[str],
    config_extensions: frozenset[str],
    config_filename_pattern: re.Pattern | None,
) -> bool:
    """Check if a filename matches known config/dependency file patterns."""
    if filename in config_filenames:
        return True
    if config_filename_pattern and config_filename_pattern.match(filename):
        return True
    if extension in config_extensions and "require" in filename.lower():
        return True
    return False


# ── Single-file scanning ────────────────────────────────────────────────


def _scan_file_lines(
    file_path: Path,
    is_source: bool,
    results: ScanResults,
    package: str,
    import_patterns: list[re.Pattern],
    dep_patterns: list[re.Pattern],
    pinned_pattern: re.Pattern,
) -> None:
    """Scan a single file's lines for package references."""
    try:
        text = file_path.read_text(errors="ignore")
    except (PermissionError, OSError):
        return

    # Fast-path: skip files that don't mention the package at all
    if package not in text:
        return

    for line_number, line in enumerate(text.splitlines(), 1):
        if package not in line:
            continue

        stripped = line.strip()

        if is_source:
            if any(p.search(line) for p in import_patterns):
                results.source_refs.append(
                    SourceReference(str(file_path), line_number, stripped)
                )
        else:
            if any(p.search(line) for p in dep_patterns):
                match = pinned_pattern.search(line)
                results.config_refs.append(
                    ConfigReference(
                        str(file_path),
                        line_number,
                        stripped,
                        match.group(1) if match else None,
                    )
                )


# ── Public entry point ───────────────────────────────────────────────────


def scan_source_and_configs(
    results: ScanResults,
    threat: ThreatProfile,
    ecosystem: EcosystemPlugin,
    roots: list[str],
) -> int:
    """Scan source and config files for package usage.

    Returns the number of files scanned.
    """
    scan_roots = roots  # already deduplicated by build_search_roots()
    scanner_dir = str(Path(__file__).resolve().parent)
    seen_files: set[str] = set()
    files_scanned = 0

    source_exts = ecosystem.source_extensions
    config_names = ecosystem.config_filenames
    config_exts = ecosystem.config_extensions
    cfg_fn_pattern = ecosystem.config_filename_pattern()
    import_pats = ecosystem.import_patterns(threat.package)
    dep_pats = ecosystem.dep_patterns(threat.package)
    pinned_pat = ecosystem.pinned_version_pattern(threat.package)

    ext_label = ", ".join(sorted(f"*{e}" for e in source_exts))
    print(f"  Scanning {ext_label} files, config/dependency files, etc.")
    print(f"  Search roots: {', '.join(scan_roots)}\n")

    for root in scan_roots:
        root_path = Path(root)
        if not root_path.is_dir():
            continue
        try:
            for dirpath, dirnames, filenames in os.walk(root_path):
                dirnames[:] = [d for d in dirnames if d not in SOURCE_SCAN_SKIP_DIRS]
                dir_path = Path(dirpath)

                for filename in filenames:
                    file_path = dir_path / filename
                    extension = file_path.suffix.lower()
                    is_source = extension in source_exts
                    is_config = _is_config_file(
                        filename,
                        extension,
                        config_names,
                        config_exts,
                        cfg_fn_pattern,
                    )

                    if not is_source and not is_config:
                        continue

                    try:
                        resolved = str(file_path.resolve())
                    except OSError:
                        continue
                    if resolved in seen_files or resolved.startswith(scanner_dir):
                        continue
                    seen_files.add(resolved)

                    files_scanned += 1
                    _scan_file_lines(
                        file_path,
                        is_source,
                        results,
                        threat.package,
                        import_pats,
                        dep_pats,
                        pinned_pat,
                    )
        except PermissionError:
            logger.debug("Permission denied walking %s", root)

    return files_scanned
