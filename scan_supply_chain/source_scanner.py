"""Phase 4: Scan source files and configs for package usage."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from .config import SOURCE_SCAN_SKIP_DIRS, pruned_walk
from .models import ConfigReference, ScanResults, SourceReference

if TYPE_CHECKING:
    from .ecosystem_base import EcosystemPlugin
    from .scan_context import ScanContext

logger = logging.getLogger(__name__)


# ── Compiled patterns for one source-scan run ───────────────────────────


@dataclass(frozen=True)
class _SourcePatterns:
    """Regex patterns for one package, pre-compiled per scan.

    Collapses the (package, import_patterns, dep_patterns,
    pinned_pattern) data clump previously passed as four arguments to
    every line-scanning call.
    """

    package: str
    imports: list[re.Pattern[str]]
    deps: list[re.Pattern[str]]
    pinned: re.Pattern[str]

    @classmethod
    def from_ecosystem(
        cls, ecosystem: EcosystemPlugin, package: str
    ) -> "_SourcePatterns":
        return cls(
            package=package,
            imports=ecosystem.import_patterns(package),
            deps=ecosystem.dep_patterns(package),
            pinned=ecosystem.pinned_version_pattern(package),
        )


@dataclass(frozen=True)
class _FileSelector:
    """Pre-built filename / extension classifiers for one ecosystem."""

    source_extensions: frozenset[str]
    config_filenames: frozenset[str]
    config_extensions: frozenset[str]
    config_filename_pattern: re.Pattern[str] | None

    @classmethod
    def from_ecosystem(cls, ecosystem: EcosystemPlugin) -> "_FileSelector":
        return cls(
            source_extensions=ecosystem.source_extensions,
            config_filenames=ecosystem.config_filenames,
            config_extensions=ecosystem.config_extensions,
            config_filename_pattern=ecosystem.config_filename_pattern(),
        )

    def classify(self, filename: str, extension: str) -> tuple[bool, bool]:
        """Return (is_source, is_config) for a filename + lowered extension."""
        is_source = extension in self.source_extensions
        is_config = self._is_config_file(filename, extension)
        return is_source, is_config

    def _is_config_file(self, filename: str, extension: str) -> bool:
        if filename in self.config_filenames:
            return True
        if self.config_filename_pattern and self.config_filename_pattern.match(
            filename
        ):
            return True
        if extension in self.config_extensions and "require" in filename.lower():
            return True
        return False


# ── Single-file scanning ────────────────────────────────────────────────


def _scan_file_lines(
    file_path: Path,
    is_source: bool,
    results: ScanResults,
    patterns: _SourcePatterns,
) -> None:
    """Scan a single file's lines for package references."""
    try:
        text = file_path.read_text(errors="ignore")
    except (PermissionError, OSError):
        return

    # Fast-path: skip files that don't mention the package at all
    if patterns.package not in text:
        return

    # For Python files, use AST for precise import detection.
    # Falls back to regex on SyntaxError.
    if is_source and file_path.suffix == ".py":
        from .ast_scanner import scan_python_imports

        lines = text.splitlines()
        ast_refs = scan_python_imports(text, lines, patterns.package, str(file_path))
        if ast_refs is not None:
            results.source_refs.extend(ast_refs)
            return

    # Regex path: used for non-Python source files (.js, .ts, etc.)
    # and as fallback when AST parsing fails.
    for line_number, line in enumerate(text.splitlines(), 1):
        if patterns.package not in line:
            continue

        stripped = line.strip()

        if is_source:
            if any(p.search(line) for p in patterns.imports):
                results.source_refs.append(
                    SourceReference(str(file_path), line_number, stripped)
                )
        else:
            if any(p.search(line) for p in patterns.deps):
                match = patterns.pinned.search(line)
                results.config_refs.append(
                    ConfigReference(
                        str(file_path),
                        line_number,
                        stripped,
                        match.group(1) if match else None,
                    )
                )


# ── Public entry point ───────────────────────────────────────────────────


def _print_scan_header(selector: _FileSelector, scan_roots: list[str]) -> None:
    ext_label = ", ".join(sorted(f"*{e}" for e in selector.source_extensions))
    print(f"  Scanning {ext_label} files, config/dependency files, etc.")
    print(f"  Search roots: {', '.join(scan_roots)}\n")


def _walk_and_scan_files(
    results: ScanResults,
    ctx: ScanContext,
    selector: _FileSelector,
    patterns: _SourcePatterns,
) -> int:
    """Walk ctx.roots, dispatch each source/config file to _scan_file_lines."""
    scanner_dir = str(Path(__file__).resolve().parent)
    seen_files: set[str] = set()
    files_scanned = 0

    for root in ctx.roots:
        root_path = Path(root)
        if not root_path.is_dir():
            continue
        for dirpath, _, filenames in pruned_walk(
            root_path, SOURCE_SCAN_SKIP_DIRS, ctx.skip_report
        ):
            dir_path = Path(dirpath)
            for filename in filenames:
                file_path = dir_path / filename
                extension = file_path.suffix.lower()
                is_source, is_config = selector.classify(filename, extension)
                if not is_source and not is_config:
                    continue

                file_str = str(file_path)
                if file_str in seen_files or file_str.startswith(scanner_dir):
                    continue
                seen_files.add(file_str)

                files_scanned += 1
                _scan_file_lines(file_path, is_source, results, patterns)

    return files_scanned


def scan_source_and_configs(results: ScanResults, ctx: ScanContext) -> int:
    """Scan source and config files for package usage.

    Returns the number of files scanned.
    """
    selector = _FileSelector.from_ecosystem(ctx.ecosystem)
    patterns = _SourcePatterns.from_ecosystem(ctx.ecosystem, ctx.threat.package)
    _print_scan_header(selector, ctx.roots)
    return _walk_and_scan_files(results, ctx, selector, patterns)
