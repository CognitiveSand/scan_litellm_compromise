"""Source/config-file reference display for per-threat reports."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from ..formatting import BOLD, GREEN, RED, RESET, YELLOW
from ..models import ConfigReference, SourceReference

_MAX_LINES_PER_FILE = 5


def _file_path_key(ref: SourceReference | ConfigReference) -> str:
    return ref.file_path


def _group_by_file(
    refs: list[SourceReference] | list[ConfigReference],
    key: Callable[[SourceReference | ConfigReference], str] | None = None,
) -> dict[str, list[Any]]:
    """Group references by file path, preserving order."""
    if key is None:
        key = _file_path_key
    grouped: dict[str, list[Any]] = {}
    for ref in refs:
        grouped.setdefault(key(ref), []).append(ref)
    return grouped


def _format_version_tag(
    ref: ConfigReference,
    compromised: frozenset[str],
) -> str:
    """Format a version annotation for a config reference."""
    if ref.pinned_version and ref.pinned_version in compromised:
        return f"  {RED}{BOLD}! PINNED TO COMPROMISED VERSION{RESET}"
    if ref.pinned_version:
        return f"  {GREEN}(v{ref.pinned_version}){RESET}"
    return ""


def print_source_refs(
    refs: list[SourceReference],
    package: str,
) -> None:
    """Print grouped source file references."""
    if not refs:
        print(f"  {GREEN}+ No {package} imports found in source files{RESET}\n")
        return

    by_file = _group_by_file(refs)
    print(
        f"  {BOLD}Source files referencing {package} ({len(by_file)} files):{RESET}\n"
    )

    for file_path, file_refs in sorted(by_file.items()):
        print(f"    {YELLOW}{file_path}{RESET}")
        for ref in file_refs[:_MAX_LINES_PER_FILE]:
            print(f"      L{ref.line_number}: {ref.line_content}")
        remaining = len(file_refs) - _MAX_LINES_PER_FILE
        if remaining > 0:
            print(f"      ... and {remaining} more references")
        print()


def print_config_refs(
    refs: list[ConfigReference],
    package: str,
    compromised: frozenset[str],
) -> None:
    """Print grouped config file references with version annotations."""
    if not refs:
        print(
            f"  {GREEN}+ No {package} dependencies found in "
            f"config/requirements files{RESET}\n"
        )
        return

    by_file = _group_by_file(refs)
    print(
        f"  {BOLD}Config/dependency files referencing {package} "
        f"({len(by_file)} files):{RESET}\n"
    )

    for file_path, file_refs in sorted(by_file.items()):
        print(f"    {YELLOW}{file_path}{RESET}")
        for ref in file_refs:
            version_tag = _format_version_tag(ref, compromised)
            print(f"      L{ref.line_number}: {ref.line_content}{version_tag}")
        print()
