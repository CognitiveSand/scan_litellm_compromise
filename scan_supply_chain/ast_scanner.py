"""AST-based Python import detection with regex fallback.

Uses ast.parse() to find real imports, from-imports, and attribute
access (pkg.method). Eliminates false positives from string literals,
regex patterns, and comments that mention the package name.

Returns None on SyntaxError — the caller falls back to regex grep.
"""

from __future__ import annotations

import ast
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .models import SourceReference


def scan_python_imports(
    source: str,
    lines: list[str],
    package: str,
    file_path: str,
) -> list[SourceReference] | None:
    """Detect real imports and usage of a package via AST.

    Returns a list of SourceReference objects, or None if parsing
    failed (caller should fall back to regex).
    """
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return None

    refs: list = []

    for node in ast.walk(tree):
        lineno = getattr(node, "lineno", 0)

        # import litellm / import litellm.utils
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == package or alias.name.startswith(f"{package}."):
                    refs.append(_ref(file_path, lineno, lines))

        # from litellm import X / from litellm.utils import Y
        elif isinstance(node, ast.ImportFrom) and node.module:
            if node.module == package or node.module.startswith(f"{package}."):
                refs.append(_ref(file_path, lineno, lines))

        # litellm.completion() / litellm.verbose = True
        elif isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            if node.value.id == package:
                refs.append(_ref(file_path, lineno, lines))

    return _deduplicate(refs)


def _ref(file_path: str, lineno: int, lines: list[str]) -> SourceReference:
    from .models import SourceReference

    content = lines[lineno - 1].strip() if 0 < lineno <= len(lines) else ""
    return SourceReference(file_path, lineno, content)


def _deduplicate(refs: list[SourceReference]) -> list[SourceReference]:
    """Remove duplicate references to the same line."""
    seen: set[int] = set()
    unique: list[SourceReference] = []
    for ref in refs:
        if ref.line_number not in seen:
            seen.add(ref.line_number)
            unique.append(ref)
    return unique
