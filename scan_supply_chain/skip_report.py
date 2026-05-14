"""Per-scan record of paths the scanner could not walk or read.

Walking system roots as a non-root user routinely hits inaccessible
sub-trees (``/var/lib/postgresql``, ``/opt/<vendor>``, …) and unreadable
files. Each occurrence is correct best-effort behaviour — the alternative
is a crashed scan — but in aggregate the operator should see how much
of the filesystem was actually inspected.

This module owns a small singleton ``SkipReport`` that the walk / read
helpers (``config.pruned_walk``, ``config.read_if_contains``,
``git_repo_index._find_repo_roots``) append to whenever they swallow a
``PermissionError`` or ``OSError``. The orchestrator resets it at the
start of each scan and ``report.print_skip_summary`` renders it at the
end.

The singleton is module-level (single-threaded scanner; the test suite
resets it via an autouse fixture). Paths are deduplicated so a
permission-denied directory contributes one line, not one per
descendant the walker never reached.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class SkipReport:
    """Paths the scanner skipped because of permission or read errors."""

    permission_errors: set[Path] = field(default_factory=set)
    read_errors: dict[Path, str] = field(default_factory=dict)

    def record_permission(self, path: Path) -> None:
        self.permission_errors.add(path)

    def record_read_error(self, path: Path, reason: str) -> None:
        # First reason wins — subsequent identical paths overwrite with
        # the same reason; differing reasons are rare and the first is
        # usually the most informative.
        self.read_errors.setdefault(path, reason)

    @property
    def is_empty(self) -> bool:
        return not (self.permission_errors or self.read_errors)

    @property
    def total(self) -> int:
        return len(self.permission_errors) + len(self.read_errors)


# Module singleton — the current scan's report.
_current = SkipReport()


def get_current_report() -> SkipReport:
    return _current


def reset_current_report() -> None:
    """Replace the current report with a fresh empty one.

    Called by the orchestrator at the start of each scan, and by the
    test suite's autouse fixture between tests.
    """
    global _current
    _current = SkipReport()


def note_permission_error(path: Path) -> None:
    """Log at debug and record in the current scan's skip report."""
    logger.debug("Permission denied: %s", path)
    _current.record_permission(path)


def note_read_error(path: Path, reason: str) -> None:
    """Log at debug and record in the current scan's skip report."""
    logger.debug("Cannot read %s: %s", path, reason)
    _current.record_read_error(path, reason)
