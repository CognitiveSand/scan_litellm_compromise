"""Per-scan record of paths the scanner could not walk or read.

Walking system roots as a non-root user routinely hits inaccessible
sub-trees (``/var/lib/postgresql``, ``/opt/<vendor>``, …) and unreadable
files. Each occurrence is correct best-effort behaviour — the alternative
is a crashed scan — but in aggregate the operator should see how much
of the filesystem was actually inspected.

Each scan owns a single ``SkipReport`` instance, carried on the
``ScanContext`` and threaded explicitly through every walker / reader
helper. Paths are deduplicated so a permission-denied directory
contributes one line, not one per descendant the walker never reached.
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
        """Log at debug and record a permission-denied path."""
        logger.debug("Permission denied: %s", path)
        self.permission_errors.add(path)

    def record_read_error(self, path: Path, reason: str) -> None:
        """Log at debug and record a non-permission read error.

        First reason wins — subsequent identical paths overwrite with
        the same reason; differing reasons are rare and the first is
        usually the most informative.
        """
        logger.debug("Cannot read %s: %s", path, reason)
        self.read_errors.setdefault(path, reason)

    @property
    def is_empty(self) -> bool:
        return not (self.permission_errors or self.read_errors)

    @property
    def total(self) -> int:
        return len(self.permission_errors) + len(self.read_errors)
