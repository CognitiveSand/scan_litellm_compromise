"""Tests for the per-scan skip report.

Module under test: scan_supply_chain.skip_report
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from scan_supply_chain.config import pruned_walk, read_if_contains
from scan_supply_chain.skip_report import SkipReport

# POSIX permission bits don't bite on Windows (NTFS ACLs ignore chmod) or
# under root (uid 0 bypasses the check). Either case makes the chmod-based
# tests below vacuous, so skip them. Evaluated at import time, so guard the
# geteuid lookup — it does not exist on Windows.
_POSIX_PERMS_INEFFECTIVE = not hasattr(os, "geteuid") or os.geteuid() == 0
_POSIX_PERMS_REASON = "POSIX permission bits ineffective (Windows or root)"


# ── SkipReport dataclass ────────────────────────────────────────────────


class TestSkipReport:
    def test_empty_by_default(self) -> None:
        report = SkipReport()
        assert report.is_empty
        assert report.total == 0

    def test_records_permission_error(self) -> None:
        report = SkipReport()
        report.record_permission(Path("/opt/locked"))
        assert not report.is_empty
        assert Path("/opt/locked") in report.permission_errors
        assert report.total == 1

    def test_records_read_error(self) -> None:
        report = SkipReport()
        report.record_read_error(Path("/var/x"), "FileNotFoundError")
        assert not report.is_empty
        assert report.read_errors[Path("/var/x")] == "FileNotFoundError"
        assert report.total == 1

    def test_deduplicates_permission_paths(self) -> None:
        report = SkipReport()
        report.record_permission(Path("/opt/locked"))
        report.record_permission(Path("/opt/locked"))
        assert len(report.permission_errors) == 1


# ── Integration with config helpers ─────────────────────────────────────


class TestPrunedWalkInstrumentation:
    @pytest.mark.skipif(_POSIX_PERMS_INEFFECTIVE, reason=_POSIX_PERMS_REASON)
    def test_subdirectory_permission_error_is_recorded(self, tmp_path: Path) -> None:
        """os.walk silently skips inaccessible sub-trees unless onerror is set.

        pruned_walk wires onerror through to the caller-supplied
        SkipReport so the post-scan summary reflects depth-N permission
        denials.
        """
        readable = tmp_path / "ok"
        locked = tmp_path / "locked"
        readable.mkdir()
        locked.mkdir()
        (readable / "file.txt").write_text("ok")
        locked.chmod(0o000)
        report = SkipReport()
        try:
            list(pruned_walk(tmp_path, frozenset(), report))
        finally:
            locked.chmod(0o755)  # restore for cleanup

        assert any("locked" in str(p) for p in report.permission_errors), (
            f"expected 'locked' in permission_errors, got {report.permission_errors}"
        )


class TestReadIfContainsInstrumentation:
    @pytest.mark.skipif(_POSIX_PERMS_INEFFECTIVE, reason=_POSIX_PERMS_REASON)
    def test_unreadable_file_is_recorded(self, tmp_path: Path) -> None:
        secret = tmp_path / "secret.txt"
        secret.write_text("contains the keyword")
        secret.chmod(0o000)
        report = SkipReport()
        try:
            result = read_if_contains(secret, "keyword", report)
        finally:
            secret.chmod(0o644)  # restore for cleanup

        assert result is None
        assert secret in report.permission_errors

    def test_missing_file_is_not_recorded(self, tmp_path: Path) -> None:
        """read_if_contains returns None for missing files without recording.

        The path.is_file() guard means missing files never enter the
        try/except block — no skip entry should be created.
        """
        report = SkipReport()
        result = read_if_contains(tmp_path / "absent.txt", "anything", report)

        assert result is None
        assert report.is_empty
