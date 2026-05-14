"""Tests for the per-scan skip report.

Module under test: scan_supply_chain.skip_report
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from scan_supply_chain.config import pruned_walk, read_if_contains
from scan_supply_chain.skip_report import (
    SkipReport,
    get_current_report,
    note_permission_error,
    note_read_error,
    reset_current_report,
)


# ── SkipReport dataclass ────────────────────────────────────────────────


class TestSkipReport:
    def test_empty_by_default(self):
        report = SkipReport()
        assert report.is_empty
        assert report.total == 0

    def test_records_permission_error(self):
        report = SkipReport()
        report.record_permission(Path("/opt/locked"))
        assert not report.is_empty
        assert Path("/opt/locked") in report.permission_errors
        assert report.total == 1

    def test_records_read_error(self):
        report = SkipReport()
        report.record_read_error(Path("/var/x"), "FileNotFoundError")
        assert not report.is_empty
        assert report.read_errors[Path("/var/x")] == "FileNotFoundError"
        assert report.total == 1

    def test_deduplicates_permission_paths(self):
        report = SkipReport()
        report.record_permission(Path("/opt/locked"))
        report.record_permission(Path("/opt/locked"))
        assert len(report.permission_errors) == 1


# ── Module singleton ────────────────────────────────────────────────────


class TestSingleton:
    def test_get_returns_current_report(self):
        report = get_current_report()
        assert isinstance(report, SkipReport)
        assert report.is_empty

    def test_reset_replaces_with_fresh_report(self):
        note_permission_error(Path("/opt/locked"))
        assert not get_current_report().is_empty

        reset_current_report()

        assert get_current_report().is_empty

    def test_note_helpers_append_to_current(self):
        note_permission_error(Path("/opt/a"))
        note_read_error(Path("/opt/b"), "OSError")

        report = get_current_report()
        assert Path("/opt/a") in report.permission_errors
        assert report.read_errors[Path("/opt/b")] == "OSError"


# ── Integration with config helpers ─────────────────────────────────────


class TestPrunedWalkInstrumentation:
    @pytest.mark.skipif(
        os.geteuid() == 0, reason="root bypasses POSIX permission bits"
    )
    def test_subdirectory_permission_error_is_recorded(self, tmp_path):
        """os.walk silently skips inaccessible sub-trees unless onerror is set.

        pruned_walk wires onerror through to the skip-report so the
        post-scan summary reflects depth-N permission denials.
        """
        readable = tmp_path / "ok"
        locked = tmp_path / "locked"
        readable.mkdir()
        locked.mkdir()
        (readable / "file.txt").write_text("ok")
        locked.chmod(0o000)
        try:
            list(pruned_walk(tmp_path, frozenset()))
        finally:
            locked.chmod(0o755)  # restore for cleanup

        report = get_current_report()
        assert any("locked" in str(p) for p in report.permission_errors), (
            f"expected 'locked' in permission_errors, got {report.permission_errors}"
        )


class TestReadIfContainsInstrumentation:
    @pytest.mark.skipif(
        os.geteuid() == 0, reason="root bypasses POSIX permission bits"
    )
    def test_unreadable_file_is_recorded(self, tmp_path):
        secret = tmp_path / "secret.txt"
        secret.write_text("contains the keyword")
        secret.chmod(0o000)
        try:
            result = read_if_contains(secret, "keyword")
        finally:
            secret.chmod(0o644)  # restore for cleanup

        assert result is None
        report = get_current_report()
        assert secret in report.permission_errors

    def test_missing_file_is_not_recorded(self, tmp_path):
        """read_if_contains returns None for missing files without recording.

        The path.is_file() guard means missing files never enter the
        try/except block — no skip entry should be created.
        """
        result = read_if_contains(tmp_path / "absent.txt", "anything")

        assert result is None
        assert get_current_report().is_empty
