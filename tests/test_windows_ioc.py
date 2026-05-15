"""Tests for Windows-specific IOC checks (Registry, Scheduled Tasks).

Module under test: scan_supply_chain.ioc_windows

These tests mock subprocess calls so they run on any platform.
"""

import pytest

from scan_supply_chain.ioc_windows import (
    _check_registry_run_keys,
    _check_scheduled_tasks,
)
from scan_supply_chain.models import ScanResults
from tests.conftest import mock_run_safe


# ── Registry Run keys ────────────────────────────────────────────────


class TestRegistryRunKeys:
    def test_flags_matching_keyword(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # @req FR-28
        mock_run_safe(
            monkeypatch,
            "ioc_windows",
            "    sysmon    REG_SZ    C:\\backdoor.exe\n",
        )

        results = ScanResults()
        _check_registry_run_keys(results, ["sysmon"])

        assert any("registry:" in ioc for ioc in results.iocs)

    def test_clean_when_no_keywords_match(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # @req FR-28
        mock_run_safe(
            monkeypatch,
            "ioc_windows",
            "    OneDrive    REG_SZ    C:\\OneDrive.exe\n",
        )

        results = ScanResults()
        _check_registry_run_keys(results, ["sysmon", "litellm"])

        assert results.iocs == []
        captured = capsys.readouterr().out
        assert "No suspicious" in captured

    def test_skips_when_keywords_empty(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # @req FR-28
        results = ScanResults()
        _check_registry_run_keys(results, [])

        assert results.iocs == []

    def test_handles_timeout(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # @req FR-28 NFR-04
        mock_run_safe(monkeypatch, "ioc_windows", None)

        results = ScanResults()
        _check_registry_run_keys(results, ["sysmon"])

        assert results.iocs == []


# ── Scheduled Tasks ──────────────────────────────────────────────────


class TestScheduledTasks:
    def test_flags_matching_keyword(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # @req FR-29
        mock_run_safe(
            monkeypatch,
            "ioc_windows",
            '"sysmon_persist","Running","Ready"\n',
        )

        results = ScanResults()
        _check_scheduled_tasks(results, ["sysmon"])

        assert any("schtask:" in ioc for ioc in results.iocs)

    def test_clean_when_no_keywords_match(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # @req FR-29
        mock_run_safe(
            monkeypatch,
            "ioc_windows",
            '"GoogleUpdate","Running","Ready"\n',
        )

        results = ScanResults()
        _check_scheduled_tasks(results, ["sysmon"])

        assert results.iocs == []
        captured = capsys.readouterr().out
        assert "No suspicious" in captured

    def test_skips_when_keywords_empty(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # @req FR-29
        results = ScanResults()
        _check_scheduled_tasks(results, [])

        assert results.iocs == []

    def test_handles_timeout(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # @req FR-29 NFR-04
        mock_run_safe(monkeypatch, "ioc_windows", None)

        results = ScanResults()
        _check_scheduled_tasks(results, ["sysmon"])

        assert results.iocs == []
