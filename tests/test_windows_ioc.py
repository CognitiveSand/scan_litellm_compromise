"""Tests for Windows-specific IOC checks (Registry, Scheduled Tasks).

Module under test: scan_supply_chain.ioc_windows

These tests mock subprocess calls so they run on any platform.
"""

import subprocess

from scan_supply_chain.ioc_windows import (
    _check_registry_run_keys,
    _check_scheduled_tasks,
)
from scan_supply_chain.models import ScanResults


# ── Registry Run keys ────────────────────────────────────────────────


class TestRegistryRunKeys:
    def test_flags_matching_keyword(self, monkeypatch, capsys):
        # @req FR-28
        monkeypatch.setattr(
            "scan_supply_chain.ioc_windows.subprocess.run",
            lambda *a, **kw: subprocess.CompletedProcess(
                args=a[0],
                returncode=0,
                stdout="    sysmon    REG_SZ    C:\\backdoor.exe\n",
            ),
        )

        results = ScanResults()
        _check_registry_run_keys(results, ["sysmon"])

        assert any("registry:" in ioc for ioc in results.iocs)

    def test_clean_when_no_keywords_match(self, monkeypatch, capsys):
        # @req FR-28
        monkeypatch.setattr(
            "scan_supply_chain.ioc_windows.subprocess.run",
            lambda *a, **kw: subprocess.CompletedProcess(
                args=a[0],
                returncode=0,
                stdout="    OneDrive    REG_SZ    C:\\OneDrive.exe\n",
            ),
        )

        results = ScanResults()
        _check_registry_run_keys(results, ["sysmon", "litellm"])

        assert results.iocs == []
        captured = capsys.readouterr().out
        assert "No suspicious" in captured

    def test_skips_when_keywords_empty(self, capsys):
        # @req FR-28
        results = ScanResults()
        _check_registry_run_keys(results, [])

        assert results.iocs == []

    def test_handles_timeout(self, monkeypatch, capsys):
        # @req FR-28 NFR-04
        monkeypatch.setattr(
            "scan_supply_chain.ioc_windows.subprocess.run",
            lambda *a, **kw: (_ for _ in ()).throw(
                subprocess.TimeoutExpired(cmd="reg", timeout=10),
            ),
        )

        results = ScanResults()
        _check_registry_run_keys(results, ["sysmon"])

        assert results.iocs == []


# ── Scheduled Tasks ──────────────────────────────────────────────────


class TestScheduledTasks:
    def test_flags_matching_keyword(self, monkeypatch, capsys):
        # @req FR-29
        monkeypatch.setattr(
            "scan_supply_chain.ioc_windows.subprocess.run",
            lambda *a, **kw: subprocess.CompletedProcess(
                args=a[0],
                returncode=0,
                stdout='"sysmon_persist","Running","Ready"\n',
            ),
        )

        results = ScanResults()
        _check_scheduled_tasks(results, ["sysmon"])

        assert any("schtask:" in ioc for ioc in results.iocs)

    def test_clean_when_no_keywords_match(self, monkeypatch, capsys):
        # @req FR-29
        monkeypatch.setattr(
            "scan_supply_chain.ioc_windows.subprocess.run",
            lambda *a, **kw: subprocess.CompletedProcess(
                args=a[0],
                returncode=0,
                stdout='"GoogleUpdate","Running","Ready"\n',
            ),
        )

        results = ScanResults()
        _check_scheduled_tasks(results, ["sysmon"])

        assert results.iocs == []
        captured = capsys.readouterr().out
        assert "No suspicious" in captured

    def test_skips_when_keywords_empty(self, capsys):
        # @req FR-29
        results = ScanResults()
        _check_scheduled_tasks(results, [])

        assert results.iocs == []

    def test_handles_timeout(self, monkeypatch, capsys):
        # @req FR-29 NFR-04
        monkeypatch.setattr(
            "scan_supply_chain.ioc_windows.subprocess.run",
            lambda *a, **kw: (_ for _ in ()).throw(
                subprocess.TimeoutExpired(cmd="schtasks", timeout=15),
            ),
        )

        results = ScanResults()
        _check_scheduled_tasks(results, ["sysmon"])

        assert results.iocs == []
