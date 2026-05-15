"""Tests for shell history scanner.

Module under test: scan_supply_chain.history_scanner
"""

from pathlib import Path

import pytest

from scan_supply_chain.history_scanner import scan_history
from scan_supply_chain.models import ScanResults


class TestScanHistory:
    def test_finds_pip_install_in_bash_history(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        # @req FR-43
        monkeypatch.setattr(
            "scan_supply_chain.history_scanner.Path.home", lambda: tmp_path
        )
        (tmp_path / ".bash_history").write_text("pip install litellm==1.82.7\nls -la\n")

        results = ScanResults()
        scan_history(results, "litellm", "pypi")

        assert len(results.findings) == 1
        assert "pip install" in results.findings[0].description

    def test_finds_npm_install_in_zsh_history(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        # @req FR-43
        monkeypatch.setattr(
            "scan_supply_chain.history_scanner.Path.home", lambda: tmp_path
        )
        (tmp_path / ".zsh_history").write_text("npm install axios\ngit status\n")

        results = ScanResults()
        scan_history(results, "axios", "npm")

        assert len(results.findings) == 1
        assert "npm install" in results.findings[0].description

    def test_finds_yarn_add(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        # @req FR-43
        monkeypatch.setattr(
            "scan_supply_chain.history_scanner.Path.home", lambda: tmp_path
        )
        (tmp_path / ".bash_history").write_text("yarn add axios\n")

        results = ScanResults()
        scan_history(results, "axios", "npm")

        assert len(results.findings) == 1

    def test_ignores_unrelated_history(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        # @req FR-43
        monkeypatch.setattr(
            "scan_supply_chain.history_scanner.Path.home", lambda: tmp_path
        )
        (tmp_path / ".bash_history").write_text("pip install flask\ngit log\n")

        results = ScanResults()
        scan_history(results, "litellm", "pypi")

        assert results.findings == []
        captured = capsys.readouterr().out
        assert "No install commands" in captured

    def test_handles_missing_history(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        # @req FR-43 NFR-03
        monkeypatch.setattr(
            "scan_supply_chain.history_scanner.Path.home", lambda: tmp_path
        )

        results = ScanResults()
        scan_history(results, "litellm", "pypi")

        assert results.findings == []

    def test_skips_pip_patterns_for_npm(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        # @req FR-43
        monkeypatch.setattr(
            "scan_supply_chain.history_scanner.Path.home", lambda: tmp_path
        )
        (tmp_path / ".bash_history").write_text("pip install axios\n")

        results = ScanResults()
        scan_history(results, "axios", "npm")

        # "pip install" is not an npm install command
        assert results.findings == []
