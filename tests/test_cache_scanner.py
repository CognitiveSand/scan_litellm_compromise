"""Tests for package cache scanner.

Module under test: scan_supply_chain.cache_scanner
"""

from pathlib import Path
import pytest

from scan_supply_chain.cache_scanner import (
    _scan_npm_cache,
    _scan_pip_cache,
    _scan_pnpm_store,
    scan_caches,
)
from scan_supply_chain.models import ScanResults
from scan_supply_chain.skip_report import SkipReport


class TestScanPipCache:
    def test_finds_package_in_pip_cache(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # @req FR-42
        monkeypatch.setattr(
            "scan_supply_chain.cache_scanner._pip_cache_dir", lambda: tmp_path
        )
        (tmp_path / "wheels" / "litellm-1.82.7.whl").mkdir(parents=True)

        results = ScanResults()
        _scan_pip_cache(results, "litellm", SkipReport())

        assert len(results.findings) == 1
        assert "pip cache" in results.findings[0].description

    def test_clean_when_no_match(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # @req FR-42
        monkeypatch.setattr(
            "scan_supply_chain.cache_scanner._pip_cache_dir", lambda: tmp_path
        )
        (tmp_path / "wheels" / "flask-3.0.whl").mkdir(parents=True)

        results = ScanResults()
        _scan_pip_cache(results, "litellm", SkipReport())

        assert results.findings == []

    def test_handles_missing_cache(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # @req FR-42 NFR-03
        monkeypatch.setattr(
            "scan_supply_chain.cache_scanner._pip_cache_dir",
            lambda: tmp_path / "nonexistent",
        )

        results = ScanResults()
        _scan_pip_cache(results, "litellm", SkipReport())

        assert results.findings == []


class TestScanNpmCache:
    def test_finds_package_in_npm_cache(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # @req FR-42
        monkeypatch.setattr(
            "scan_supply_chain.cache_scanner.Path.home", lambda: tmp_path
        )
        cacache = tmp_path / ".npm" / "_cacache" / "content-v2"
        cacache.mkdir(parents=True)
        (cacache / "axios-1.14.1.tgz").write_text("")

        results = ScanResults()
        _scan_npm_cache(results, "axios", SkipReport())

        assert len(results.findings) == 1
        assert "npm cache" in results.findings[0].description

    def test_clean_when_no_match(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # @req FR-42
        monkeypatch.setattr(
            "scan_supply_chain.cache_scanner.Path.home", lambda: tmp_path
        )
        cacache = tmp_path / ".npm" / "_cacache"
        cacache.mkdir(parents=True)
        (cacache / "lodash-4.17.tgz").write_text("")

        results = ScanResults()
        _scan_npm_cache(results, "axios", SkipReport())

        assert results.findings == []


class TestScanPnpmStore:
    def test_finds_package_in_pnpm_store(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # @req FR-42
        monkeypatch.setattr(
            "scan_supply_chain.cache_scanner.Path.home", lambda: tmp_path
        )
        store = tmp_path / ".local" / "share" / "pnpm" / "store" / "v3"
        (store / "plain-crypto-js").mkdir(parents=True)

        results = ScanResults()
        _scan_pnpm_store(results, "plain-crypto-js", SkipReport())

        assert len(results.findings) == 1
        assert "pnpm store" in results.findings[0].description


class TestScanCachesIntegration:
    def test_skips_npm_for_pypi(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        # @req FR-42
        monkeypatch.setattr(
            "scan_supply_chain.cache_scanner._pip_cache_dir",
            lambda: tmp_path / "nonexistent",
        )

        results = ScanResults()
        scan_caches(results, "litellm", "pypi")

        captured = capsys.readouterr().out
        assert "No cache traces" in captured

    def test_skips_pip_for_npm(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        # @req FR-42
        monkeypatch.setattr(
            "scan_supply_chain.cache_scanner.Path.home", lambda: tmp_path
        )

        results = ScanResults()
        scan_caches(results, "axios", "npm")

        captured = capsys.readouterr().out
        assert "No cache traces" in captured
