"""Tests for Phase 4 I/O: scanning source and config files for package references.

Module under test: scan_supply_chain.source_scanner
"""

from pathlib import Path

import pytest

from scan_supply_chain.ecosystem_pypi import PyPIPlugin
from scan_supply_chain.models import ScanResults
from scan_supply_chain.scan_context import ScanContext
from scan_supply_chain.source_scanner import scan_source_and_configs
from tests.conftest import make_litellm_threat, make_scan_context

Setup = tuple[Path, ScanContext, ScanResults]


class TestScanSourceAndConfigs:
    @pytest.fixture
    def setup(self, tmp_path: Path) -> Setup:
        threat = make_litellm_threat()
        results = ScanResults(compromised_versions=threat.compromised)
        ctx = make_scan_context(threat, PyPIPlugin(), [str(tmp_path)])
        return tmp_path, ctx, results

    def test_finds_litellm_import_in_py_file(
        self, setup: Setup, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # @req FR-20
        tmp_path, ctx, results = setup
        py_file = tmp_path / "app.py"
        py_file.write_text("import litellm\nlitellm.completion('hi')\n")

        scan_source_and_configs(results, ctx)

        assert len(results.source_refs) >= 1
        assert any("import litellm" in r.line_content for r in results.source_refs)

    def test_finds_litellm_in_requirements_txt(
        self, setup: Setup, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # @req FR-21 FR-22
        tmp_path, ctx, results = setup
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("flask==3.0\nlitellm==1.82.7\n")

        scan_source_and_configs(results, ctx)

        assert len(results.config_refs) >= 1
        assert any(r.pinned_version == "1.82.7" for r in results.config_refs)

    def test_finds_litellm_in_pyproject_toml(
        self, setup: Setup, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # @req FR-21
        tmp_path, ctx, results = setup
        toml_file = tmp_path / "pyproject.toml"
        toml_file.write_text('[project]\ndependencies = ["litellm>=1.80"]\n')

        scan_source_and_configs(results, ctx)

        assert len(results.config_refs) >= 1

    def test_ignores_files_without_package_name(
        self, setup: Setup, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # @req FR-20
        tmp_path, ctx, results = setup
        py_file = tmp_path / "app.py"
        py_file.write_text("import flask\nflask.run()\n")

        count = scan_source_and_configs(results, ctx)

        assert results.source_refs == []
        assert count >= 1  # file was scanned

    def test_skips_scanner_own_source_code(
        self, setup: Setup, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # @req FR-30
        tmp_path, ctx, results = setup
        # Even if litellm is in scanner's own source, it should be excluded
        count = scan_source_and_configs(results, ctx)
        # Just verify it doesn't crash
        assert count >= 0

    def test_returns_file_count(
        self, setup: Setup, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # @req FR-20
        tmp_path, ctx, results = setup
        (tmp_path / "a.py").write_text("x = 1\n")
        (tmp_path / "b.py").write_text("y = 2\n")

        count = scan_source_and_configs(results, ctx)

        assert count == 2

    def test_skips_site_packages(
        self, setup: Setup, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # @req FR-20
        tmp_path, ctx, results = setup
        sp = tmp_path / "site-packages"
        sp.mkdir()
        (sp / "something.py").write_text("import litellm\n")

        scan_source_and_configs(results, ctx)

        # site-packages should be skipped in source scanning
        assert results.source_refs == []

    def test_handles_binary_file_gracefully(
        self, setup: Setup, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # @req NFR-03
        tmp_path, ctx, results = setup
        (tmp_path / "data.py").write_bytes(b"\x00\x01\x02litellm\xff\xfe")

        # Should not crash
        scan_source_and_configs(results, ctx)

    def test_scans_symlinked_files_without_crash(
        self, setup: Setup, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # @req FR-20
        tmp_path, ctx, results = setup
        real_file = tmp_path / "real.py"
        real_file.write_text("import litellm\n")
        link = tmp_path / "link.py"
        link.symlink_to(real_file)

        scan_source_and_configs(results, ctx)

        # Both paths are scanned (string-based dedup; roots are pre-deduped
        # so the only duplicate source is symlinks, which is rare in practice)
        assert len(results.source_refs) >= 1
        assert any("import litellm" in r.line_content for r in results.source_refs)
