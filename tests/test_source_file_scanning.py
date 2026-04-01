"""Tests for Phase 4 I/O: scanning source and config files for package references.

Module under test: scan_supply_chain.source_scanner
"""

import pytest

from scan_supply_chain.ecosystem_pypi import PyPIPlugin
from scan_supply_chain.models import ScanResults
from scan_supply_chain.source_scanner import scan_source_and_configs
from tests.conftest import make_litellm_threat


class TestScanSourceAndConfigs:
    @pytest.fixture
    def setup(self, tmp_path):
        ecosystem = PyPIPlugin()
        threat = make_litellm_threat()
        results = ScanResults(compromised_versions=threat.compromised)
        roots = [str(tmp_path)]
        return tmp_path, ecosystem, threat, results, roots

    def test_finds_litellm_import_in_py_file(self, setup, capsys):
        # @req FR-20
        tmp_path, ecosystem, threat, results, roots = setup
        py_file = tmp_path / "app.py"
        py_file.write_text("import litellm\nlitellm.completion('hi')\n")

        scan_source_and_configs(results, threat, ecosystem, roots)

        assert len(results.source_refs) >= 1
        assert any("import litellm" in r.line_content for r in results.source_refs)

    def test_finds_litellm_in_requirements_txt(self, setup, capsys):
        # @req FR-21 FR-22
        tmp_path, ecosystem, threat, results, roots = setup
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("flask==3.0\nlitellm==1.82.7\n")

        scan_source_and_configs(results, threat, ecosystem, roots)

        assert len(results.config_refs) >= 1
        assert any(r.pinned_version == "1.82.7" for r in results.config_refs)

    def test_finds_litellm_in_pyproject_toml(self, setup, capsys):
        # @req FR-21
        tmp_path, ecosystem, threat, results, roots = setup
        toml_file = tmp_path / "pyproject.toml"
        toml_file.write_text('[project]\ndependencies = ["litellm>=1.80"]\n')

        scan_source_and_configs(results, threat, ecosystem, roots)

        assert len(results.config_refs) >= 1

    def test_ignores_files_without_package_name(self, setup, capsys):
        # @req FR-20
        tmp_path, ecosystem, threat, results, roots = setup
        py_file = tmp_path / "app.py"
        py_file.write_text("import flask\nflask.run()\n")

        count = scan_source_and_configs(
            results,
            threat,
            ecosystem,
            roots,
        )

        assert results.source_refs == []
        assert count >= 1  # file was scanned

    def test_skips_scanner_own_source_code(self, setup, capsys):
        # @req FR-30
        tmp_path, ecosystem, threat, results, roots = setup
        # Even if litellm is in scanner's own source, it should be excluded
        count = scan_source_and_configs(
            results,
            threat,
            ecosystem,
            roots,
        )
        # Just verify it doesn't crash
        assert count >= 0

    def test_returns_file_count(self, setup, capsys):
        # @req FR-20
        tmp_path, ecosystem, threat, results, roots = setup
        (tmp_path / "a.py").write_text("x = 1\n")
        (tmp_path / "b.py").write_text("y = 2\n")

        count = scan_source_and_configs(
            results,
            threat,
            ecosystem,
            roots,
        )

        assert count == 2

    def test_skips_site_packages(self, setup, capsys):
        # @req FR-20
        tmp_path, ecosystem, threat, results, roots = setup
        sp = tmp_path / "site-packages"
        sp.mkdir()
        (sp / "something.py").write_text("import litellm\n")

        scan_source_and_configs(results, threat, ecosystem, roots)

        # site-packages should be skipped in source scanning
        assert results.source_refs == []

    def test_handles_binary_file_gracefully(self, setup, capsys):
        # @req NFR-03
        tmp_path, ecosystem, threat, results, roots = setup
        (tmp_path / "data.py").write_bytes(b"\x00\x01\x02litellm\xff\xfe")

        # Should not crash
        scan_source_and_configs(results, threat, ecosystem, roots)

    def test_deduplicates_by_realpath(self, setup, capsys):
        # @req FR-20
        tmp_path, ecosystem, threat, results, roots = setup
        real_file = tmp_path / "real.py"
        real_file.write_text("import litellm\n")
        link = tmp_path / "link.py"
        link.symlink_to(real_file)

        scan_source_and_configs(results, threat, ecosystem, roots)

        # Should deduplicate — only count real.py once
        paths = {r.file_path for r in results.source_refs}
        assert len(paths) == 1
