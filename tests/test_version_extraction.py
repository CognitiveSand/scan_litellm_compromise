"""Tests for Phase 2: extracting package versions from metadata.

Module under test: scan_supply_chain.version_checker
               and scan_supply_chain.ecosystem_pypi
               and scan_supply_chain.ecosystem_npm
"""

import json

import pytest

from scan_supply_chain.ecosystem_pypi import PyPIPlugin
from scan_supply_chain.ecosystem_npm import NpmPlugin
from scan_supply_chain.models import ScanResults
from scan_supply_chain.version_checker import scan_environments
from tests.conftest import make_litellm_threat


# ── PyPI: extract_version ─────────────────────────────────────────────


class TestPyPIExtractVersion:
    @pytest.fixture
    def plugin(self):
        return PyPIPlugin()

    def test_reads_version_from_metadata_file(self, tmp_path, plugin):
        # @req FR-08
        dist_info = tmp_path / "litellm-1.82.7.dist-info"
        dist_info.mkdir()
        (dist_info / "METADATA").write_text(
            "Metadata-Version: 2.1\nName: litellm\nVersion: 1.82.7\n"
        )
        assert plugin.extract_version(dist_info) == "1.82.7"

    def test_reads_version_from_pkg_info(self, tmp_path, plugin):
        # @req FR-08
        egg_info = tmp_path / "litellm-1.80.0.egg-info"
        egg_info.mkdir()
        (egg_info / "PKG-INFO").write_text(
            "Metadata-Version: 1.0\nName: litellm\nVersion: 1.80.0\n"
        )
        assert plugin.extract_version(egg_info) == "1.80.0"

    def test_prefers_metadata_over_pkg_info(self, tmp_path, plugin):
        # @req FR-08
        dist_info = tmp_path / "litellm-1.82.7.dist-info"
        dist_info.mkdir()
        (dist_info / "METADATA").write_text("Version: 1.82.7\n")
        (dist_info / "PKG-INFO").write_text("Version: 1.82.6\n")
        assert plugin.extract_version(dist_info) == "1.82.7"

    def test_falls_back_to_dirname_when_no_metadata(self, tmp_path, plugin):
        # @req FR-08
        dist_info = tmp_path / "litellm-1.82.7.dist-info"
        dist_info.mkdir()
        assert plugin.extract_version(dist_info) == "1.82.7"

    def test_falls_back_to_dirname_for_egg_info(self, tmp_path, plugin):
        # @req FR-08
        egg_info = tmp_path / "litellm-1.80.0.egg-info"
        egg_info.mkdir()
        assert plugin.extract_version(egg_info) == "1.80.0"

    def test_returns_none_for_unrecognized_directory(self, tmp_path, plugin):
        # @req FR-08
        unknown = tmp_path / "unknown-dir"
        unknown.mkdir()
        assert plugin.extract_version(unknown) is None

    def test_strips_whitespace_from_version(self, tmp_path, plugin):
        # @req FR-08
        dist_info = tmp_path / "litellm-1.82.7.dist-info"
        dist_info.mkdir()
        (dist_info / "METADATA").write_text("Version:  1.82.7  \n")
        assert plugin.extract_version(dist_info) == "1.82.7"

    @pytest.mark.parametrize(
        "version",
        [
            "1.82.7",
            "1.82.8",
            "0.0.1",
            "2.0.0a1",
            "1.82.7.post1",
            "1.82.7.dev0",
            "1.82.7rc1",
        ],
    )
    def test_handles_various_version_formats(self, tmp_path, plugin, version):
        # @req FR-08
        dist_info = tmp_path / f"litellm-{version}.dist-info"
        dist_info.mkdir()
        (dist_info / "METADATA").write_text(f"Version: {version}\n")
        assert plugin.extract_version(dist_info) == version


# ── npm: extract_version ──────────────────────────────────────────────


class TestNpmExtractVersion:
    @pytest.fixture
    def plugin(self):
        return NpmPlugin()

    def test_reads_version_from_package_json(self, tmp_path, plugin):
        # @req FR-09
        pkg_dir = tmp_path / "axios"
        pkg_dir.mkdir()
        (pkg_dir / "package.json").write_text(
            json.dumps({"name": "axios", "version": "1.14.1"})
        )
        assert plugin.extract_version(pkg_dir) == "1.14.1"

    def test_returns_none_when_no_package_json(self, tmp_path, plugin):
        # @req FR-09
        pkg_dir = tmp_path / "axios"
        pkg_dir.mkdir()
        assert plugin.extract_version(pkg_dir) is None

    def test_returns_none_for_invalid_json(self, tmp_path, plugin):
        # @req FR-09
        pkg_dir = tmp_path / "axios"
        pkg_dir.mkdir()
        (pkg_dir / "package.json").write_text("not json")
        assert plugin.extract_version(pkg_dir) is None

    def test_returns_none_when_version_field_missing(self, tmp_path, plugin):
        # @req FR-09
        pkg_dir = tmp_path / "axios"
        pkg_dir.mkdir()
        (pkg_dir / "package.json").write_text('{"name": "axios"}')
        assert plugin.extract_version(pkg_dir) is None


# ── scan_environments (integration) ──────────────────────────────────


class TestScanEnvironments:
    def test_reports_compromised_installation(self, tmp_path, capsys):
        # @req FR-10
        dist_info = tmp_path / "litellm-1.82.7.dist-info"
        dist_info.mkdir()
        (dist_info / "METADATA").write_text("Version: 1.82.7\n")

        threat = make_litellm_threat()
        ecosystem = PyPIPlugin()
        results = ScanResults(compromised_versions=threat.compromised)
        scan_environments([dist_info], results, ecosystem, threat)

        assert len(results.installations) == 1
        assert results.installations[0].version == "1.82.7"
        captured = capsys.readouterr().out
        assert "COMPROMISED" in captured

    def test_reports_safe_installation(self, tmp_path, capsys):
        # @req FR-10
        dist_info = tmp_path / "litellm-1.82.6.dist-info"
        dist_info.mkdir()
        (dist_info / "METADATA").write_text("Version: 1.82.6\n")

        threat = make_litellm_threat()
        ecosystem = PyPIPlugin()
        results = ScanResults(compromised_versions=threat.compromised)
        scan_environments([dist_info], results, ecosystem, threat)

        assert len(results.installations) == 1
        captured = capsys.readouterr().out
        assert "clean" in captured

    def test_reports_no_installations_found(self, capsys):
        # @req FR-10
        threat = make_litellm_threat()
        ecosystem = PyPIPlugin()
        results = ScanResults(compromised_versions=threat.compromised)
        scan_environments([], results, ecosystem, threat)

        assert results.installations == []
        captured = capsys.readouterr().out
        assert "No litellm installations found" in captured
