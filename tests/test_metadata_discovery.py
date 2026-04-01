"""Tests for Phase 1: discovering package installations via filesystem metadata.

Module under test: scan_supply_chain.discovery
"""

from scan_supply_chain.discovery import (
    _deduplicate_by_realpath,
    _walk_for_metadata,
    _walk_for_node_modules,
    find_package_metadata,
)
from scan_supply_chain.ecosystem_pypi import PyPIPlugin


# ── _walk_for_metadata (PyPI filesystem) ──────────────────────────────


class TestWalkForMetadata:
    def test_finds_dist_info_in_site_packages(self, tmp_path):
        # @req FR-06
        dist_info = tmp_path / "lib" / "site-packages" / "litellm-1.82.7.dist-info"
        dist_info.mkdir(parents=True)

        pattern = PyPIPlugin().metadata_dir_pattern("litellm")
        result = _walk_for_metadata(tmp_path, pattern, "litellm")

        assert len(result) == 1
        assert result[0].name == "litellm-1.82.7.dist-info"

    def test_finds_multiple_installs_in_nested_envs(self, tmp_path):
        # @req FR-06
        (tmp_path / "venv1" / "lib" / "litellm-1.82.6.dist-info").mkdir(parents=True)
        (tmp_path / "venv2" / "lib" / "litellm-1.82.7.dist-info").mkdir(parents=True)

        pattern = PyPIPlugin().metadata_dir_pattern("litellm")
        result = _walk_for_metadata(tmp_path, pattern, "litellm")

        assert len(result) == 2

    def test_skips_pycache_directories(self, tmp_path):
        # @req FR-06
        (tmp_path / "__pycache__" / "litellm-1.82.7.dist-info").mkdir(parents=True)

        pattern = PyPIPlugin().metadata_dir_pattern("litellm")
        result = _walk_for_metadata(tmp_path, pattern, "litellm")

        assert result == []

    def test_returns_empty_for_directory_without_package(self, tmp_path):
        # @req FR-06
        (tmp_path / "lib" / "site-packages" / "requests-2.31.dist-info").mkdir(
            parents=True
        )

        pattern = PyPIPlugin().metadata_dir_pattern("litellm")
        result = _walk_for_metadata(tmp_path, pattern, "litellm")

        assert result == []

    def test_finds_egg_info_directories(self, tmp_path):
        # @req FR-06
        (tmp_path / "litellm-1.80.0.egg-info").mkdir()

        pattern = PyPIPlugin().metadata_dir_pattern("litellm")
        result = _walk_for_metadata(tmp_path, pattern, "litellm")

        assert len(result) == 1
        assert result[0].name == "litellm-1.80.0.egg-info"

    def test_handles_permission_error_gracefully(self, tmp_path, monkeypatch):
        # @req FR-06 NFR-03
        def walk_that_raises(path, **kwargs):
            raise PermissionError("denied")

        monkeypatch.setattr("scan_supply_chain.discovery.os.walk", walk_that_raises)

        pattern = PyPIPlugin().metadata_dir_pattern("litellm")
        result = _walk_for_metadata(tmp_path, pattern, "litellm")

        assert result == []


# ── _walk_for_node_modules (npm filesystem) ──────────────────────────


class TestWalkForNodeModules:
    def test_finds_axios_in_node_modules(self, tmp_path):
        # @req FR-07
        pkg_dir = tmp_path / "project" / "node_modules" / "axios"
        pkg_dir.mkdir(parents=True)
        (pkg_dir / "package.json").write_text('{"version": "1.14.1"}')

        result = _walk_for_node_modules(tmp_path, "axios")

        assert len(result) == 1
        assert result[0].name == "axios"

    def test_ignores_dir_without_package_json(self, tmp_path):
        # @req FR-07
        (tmp_path / "node_modules" / "axios").mkdir(parents=True)
        # No package.json

        result = _walk_for_node_modules(tmp_path, "axios")

        assert result == []

    def test_finds_nested_node_modules(self, tmp_path):
        # @req FR-07
        pkg1 = tmp_path / "proj1" / "node_modules" / "axios"
        pkg1.mkdir(parents=True)
        (pkg1 / "package.json").write_text('{"version": "1.14.0"}')

        pkg2 = tmp_path / "proj2" / "node_modules" / "axios"
        pkg2.mkdir(parents=True)
        (pkg2 / "package.json").write_text('{"version": "1.14.1"}')

        result = _walk_for_node_modules(tmp_path, "axios")

        assert len(result) == 2


# ── _deduplicate_by_realpath ──────────────────────────────────────────


class TestDeduplicateByRealpath:
    def test_removes_symlink_duplicates(self, tmp_path):
        # @req FR-06 FR-07
        real_dir = tmp_path / "real" / "litellm-1.82.7.dist-info"
        real_dir.mkdir(parents=True)
        link_dir = tmp_path / "link"
        link_dir.symlink_to(tmp_path / "real")
        link_target = link_dir / "litellm-1.82.7.dist-info"

        result = _deduplicate_by_realpath([real_dir, link_target])

        assert len(result) == 1

    def test_keeps_distinct_paths(self, tmp_path):
        # @req FR-06 FR-07
        dir_a = tmp_path / "a" / "litellm-1.82.7.dist-info"
        dir_b = tmp_path / "b" / "litellm-1.82.8.dist-info"
        dir_a.mkdir(parents=True)
        dir_b.mkdir(parents=True)

        result = _deduplicate_by_realpath([dir_a, dir_b])

        assert len(result) == 2


# ── find_package_metadata (integration) ──────────────────────────────


class TestFindPackageMetadata:
    def test_finds_pypi_package_from_roots(self, tmp_path):
        # @req FR-06
        site_pkg = tmp_path / "lib" / "site-packages"
        (site_pkg / "litellm-1.82.7.dist-info").mkdir(parents=True)

        ecosystem = PyPIPlugin()
        result = find_package_metadata([str(tmp_path)], ecosystem, "litellm")

        assert len(result) == 1

    def test_returns_empty_when_no_package_installed(self, tmp_path):
        # @req FR-06
        (tmp_path / "lib" / "site-packages" / "flask-3.0.dist-info").mkdir(parents=True)

        ecosystem = PyPIPlugin()
        result = find_package_metadata([str(tmp_path)], ecosystem, "litellm")

        assert result == []

    def test_uses_explicit_roots(self, tmp_path):
        # @req FR-06 FR-13
        target = tmp_path / "myproject"
        (target / "venv" / "lib" / "litellm-1.82.7.dist-info").mkdir(parents=True)

        ecosystem = PyPIPlugin()
        result = find_package_metadata([str(target)], ecosystem, "litellm")

        assert len(result) == 1
