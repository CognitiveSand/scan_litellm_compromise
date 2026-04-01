"""Tests for packaging and backward compatibility.

Verifies pyproject.toml entry points and version consistency.
"""

import tomllib
from pathlib import Path

from scan_supply_chain import __version__

PROJECT_ROOT = Path(__file__).resolve().parent.parent
PYPROJECT = PROJECT_ROOT / "pyproject.toml"


class TestEntryPoints:
    def test_primary_cli_entry_point_exists(self):
        # @req FR-33
        data = tomllib.loads(PYPROJECT.read_text())
        scripts = data["project"]["scripts"]
        assert "scan-supply-chain" in scripts

    def test_backward_compat_alias_exists(self):
        # @req FR-33
        data = tomllib.loads(PYPROJECT.read_text())
        scripts = data["project"]["scripts"]
        assert "scan-litellm" in scripts

    def test_both_point_to_same_entry(self):
        # @req FR-33
        data = tomllib.loads(PYPROJECT.read_text())
        scripts = data["project"]["scripts"]
        assert scripts["scan-supply-chain"] == scripts["scan-litellm"]


class TestEcosystemCache:
    def test_pypi_returns_same_instance(self):
        from scan_supply_chain.ecosystem_base import _ecosystem_cache, get_ecosystem

        _ecosystem_cache.clear()
        first = get_ecosystem("pypi")
        second = get_ecosystem("pypi")
        assert first is second

    def test_npm_returns_same_instance(self):
        from scan_supply_chain.ecosystem_base import _ecosystem_cache, get_ecosystem

        _ecosystem_cache.clear()
        first = get_ecosystem("npm")
        second = get_ecosystem("npm")
        assert first is second


class TestVersionConsistency:
    def test_init_version_matches_pyproject(self):
        # @req NFR-12
        data = tomllib.loads(PYPROJECT.read_text())
        assert data["project"]["version"] == __version__

    def test_no_runtime_dependencies(self):
        # @req NFR-01
        data = tomllib.loads(PYPROJECT.read_text())
        assert "dependencies" not in data["project"]
