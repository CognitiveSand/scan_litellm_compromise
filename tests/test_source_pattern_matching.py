"""Tests for the source scanner's pure pattern-matching helpers.

Module under test: scan_supply_chain.source_scanner
"""

import pytest

from scan_supply_chain.ecosystem_pypi import PyPIPlugin
from scan_supply_chain.source_scanner import _is_config_file
from tests.conftest import matches_any


# ── _is_config_file ──────────────────────────────────────────────────


class TestIsConfigFile:
    @pytest.fixture
    def pypi(self):
        return PyPIPlugin()

    @pytest.mark.parametrize(
        "filename",
        [
            "pyproject.toml",
            "setup.cfg",
            "setup.py",
            "requirements.txt",
            "requirements-dev.txt",
            "requirements-prod.txt",
            "Pipfile",
            "Pipfile.lock",
            "poetry.lock",
            "pdm.lock",
            "uv.lock",
        ],
    )
    def test_recognizes_known_config_files(self, pypi, filename):
        # @req FR-21
        ext = "." + filename.rsplit(".", 1)[-1] if "." in filename else ""
        assert _is_config_file(
            filename,
            ext,
            pypi.config_filenames,
            pypi.config_extensions,
            pypi.config_filename_pattern(),
        )

    @pytest.mark.parametrize(
        "filename",
        [
            "requirements-ci.txt",
            "requirements-test.txt",
        ],
    )
    def test_recognizes_requirements_variants(self, pypi, filename):
        # @req FR-21
        assert _is_config_file(
            filename,
            ".txt",
            pypi.config_filenames,
            pypi.config_extensions,
            pypi.config_filename_pattern(),
        )

    @pytest.mark.parametrize(
        "filename",
        [
            "app.py",
            "README.md",
            "data.csv",
            "image.png",
        ],
    )
    def test_rejects_non_config_files(self, pypi, filename):
        # @req FR-21
        ext = "." + filename.rsplit(".", 1)[-1] if "." in filename else ""
        assert not _is_config_file(
            filename,
            ext,
            pypi.config_filenames,
            pypi.config_extensions,
            pypi.config_filename_pattern(),
        )


# ── Source pattern matching ──────────────────────────────────────────


class TestSourcePatternMatching:
    @pytest.fixture
    def import_patterns(self):
        return PyPIPlugin().import_patterns("litellm")

    @pytest.mark.parametrize(
        "line",
        [
            "import litellm",
            "  import litellm",
            "\timport litellm",
            "from litellm import completion",
            "from litellm.utils import helper",
            'x = litellm.completion("hello")',
        ],
    )
    def test_matches_import_patterns(self, import_patterns, line):
        # @req FR-20
        assert matches_any(import_patterns, line)

    @pytest.mark.parametrize(
        "line",
        [
            "# import litellm",
            "import flask",
            "",
            "my_litellm = None",
        ],
    )
    def test_rejects_non_import_patterns(self, import_patterns, line):
        # @req FR-20
        assert not matches_any(import_patterns, line)


# ── Config pattern matching ──────────────────────────────────────────


class TestConfigPatternMatching:
    @pytest.fixture
    def dep_patterns(self):
        return PyPIPlugin().dep_patterns("litellm")

    @pytest.mark.parametrize(
        "line",
        [
            "litellm==1.82.7",
            "litellm>=1.80.0",
            "litellm~=1.80",
            '"litellm"',
            "litellm",
        ],
    )
    def test_matches_dep_patterns(self, dep_patterns, line):
        # @req FR-21
        assert matches_any(dep_patterns, line)

    @pytest.mark.parametrize(
        "line",
        [
            "requests==2.31.0",
            "# litellm is great",
        ],
    )
    def test_rejects_non_dep_patterns(self, dep_patterns, line):
        # @req FR-21
        assert not matches_any(dep_patterns, line)
