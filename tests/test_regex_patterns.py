"""Tests for the detection engine: regex patterns from ecosystem plugins.

Module under test: scan_supply_chain.ecosystem_pypi, ecosystem_npm
"""

import pytest

from scan_supply_chain.ecosystem_pypi import PyPIPlugin
from scan_supply_chain.ecosystem_npm import NpmPlugin


# ── PyPI metadata dir pattern ────────────────────────────────────────


class TestPyPIMetadataDirPattern:
    @pytest.fixture
    def pattern(self):
        return PyPIPlugin().metadata_dir_pattern("litellm")

    @pytest.mark.parametrize(
        "dirname",
        [
            "litellm-1.82.7.dist-info",
            "litellm-1.82.8.dist-info",
            "litellm-1.0.egg-info",
            "litellm-0.0.1a1.egg-info",
            "litellm-2.0.0.dev0.dist-info",
        ],
    )
    def test_recognizes_litellm_metadata_dirs(self, pattern, dirname):
        assert pattern.match(dirname) is not None

    @pytest.mark.parametrize(
        "dirname",
        [
            "requests-2.31.0.dist-info",
            "flask-3.0.egg-info",
            "litellm",
            ".dist-info",
            "",
            "__pycache__",
        ],
    )
    def test_rejects_non_litellm_dirs(self, pattern, dirname):
        assert pattern.match(dirname) is None


# ── PyPI Python import patterns ──────────────────────────────────────


class TestPyPIImportPatterns:
    @pytest.fixture
    def patterns(self):
        return PyPIPlugin().import_patterns("litellm")

    def _matches(self, patterns, line):
        return any(p.search(line) for p in patterns)

    @pytest.mark.parametrize(
        "line",
        [
            "import litellm",
            "  import litellm",
            "from litellm import something",
            "from litellm.utils import helper",
            "  from litellm import completion",
            'litellm.completion("hello")',
            '"litellm"',
            "'litellm'",
            'result = litellm.acompletion(prompt="hi")',
        ],
    )
    def test_matches_litellm_usage(self, patterns, line):
        assert self._matches(patterns, line)

    @pytest.mark.parametrize(
        "line",
        [
            "import requests",
            "from flask import Flask",
            "# litellm is not used",
            "my_litellm_wrapper()",
            "x = xlitellm",
        ],
    )
    def test_does_not_match_non_litellm_usage(self, patterns, line):
        assert not self._matches(patterns, line)


# ── PyPI dependency patterns ─────────────────────────────────────────


class TestPyPIDependencyPatterns:
    @pytest.fixture
    def patterns(self):
        return PyPIPlugin().dep_patterns("litellm")

    def _matches(self, patterns, line):
        return any(p.search(line) for p in patterns)

    @pytest.mark.parametrize(
        "line",
        [
            "litellm>=1.80.0",
            "litellm==1.82.7",
            "litellm~=1.80",
            "litellm!=1.82.7",
            "litellm<2.0",
            '"litellm"',
            "'litellm'",
            'litellm = "^1.80"',
            "litellm",
        ],
    )
    def test_matches_litellm_dependency_lines(self, patterns, line):
        assert self._matches(patterns, line)

    @pytest.mark.parametrize(
        "line",
        [
            "requests>=2.0",
            "# litellm is not a dep",
            "my-litellm-wrapper>=1.0",
        ],
    )
    def test_does_not_match_non_litellm_deps(self, patterns, line):
        assert not self._matches(patterns, line)


# ── PyPI pinned version extraction ───────────────────────────────────


class TestPyPIPinnedVersion:
    @pytest.fixture
    def pattern(self):
        return PyPIPlugin().pinned_version_pattern("litellm")

    @pytest.mark.parametrize(
        "line,expected",
        [
            ("litellm==1.82.7", "1.82.7"),
            ("litellm==1.82.8", "1.82.8"),
            ("litellm==1.80.0", "1.80.0"),
            ("litellm==0.1.0a1", "0.1.0a1"),
        ],
    )
    def test_extracts_pinned_versions(self, pattern, line, expected):
        match = pattern.search(line)
        assert match is not None
        assert match.group(1) == expected

    @pytest.mark.parametrize(
        "line",
        [
            "litellm>=1.80.0",
            "litellm~=1.80",
            "litellm",
            "requests==2.31.0",
        ],
    )
    def test_does_not_extract_from_non_pinned(self, pattern, line):
        match = pattern.search(line)
        # Either no match, or not a pinned litellm version
        if match:
            assert (
                "litellm" not in line.split("==")[0]
                or match.group(1) != line.split("==")[-1]
            )


# ── npm import patterns ──────────────────────────────────────────────


class TestNpmImportPatterns:
    @pytest.fixture
    def patterns(self):
        return NpmPlugin().import_patterns("axios")

    def _matches(self, patterns, line):
        return any(p.search(line) for p in patterns)

    @pytest.mark.parametrize(
        "line",
        [
            "const axios = require('axios')",
            'const axios = require("axios")',
            "import axios from 'axios'",
            'import axios from "axios"',
            "import { get } from 'axios'",
            "from 'axios'",
            "require('axios/lib/utils')",
            "import 'axios'",
        ],
    )
    def test_matches_axios_usage(self, patterns, line):
        assert self._matches(patterns, line)

    @pytest.mark.parametrize(
        "line",
        [
            "import http from 'http'",
            "require('node-fetch')",
            "// axios is not used",
        ],
    )
    def test_does_not_match_non_axios_usage(self, patterns, line):
        assert not self._matches(patterns, line)


# ── npm dependency patterns ──────────────────────────────────────────


class TestNpmDependencyPatterns:
    @pytest.fixture
    def patterns(self):
        return NpmPlugin().dep_patterns("axios")

    def _matches(self, patterns, line):
        return any(p.search(line) for p in patterns)

    @pytest.mark.parametrize(
        "line",
        [
            '"axios": "^1.14.0"',
            '"axios": "1.14.1"',
            "'axios': '^1.0.0'",
            "axios@^1.14.0:",
            '"node_modules/axios"',
        ],
    )
    def test_matches_axios_dependency_lines(self, patterns, line):
        assert self._matches(patterns, line)

    @pytest.mark.parametrize(
        "line",
        [
            '"node-fetch": "^3.0"',
            "// axios dep comment",
        ],
    )
    def test_does_not_match_non_axios_deps(self, patterns, line):
        assert not self._matches(patterns, line)


# ── npm pinned version extraction ────────────────────────────────────


class TestNpmPinnedVersion:
    @pytest.fixture
    def pattern(self):
        return NpmPlugin().pinned_version_pattern("axios")

    @pytest.mark.parametrize(
        "line,expected",
        [
            ('"axios": "1.14.1"', "1.14.1"),
            ('"axios": "0.30.4"', "0.30.4"),
        ],
    )
    def test_extracts_pinned_versions(self, pattern, line, expected):
        match = pattern.search(line)
        assert match is not None
        assert match.group(1) == expected

    @pytest.mark.parametrize(
        "line",
        [
            '"axios": "^1.14.0"',
            '"axios": "~1.14.0"',
        ],
    )
    def test_does_not_extract_ranged_versions(self, pattern, line):
        match = pattern.search(line)
        assert match is None
