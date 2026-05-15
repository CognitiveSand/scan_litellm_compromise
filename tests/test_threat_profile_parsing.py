"""Tests for TOML threat-profile parsing.

Module under test: scan_supply_chain.threat_profile
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import pytest

from scan_supply_chain.threat_profile import (
    GitArtifactsIOC,
    InvalidThreatProfileError,
    UnknownProfileKeyError,
    _load_from_dir,
    load_threat_file,
)


_MINIMAL_HEADER = """
[threat]
id          = "test-2026-05"
name        = "Test"
date        = "2026-05-14"
ecosystem   = "npm"
package     = "test-package"
compromised = ["1.0.0"]
safe        = "0.9.9"
advisory    = "https://example.com"
"""


def _write_toml(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "threat.toml"
    path.write_text(_MINIMAL_HEADER + body)
    return path


class TestParseGitArtifacts:
    def test_missing_block_yields_empty_iocs(self, tmp_path: Path) -> None:
        profile = load_threat_file(_write_toml(tmp_path, ""))
        assert isinstance(profile.git_artifacts, GitArtifactsIOC)
        assert profile.git_artifacts.is_empty

    def test_full_block_parses_all_fields(self, tmp_path: Path) -> None:
        body = """
[ioc.git_artifacts]
workflow_filenames    = ["discussion.yaml", "shai-hulud-workflow.yml"]
workflow_name_regexes = ['^formatter_\\d+\\.ya?ml$']
branch_names          = ["fremen", "atreides"]
branch_name_regexes   = ['^add-linter-workflow-\\d+$']
commit_author_emails  = ["claude@users.noreply.github.com"]
repo_descriptions     = ["Shai-Hulud"]
"""
        profile = load_threat_file(_write_toml(tmp_path, body))
        ga = profile.git_artifacts
        assert ga.workflow_filenames == (
            "discussion.yaml",
            "shai-hulud-workflow.yml",
        )
        # Regex fields are compiled to re.Pattern objects at load time.
        assert len(ga.workflow_name_regexes) == 1
        assert ga.workflow_name_regexes[0].search("formatter_42.yml")
        assert set(ga.branch_names) == {"fremen", "atreides"}
        assert len(ga.branch_name_regexes) == 1
        assert ga.branch_name_regexes[0].search("add-linter-workflow-1732456789012")
        assert ga.commit_author_emails == ("claude@users.noreply.github.com",)
        assert ga.repo_descriptions == ("Shai-Hulud",)

    def test_invalid_workflow_regex_raises_at_load_time(self, tmp_path: Path) -> None:
        body = """
[ioc.git_artifacts]
workflow_name_regexes = ["[unclosed"]
"""
        with pytest.raises(re.error) as exc:
            load_threat_file(_write_toml(tmp_path, body))
        assert "workflow_name_regexes" in str(exc.value)
        assert "[unclosed" in str(exc.value)

    def test_invalid_branch_regex_raises_at_load_time(self, tmp_path: Path) -> None:
        body = """
[ioc.git_artifacts]
branch_name_regexes = ["(["]
"""
        with pytest.raises(re.error) as exc:
            load_threat_file(_write_toml(tmp_path, body))
        assert "branch_name_regexes" in str(exc.value)


# ── _load_from_dir error propagation ────────────────────────────────────


class TestLoadFromDir:
    def test_invalid_regex_in_dir_raises_with_path(self, tmp_path: Path) -> None:
        bad = tmp_path / "broken.toml"
        bad.write_text(
            _MINIMAL_HEADER
            + """
[ioc.git_artifacts]
workflow_name_regexes = ["[unclosed"]
"""
        )
        with pytest.raises(InvalidThreatProfileError) as exc:
            _load_from_dir(tmp_path)
        assert exc.value.path == bad
        assert "broken.toml" in str(exc.value)

    def test_malformed_toml_raises_with_path(self, tmp_path: Path) -> None:
        bad = tmp_path / "broken.toml"
        bad.write_text("this is not = valid toml [\n")
        with pytest.raises(InvalidThreatProfileError) as exc:
            _load_from_dir(tmp_path)
        assert exc.value.path == bad
        assert isinstance(exc.value.__cause__, tomllib.TOMLDecodeError)

    def test_missing_required_field_raises_with_path(self, tmp_path: Path) -> None:
        bad = tmp_path / "broken.toml"
        # Missing [threat] section entirely
        bad.write_text('[threat]\nid = "x"\nname = "x"\n')
        with pytest.raises(InvalidThreatProfileError) as exc:
            _load_from_dir(tmp_path)
        assert exc.value.path == bad
        assert isinstance(exc.value.__cause__, KeyError)

    def test_missing_directory_returns_empty(self, tmp_path: Path) -> None:
        # An absent user-config dir is not an error.
        result = _load_from_dir(tmp_path / "nonexistent")
        assert result == {}


class TestUnknownKeyDetection:
    """Typos in known sections must fail loud, not silently default."""

    def test_typo_in_threat_section_raises(self, tmp_path: Path) -> None:
        # ``ecosytem`` is a typo for ``ecosystem``; without schema
        # validation the parser silently dropped the value and used the
        # default for the actual ``ecosystem`` field.
        toml = """
[threat]
id          = "x"
name        = "x"
ecosystem   = "npm"
package     = "x"
ecosytem    = "npm"
"""
        path = tmp_path / "typo.toml"
        path.write_text(toml)
        with pytest.raises(UnknownProfileKeyError) as exc:
            load_threat_file(path)
        assert "ecosytem" in str(exc.value)
        assert "[threat]" in str(exc.value)

    def test_unknown_top_level_section_raises(self, tmp_path: Path) -> None:
        body = """
[unknown_section]
foo = "bar"
"""
        path = _write_toml(tmp_path, body)
        with pytest.raises(UnknownProfileKeyError) as exc:
            load_threat_file(path)
        assert "unknown_section" in str(exc.value)

    def test_unknown_key_in_walk_files_raises(self, tmp_path: Path) -> None:
        body = """
[[ioc.walk_files]]
description = "x"
filenamez   = ["bundle.js"]
"""
        path = _write_toml(tmp_path, body)
        with pytest.raises(UnknownProfileKeyError) as exc:
            load_threat_file(path)
        assert "filenamez" in str(exc.value)
        assert "ioc.walk_files" in str(exc.value)

    def test_unknown_key_in_git_artifacts_raises(self, tmp_path: Path) -> None:
        body = """
[ioc.git_artifacts]
branch_namez = ["fremen"]
"""
        path = _write_toml(tmp_path, body)
        with pytest.raises(UnknownProfileKeyError) as exc:
            load_threat_file(path)
        assert "branch_namez" in str(exc.value)

    def test_unknown_platform_in_remediation_raises(self, tmp_path: Path) -> None:
        body = """
[remediation.remove_artifacts]
freebsd = ["rm /tmp/foo"]
"""
        path = _write_toml(tmp_path, body)
        with pytest.raises(UnknownProfileKeyError) as exc:
            load_threat_file(path)
        assert "freebsd" in str(exc.value)

    def test_typo_wrapped_by_load_from_dir(self, tmp_path: Path) -> None:
        bad = tmp_path / "broken.toml"
        bad.write_text(
            _MINIMAL_HEADER
            + """
[ioc.git_artifacts]
branch_namez = ["fremen"]
"""
        )
        with pytest.raises(InvalidThreatProfileError) as exc:
            _load_from_dir(tmp_path)
        assert exc.value.path == bad
        assert isinstance(exc.value.__cause__, UnknownProfileKeyError)


class TestParsePersistenceKeywords:
    def test_missing_block_yields_empty_tuple(self, tmp_path: Path) -> None:
        profile = load_threat_file(_write_toml(tmp_path, ""))
        assert profile.persistence_keywords == ()

    def test_terms_are_parsed(self, tmp_path: Path) -> None:
        body = """
[ioc.persistence_keywords]
terms = ["gh-token-monitor", "shai-hulud"]
"""
        profile = load_threat_file(_write_toml(tmp_path, body))
        assert profile.persistence_keywords == (
            "gh-token-monitor",
            "shai-hulud",
        )
