"""Tests for TOML threat-profile parsing.

Module under test: scan_supply_chain.threat_profile
"""

from __future__ import annotations

from pathlib import Path

from scan_supply_chain.threat_profile import (
    GitArtifactsIOC,
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
    def test_missing_block_yields_empty_iocs(self, tmp_path):
        profile = load_threat_file(_write_toml(tmp_path, ""))
        assert isinstance(profile.git_artifacts, GitArtifactsIOC)
        assert profile.git_artifacts.is_empty

    def test_full_block_parses_all_fields(self, tmp_path):
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
        assert ga.workflow_name_regexes == (r"^formatter_\d+\.ya?ml$",)
        assert set(ga.branch_names) == {"fremen", "atreides"}
        assert ga.branch_name_regexes == (r"^add-linter-workflow-\d+$",)
        assert ga.commit_author_emails == (
            "claude@users.noreply.github.com",
        )
        assert ga.repo_descriptions == ("Shai-Hulud",)


class TestParsePersistenceKeywords:
    def test_missing_block_yields_empty_tuple(self, tmp_path):
        profile = load_threat_file(_write_toml(tmp_path, ""))
        assert profile.persistence_keywords == ()

    def test_terms_are_parsed(self, tmp_path):
        body = """
[ioc.persistence_keywords]
terms = ["gh-token-monitor", "shai-hulud"]
"""
        profile = load_threat_file(_write_toml(tmp_path, body))
        assert profile.persistence_keywords == (
            "gh-token-monitor",
            "shai-hulud",
        )
