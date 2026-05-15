"""Tests for the anti-worm scanner and its corroboration scorer.

Module under test: scan_supply_chain.anti_worm_scanner
"""

from __future__ import annotations

import re
from pathlib import Path

from scan_supply_chain.anti_worm_scanner import (
    WormIndicators,
    aggregate_indicators,
    scan_anti_worm,
)
from scan_supply_chain.git_repo_index import GitRepoSnapshot
from scan_supply_chain.models import FindingCategory, ScanResults
from scan_supply_chain.threat_profile import GitArtifactsIOC

from tests.conftest import make_axios_threat

# Weight constants mirror the scanner's internal values.
HIGH = 3
LOW = 1


def _snapshot(
    *,
    repo_root: str = "/tmp/proj",
    description: str = "",
    local_branches: tuple[str, ...] = (),
    workflow_files: tuple[Path, ...] = (),
    recent_author_emails: tuple[str, ...] = (),
) -> GitRepoSnapshot:
    return GitRepoSnapshot(
        repo_root=Path(repo_root),
        description=description,
        local_branches=local_branches,
        workflow_files=workflow_files,
        recent_author_emails=recent_author_emails,
    )


# ── No-op cases ─────────────────────────────────────────────────────────


class TestNoOpCases:
    def test_empty_indicators_emit_nothing(self) -> None:
        results = ScanResults()
        scan_anti_worm(
            results,
            WormIndicators(),
            [_snapshot(description="Shai-Hulud: Here We Go Again")],
        )
        assert results.findings == []

    def test_no_snapshots_emit_nothing(self) -> None:
        results = ScanResults()
        scan_anti_worm(
            results,
            WormIndicators(repo_descriptions=("Shai-Hulud",)),
            [],
        )
        assert results.findings == []

    def test_clean_repo_emits_nothing(self) -> None:
        results = ScanResults()
        scan_anti_worm(
            results,
            WormIndicators(
                workflow_filenames=frozenset({"discussion.yaml"}),
                repo_descriptions=("Shai-Hulud",),
                branch_names=frozenset({"fremen"}),
            ),
            [
                _snapshot(
                    description="A perfectly normal project",
                    local_branches=("main", "develop"),
                    workflow_files=(Path("/r/.github/workflows/ci.yml"),),
                )
            ],
        )
        assert results.findings == []


# ── Strong signals (HIGH alone) ─────────────────────────────────────────


class TestStrongSignals:
    def test_workflow_filename_match_is_high_alone(self) -> None:
        results = ScanResults()
        scan_anti_worm(
            results,
            WormIndicators(workflow_filenames=frozenset({"discussion.yaml"})),
            [_snapshot(workflow_files=(Path("/r/.github/workflows/discussion.yaml"),))],
        )
        assert len(results.findings) == 1
        f = results.findings[0]
        assert f.category == FindingCategory.GIT_ARTIFACT
        assert f.weight == HIGH
        assert "discussion.yaml" in f.description

    def test_workflow_name_regex_match_is_high_alone(self) -> None:
        results = ScanResults()
        scan_anti_worm(
            results,
            WormIndicators(
                workflow_name_regexes=(re.compile(r"^formatter_\d+\.ya?ml$"),),
            ),
            [
                _snapshot(
                    workflow_files=(Path("/r/.github/workflows/formatter_12345.yml"),)
                )
            ],
        )
        assert len(results.findings) == 1
        assert results.findings[0].weight == HIGH

    def test_repo_description_match_is_high_alone(self) -> None:
        results = ScanResults()
        scan_anti_worm(
            results,
            WormIndicators(repo_descriptions=("Shai-Hulud",)),
            [_snapshot(description="Shai-Hulud: Here We Go Again")],
        )
        assert len(results.findings) == 1
        assert results.findings[0].weight == HIGH
        assert "Shai-Hulud" in results.findings[0].description


# ── Weak signals (LOW alone, HIGH when corroborated) ────────────────────


class TestWeakSignals:
    def test_branch_name_alone_is_low(self) -> None:
        results = ScanResults()
        scan_anti_worm(
            results,
            WormIndicators(branch_names=frozenset({"fremen", "atreides"})),
            [_snapshot(local_branches=("main", "fremen"))],
        )
        assert len(results.findings) == 1
        assert results.findings[0].weight == LOW
        assert "fremen" in results.findings[0].description

    def test_branch_name_regex_match_is_low_alone(self) -> None:
        results = ScanResults()
        scan_anti_worm(
            results,
            WormIndicators(
                branch_name_regexes=(re.compile(r"^add-linter-workflow-\d+$"),),
            ),
            [
                _snapshot(
                    local_branches=(
                        "main",
                        "add-linter-workflow-1732456789012",
                    )
                )
            ],
        )
        assert len(results.findings) == 1
        f = results.findings[0]
        assert f.weight == LOW
        assert "add-linter-workflow-1732456789012" in f.description

    def test_branch_regex_dedupes_with_literal(self) -> None:
        """A branch matched by both a literal and a regex emits one finding."""
        results = ScanResults()
        scan_anti_worm(
            results,
            WormIndicators(
                branch_names=frozenset({"fremen"}),
                branch_name_regexes=(re.compile(r"^fr"),),
            ),
            [_snapshot(local_branches=("fremen",))],
        )
        assert len(results.findings) == 1

    def test_author_email_alone_is_low(self) -> None:
        results = ScanResults()
        scan_anti_worm(
            results,
            WormIndicators(
                commit_author_emails=frozenset({"claude@users.noreply.github.com"})
            ),
            [
                _snapshot(
                    recent_author_emails=(
                        "alice@example.com",
                        "claude@users.noreply.github.com",
                    )
                )
            ],
        )
        assert len(results.findings) == 1
        assert results.findings[0].weight == LOW

    def test_branch_plus_description_escalates_branch_to_high(self) -> None:
        results = ScanResults()
        scan_anti_worm(
            results,
            WormIndicators(
                branch_names=frozenset({"fremen"}),
                repo_descriptions=("Shai-Hulud",),
            ),
            [
                _snapshot(
                    description="Shai-Hulud: Here We Go Again",
                    local_branches=("fremen",),
                )
            ],
        )
        # Two findings, both HIGH.
        assert len(results.findings) == 2
        for f in results.findings:
            assert f.weight == HIGH

    def test_branch_plus_workflow_escalates_branch_to_high(self) -> None:
        results = ScanResults()
        scan_anti_worm(
            results,
            WormIndicators(
                branch_names=frozenset({"sandworm"}),
                workflow_filenames=frozenset({"discussion.yaml"}),
            ),
            [
                _snapshot(
                    local_branches=("sandworm",),
                    workflow_files=(Path("/r/.github/workflows/discussion.yaml"),),
                )
            ],
        )
        assert len(results.findings) == 2
        weights = sorted(f.weight for f in results.findings)
        assert weights == [HIGH, HIGH]

    def test_two_weak_signals_alone_stay_low(self) -> None:
        """Weak + weak (no strong) does not escalate."""
        results = ScanResults()
        scan_anti_worm(
            results,
            WormIndicators(
                branch_names=frozenset({"fremen"}),
                commit_author_emails=frozenset({"claude@users.noreply.github.com"}),
            ),
            [
                _snapshot(
                    local_branches=("fremen",),
                    recent_author_emails=("claude@users.noreply.github.com",),
                )
            ],
        )
        assert len(results.findings) == 2
        for f in results.findings:
            assert f.weight == LOW


# ── Per-repo scoping ────────────────────────────────────────────────────


class TestPerRepoScoping:
    def test_corroboration_is_per_repo_not_global(self) -> None:
        """Strong signal in repo A must not escalate weak signal in repo B."""
        results = ScanResults()
        scan_anti_worm(
            results,
            WormIndicators(
                branch_names=frozenset({"fremen"}),
                repo_descriptions=("Shai-Hulud",),
            ),
            [
                _snapshot(
                    repo_root="/repo/A",
                    description="Shai-Hulud: Here We Go Again",
                    local_branches=("main",),
                ),
                _snapshot(
                    repo_root="/repo/B",
                    description="totally fine",
                    local_branches=("fremen",),
                ),
            ],
        )
        # Repo A: 1 HIGH (description).
        # Repo B: 1 LOW (branch alone, no corroborating strong signal).
        # The scanner emits str(Path(...)) for evidence; on Windows that
        # uses backslashes, so build the expected dict the same way.
        by_evidence = {f.evidence: f.weight for f in results.findings}
        assert by_evidence == {
            str(Path("/repo/A")): HIGH,
            str(Path("/repo/B")): LOW,
        }


# ── Aggregation across threat profiles ──────────────────────────────────


class TestAggregateIndicators:
    def test_empty_threats_returns_empty(self) -> None:
        result = aggregate_indicators([])
        assert result.is_empty

    def test_threat_without_git_artifacts_contributes_nothing(self) -> None:
        # Axios threat has no git_artifacts block.
        threat = make_axios_threat()
        result = aggregate_indicators([threat])
        assert result.is_empty

    def test_union_across_multiple_threats(self) -> None:
        t1 = make_axios_threat(
            git_artifacts=GitArtifactsIOC(
                workflow_filenames=("discussion.yaml",),
                branch_names=("fremen",),
                repo_descriptions=("Shai-Hulud",),
            ),
        )
        t2 = make_axios_threat(
            git_artifacts=GitArtifactsIOC(
                workflow_filenames=("shai-hulud-workflow.yml",),
                branch_names=("atreides",),
                commit_author_emails=("claude@users.noreply.github.com",),
            ),
        )

        result = aggregate_indicators([t1, t2])

        assert result.workflow_filenames == frozenset(
            {"discussion.yaml", "shai-hulud-workflow.yml"}
        )
        assert result.branch_names == frozenset({"fremen", "atreides"})
        assert result.commit_author_emails == frozenset(
            {"claude@users.noreply.github.com"}
        )
        assert result.repo_descriptions == ("Shai-Hulud",)

    def test_passes_workflow_regexes_through(self) -> None:
        threat = make_axios_threat(
            git_artifacts=GitArtifactsIOC(
                workflow_name_regexes=(re.compile(r"^formatter_\d+\.ya?ml$"),),
            ),
        )
        result = aggregate_indicators([threat])
        assert len(result.workflow_name_regexes) == 1
        assert result.workflow_name_regexes[0].search("formatter_12345.yml")

    def test_passes_branch_regexes_through(self) -> None:
        threat = make_axios_threat(
            git_artifacts=GitArtifactsIOC(
                branch_name_regexes=(re.compile(r"^add-linter-workflow-\d+$"),),
            ),
        )
        result = aggregate_indicators([threat])
        assert len(result.branch_name_regexes) == 1
        assert result.branch_name_regexes[0].search("add-linter-workflow-1732456789012")
