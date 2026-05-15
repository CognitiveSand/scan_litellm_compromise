"""Anti-worm scanner — match worm-class indicators against git snapshots.

Runs once per scan, after ``git_repo_index.build_repo_index`` has
collected snapshots. Independent of which threat profiles are loaded:
the caller (Phase B-2 wiring in ``scanner.main``) aggregates indicators
across all worm-class profiles into a single ``WormIndicators`` before
invoking ``scan_anti_worm``.

Corroboration rule
------------------
Workflow-filename and repo-description matches are independently
high-signal — Shai-Hulud's literal ``discussion.yaml`` workflow and the
string ``Shai-Hulud`` in ``.git/description`` have essentially no benign
collisions.

Branch names (Dune universe) and commit-author emails are weak alone —
a Dune-themed personal project would false-positive on the branch
list — so they only escalate to HIGH when *another* worm signal fires
on the same repository. Alone, they are reported at LOW weight so the
operator sees them without drowning real signals.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path

from .git_repo_index import GitRepoSnapshot
from .models import FindingCategory, ScanResults
from .threat_profile import ThreatProfile

# Weight constants — mirror ``models.Confidence`` tiers.
_WEIGHT_HIGH = 3
_WEIGHT_LOW = 1


@dataclass(frozen=True)
class WormIndicators:
    """Aggregated set of worm-class indicator strings.

    Each indicator is a literal string (or regex, for workflow names)
    that, if matched against a git repo snapshot, contributes a finding.
    Provenance back to the originating threat profile is not tracked at
    this level — reporting happens against the aggregated set.
    """

    workflow_filenames: frozenset[str] = frozenset()
    workflow_name_regexes: tuple[re.Pattern[str], ...] = ()
    branch_names: frozenset[str] = frozenset()
    branch_name_regexes: tuple[re.Pattern[str], ...] = ()
    commit_author_emails: frozenset[str] = frozenset()
    repo_descriptions: tuple[str, ...] = ()

    @property
    def is_empty(self) -> bool:
        return not (
            self.workflow_filenames
            or self.workflow_name_regexes
            or self.branch_names
            or self.branch_name_regexes
            or self.commit_author_emails
            or self.repo_descriptions
        )


def aggregate_indicators(threats: Iterable[ThreatProfile]) -> WormIndicators:
    """Union every loaded threat's ``git_artifacts`` block into one set.

    Patterns are already compiled by ``_parse_git_artifacts`` at load
    time — a malformed profile fails to load and never reaches this
    function, so no exception handling is needed here.
    """
    workflow_filenames: set[str] = set()
    workflow_regexes: list[re.Pattern[str]] = []
    branch_names: set[str] = set()
    branch_regexes: list[re.Pattern[str]] = []
    commit_emails: set[str] = set()
    repo_descriptions: list[str] = []

    for threat in threats:
        ga = threat.git_artifacts
        workflow_filenames.update(ga.workflow_filenames)
        branch_names.update(ga.branch_names)
        commit_emails.update(ga.commit_author_emails)
        repo_descriptions.extend(ga.repo_descriptions)
        workflow_regexes.extend(ga.workflow_name_regexes)
        branch_regexes.extend(ga.branch_name_regexes)

    # Deduplicate repo_descriptions while preserving order
    seen_desc: set[str] = set()
    unique_desc: list[str] = []
    for d in repo_descriptions:
        if d not in seen_desc:
            seen_desc.add(d)
            unique_desc.append(d)

    return WormIndicators(
        workflow_filenames=frozenset(workflow_filenames),
        workflow_name_regexes=tuple(workflow_regexes),
        branch_names=frozenset(branch_names),
        branch_name_regexes=tuple(branch_regexes),
        commit_author_emails=frozenset(commit_emails),
        repo_descriptions=tuple(unique_desc),
    )


@dataclass(frozen=True)
class _RepoMatch:
    """Matched signals for one repo, before weight assignment."""

    repo_root: Path
    strong_hits: tuple[str, ...]  # workflow filenames / description substrings
    weak_hits: tuple[str, ...]  # branch names / author emails

    @property
    def has_any(self) -> bool:
        return bool(self.strong_hits or self.weak_hits)


def scan_anti_worm(
    results: ScanResults,
    indicators: WormIndicators,
    snapshots: Iterable[GitRepoSnapshot],
) -> None:
    """Emit one ``Finding`` per matched signal across all snapshots."""
    if indicators.is_empty:
        return
    for snapshot in snapshots:
        match = _match_repo(snapshot, indicators)
        if not match.has_any:
            continue
        # Strong signals are always HIGH.  Weak signals escalate to
        # HIGH when at least one strong signal also fired at this repo.
        weak_weight = _WEIGHT_HIGH if match.strong_hits else _WEIGHT_LOW
        repo_label = str(match.repo_root)
        for hit in match.strong_hits:
            results.add_finding(
                FindingCategory.GIT_ARTIFACT,
                f"git artifact: {hit} ({repo_label})",
                repo_label,
                _WEIGHT_HIGH,
            )
        for hit in match.weak_hits:
            results.add_finding(
                FindingCategory.GIT_ARTIFACT,
                f"git artifact: {hit} ({repo_label})",
                repo_label,
                weak_weight,
            )


# ── Per-repo matcher ────────────────────────────────────────────────────


def _match_repo(snapshot: GitRepoSnapshot, indicators: WormIndicators) -> _RepoMatch:
    strong: list[str] = []
    weak: list[str] = []

    strong.extend(_match_workflow_files(snapshot.workflow_files, indicators))
    strong.extend(
        _match_description(snapshot.description, indicators.repo_descriptions)
    )

    weak.extend(
        f"branch={b}"
        for b in _match_branches(
            snapshot.local_branches,
            indicators.branch_names,
            indicators.branch_name_regexes,
        )
    )
    weak.extend(
        f"author={e}"
        for e in _match_set(
            snapshot.recent_author_emails, indicators.commit_author_emails
        )
    )

    return _RepoMatch(
        repo_root=snapshot.repo_root,
        strong_hits=tuple(strong),
        weak_hits=tuple(weak),
    )


def _match_workflow_files(
    workflow_files: Sequence[Path], indicators: WormIndicators
) -> list[str]:
    """Return labels for workflow files whose basename matches an indicator."""
    hits: list[str] = []
    for wf in workflow_files:
        name = wf.name
        if name in indicators.workflow_filenames:
            hits.append(f"workflow={name}")
            continue
        for pattern in indicators.workflow_name_regexes:
            if pattern.search(name):
                hits.append(f"workflow={name}")
                break
    return hits


def _match_description(description: str, needles: Sequence[str]) -> list[str]:
    """Return labels for description substrings that appear in description."""
    if not description:
        return []
    return [f'description~"{needle}"' for needle in needles if needle in description]


def _match_set(haystack: Sequence[str], needles: Iterable[str]) -> list[str]:
    """Return needles that appear verbatim in haystack."""
    haystack_set = set(haystack)
    return [n for n in needles if n in haystack_set]


def _match_branches(
    branches: Sequence[str],
    literals: Iterable[str],
    regexes: Sequence[re.Pattern[str]],
) -> list[str]:
    """Return matched branch names from literal set + regex patterns, deduped."""
    branch_set = set(branches)
    seen: set[str] = set()
    out: list[str] = []
    for literal in literals:
        if literal in branch_set and literal not in seen:
            seen.add(literal)
            out.append(literal)
    if regexes:
        for branch in branches:
            if branch in seen:
                continue
            if any(p.search(branch) for p in regexes):
                seen.add(branch)
                out.append(branch)
    return out
