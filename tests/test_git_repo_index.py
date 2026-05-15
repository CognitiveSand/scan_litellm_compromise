"""Tests for git repo index discovery.

Module under test: scan_supply_chain.git_repo_index
"""

from __future__ import annotations

from pathlib import Path

import pytest

from scan_supply_chain.git_repo_index import (
    GitRepoSnapshot,
    build_repo_index,
)
from scan_supply_chain.skip_report import SkipReport


# ── Fixture helpers ─────────────────────────────────────────────────────


def _make_repo(
    root: Path,
    *,
    description: str = "Unnamed repository; edit this file 'description' to name the repository.",
    refs_heads: dict[str, str] | None = None,
    packed_refs: str | None = None,
    workflows: dict[str, str] | None = None,
) -> Path:
    """Create a fake .git tree under *root* and return the repo root."""
    root.mkdir(parents=True, exist_ok=True)
    git = root / ".git"
    git.mkdir()
    (git / "description").write_text(description)

    heads = git / "refs" / "heads"
    heads.mkdir(parents=True)
    for branch, sha in (refs_heads or {}).items():
        (heads / branch).parent.mkdir(parents=True, exist_ok=True)
        (heads / branch).write_text(sha + "\n")

    if packed_refs is not None:
        (git / "packed-refs").write_text(packed_refs)

    if workflows:
        wf_dir = root / ".github" / "workflows"
        wf_dir.mkdir(parents=True)
        for name, content in workflows.items():
            (wf_dir / name).write_text(content)
    return root


# ── build_repo_index ────────────────────────────────────────────────────


class TestBuildRepoIndex:
    def test_returns_empty_when_no_git_dirs(self, tmp_path: Path) -> None:
        assert build_repo_index([str(tmp_path)], SkipReport()) == []

    def test_discovers_single_repo(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _disable_git_log(monkeypatch)
        _make_repo(tmp_path / "proj", description="my project")

        snapshots = build_repo_index([str(tmp_path)], SkipReport())

        assert len(snapshots) == 1
        snap = snapshots[0]
        assert isinstance(snap, GitRepoSnapshot)
        assert snap.repo_root.name == "proj"
        assert snap.description == "my project"

    def test_reads_refs_heads(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _disable_git_log(monkeypatch)
        _make_repo(
            tmp_path / "proj",
            refs_heads={"main": "deadbeef", "feature/fremen": "abc123"},
        )

        [snap] = build_repo_index([str(tmp_path)], SkipReport())

        assert "main" in snap.local_branches
        assert "feature/fremen" in snap.local_branches

    def test_reads_packed_refs(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _disable_git_log(monkeypatch)
        packed = (
            "# pack-refs with: peeled fully-peeled sorted\n"
            "deadbeef refs/heads/atreides\n"
            "abc123 refs/heads/main\n"
            "^cafef00d\n"
            "11223344 refs/remotes/origin/main\n"
        )
        _make_repo(tmp_path / "proj", packed_refs=packed)

        [snap] = build_repo_index([str(tmp_path)], SkipReport())

        assert "atreides" in snap.local_branches
        assert "main" in snap.local_branches
        # Remote refs and peeled lines must not appear as local branches.
        assert "refs/remotes/origin/main" not in snap.local_branches
        assert "origin/main" not in snap.local_branches

    def test_lists_workflow_files(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _disable_git_log(monkeypatch)
        _make_repo(
            tmp_path / "proj",
            workflows={
                "ci.yml": "name: ci",
                "discussion.yaml": "name: discussion",
                "README.md": "ignore",  # not a yaml file
            },
        )

        [snap] = build_repo_index([str(tmp_path)], SkipReport())

        names = {p.name for p in snap.workflow_files}
        assert names == {"ci.yml", "discussion.yaml"}

    def test_does_not_descend_into_git_dir(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A spurious .git named directory inside .git/ must not yield a repo."""
        _disable_git_log(monkeypatch)
        _make_repo(tmp_path / "proj")
        nested = tmp_path / "proj" / ".git" / "modules" / "sub" / ".git"
        nested.mkdir(parents=True)

        snapshots = build_repo_index([str(tmp_path)], SkipReport())

        assert len(snapshots) == 1
        assert snapshots[0].repo_root.name == "proj"

    def test_deduplicates_by_real_path(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A symlinked alias to the same repo should be returned once."""
        _disable_git_log(monkeypatch)
        _make_repo(tmp_path / "proj")
        try:
            (tmp_path / "alias").symlink_to(tmp_path / "proj")
        except (OSError, NotImplementedError):
            pytest.skip("symlinks not supported on this platform")

        snapshots = build_repo_index([str(tmp_path)], SkipReport())

        assert len(snapshots) == 1

    def test_skips_node_modules(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Repos under node_modules / site-packages must not be discovered."""
        _disable_git_log(monkeypatch)
        _make_repo(tmp_path / "outer")
        _make_repo(tmp_path / "outer" / "node_modules" / "vendor")

        snapshots = build_repo_index([str(tmp_path)], SkipReport())

        roots = {s.repo_root.name for s in snapshots}
        assert roots == {"outer"}

    def test_skips_when_git_binary_absent(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """recent_author_emails is empty when git is not on PATH."""
        monkeypatch.setattr(
            "scan_supply_chain.git_repo_index.shutil.which", lambda _: None
        )
        _make_repo(tmp_path / "proj")

        [snap] = build_repo_index([str(tmp_path)], SkipReport())

        assert snap.recent_author_emails == ()

    def test_collects_unique_recent_emails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Author emails from git log are deduplicated, order preserved."""
        monkeypatch.setattr(
            "scan_supply_chain.git_repo_index.shutil.which",
            lambda _: "/usr/bin/git",
        )
        monkeypatch.setattr(
            "scan_supply_chain.git_repo_index.run_safe",
            lambda *_a, **_kw: (
                "alice@example.com\n"
                "claude@users.noreply.github.com\n"
                "alice@example.com\n"
                "\n"
            ),
        )
        _make_repo(tmp_path / "proj")

        [snap] = build_repo_index([str(tmp_path)], SkipReport())

        assert snap.recent_author_emails == (
            "alice@example.com",
            "claude@users.noreply.github.com",
        )


# ── Helpers ─────────────────────────────────────────────────────────────


def _disable_git_log(monkeypatch: pytest.MonkeyPatch) -> None:
    """Stub out git-on-PATH so no subprocess runs from tests by default."""
    monkeypatch.setattr("scan_supply_chain.git_repo_index.shutil.which", lambda _: None)
