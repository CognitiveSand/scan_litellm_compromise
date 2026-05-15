"""Discover local git repositories and snapshot the files the anti-worm
scanner needs.

Runs once per scan (before the per-threat pipeline). The anti-worm
scanner then matches indicator strings against the snapshots in memory
— no repeat I/O when multiple worm-class threat profiles are loaded.

Only the four files/queries the anti-worm scanner consumes are read:

  * ``.git/description``
  * ``.git/refs/heads/*`` and ``.git/packed-refs`` (local branch names)
  * ``.github/workflows/*.y[a]ml`` next to ``.git/``
  * ``git log --format=%ae -n 200`` (recent commit authors, gated on
    ``git`` being on PATH)
"""

from __future__ import annotations

import logging
import os
import shutil
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path

from .config import GIT_REPO_WALK_SKIP_DIRS
from .skip_report import SkipReport
from .subprocess_utils import run_safe

logger = logging.getLogger(__name__)

# Cap to keep scan time bounded on machines with very long histories.
_AUTHOR_EMAIL_LOOKBACK = 200

# Workflow file extensions to enumerate next to each repo root.
_WORKFLOW_SUFFIXES = (".yml", ".yaml")


@dataclass(frozen=True)
class GitRepoSnapshot:
    """A targeted read-only snapshot of one local git repository."""

    repo_root: Path
    description: str
    local_branches: tuple[str, ...]
    workflow_files: tuple[Path, ...]
    recent_author_emails: tuple[str, ...]


def build_repo_index(
    roots: Iterable[str], skip_report: SkipReport
) -> list[GitRepoSnapshot]:
    """Return one ``GitRepoSnapshot`` per local repository found under *roots*.

    Repositories whose real paths coincide (e.g. via a symlinked worktree)
    are deduplicated.
    """
    git_available = shutil.which("git") is not None
    seen: set[Path] = set()
    snapshots: list[GitRepoSnapshot] = []
    for repo_root in _find_repo_roots(roots, skip_report):
        try:
            resolved = repo_root.resolve(strict=False)
        except OSError:
            resolved = repo_root
        if resolved in seen:
            continue
        seen.add(resolved)
        snapshots.append(_snapshot_repo(repo_root, git_available, skip_report))
    return snapshots


# ── Discovery ───────────────────────────────────────────────────────────


def _find_repo_roots(roots: Iterable[str], skip_report: SkipReport) -> Iterator[Path]:
    """Yield the parent directory of each ``.git`` directory found.

    Does not descend into ``.git/`` itself. Prunes heavy/uninteresting
    sibling trees per ``GIT_REPO_WALK_SKIP_DIRS``. Per-subdirectory
    permission errors are routed through ``onerror`` into the
    skip-report so the post-scan summary reflects them.
    """

    def _on_error(exc: OSError) -> None:
        path = Path(exc.filename) if exc.filename else Path("<unknown>")
        if isinstance(exc, PermissionError):
            skip_report.record_permission(path)
        else:
            skip_report.record_read_error(path, type(exc).__name__)

    for raw in roots:
        root_path = Path(raw)
        if not root_path.is_dir():
            continue
        try:
            for dirpath, dirnames, _ in os.walk(root_path, onerror=_on_error):
                dirnames[:] = [d for d in dirnames if d not in GIT_REPO_WALK_SKIP_DIRS]
                if ".git" in dirnames:
                    yield Path(dirpath)
                    # Don't descend into .git/ -- we read targeted files
                    # directly. Also don't descend into siblings: nested
                    # repos under a repo root are unusual; one snapshot
                    # per outer repo is enough for the anti-worm scan.
                    dirnames.remove(".git")
        except PermissionError:
            skip_report.record_permission(root_path)


# ── Per-repo snapshot ───────────────────────────────────────────────────


def _snapshot_repo(
    repo_root: Path, git_available: bool, skip_report: SkipReport
) -> GitRepoSnapshot:
    git_dir = repo_root / ".git"
    return GitRepoSnapshot(
        repo_root=repo_root,
        description=_read_description(git_dir, skip_report),
        local_branches=tuple(_read_local_branches(git_dir, skip_report)),
        workflow_files=tuple(_list_workflow_files(repo_root, skip_report)),
        recent_author_emails=tuple(_read_recent_emails(repo_root, git_available)),
    )


def _read_description(git_dir: Path, skip_report: SkipReport) -> str:
    """Return the contents of ``.git/description`` or empty string."""
    desc_path = git_dir / "description"
    try:
        return desc_path.read_text(errors="ignore").strip()
    except FileNotFoundError:
        # Missing description file is normal — don't record.
        return ""
    except PermissionError:
        skip_report.record_permission(desc_path)
        return ""
    except OSError as exc:
        skip_report.record_read_error(desc_path, type(exc).__name__)
        return ""


def _read_local_branches(git_dir: Path, skip_report: SkipReport) -> Iterator[str]:
    """Yield local branch short names from refs/heads/ and packed-refs."""
    heads_dir = git_dir / "refs" / "heads"
    if heads_dir.is_dir():
        try:
            for entry in heads_dir.rglob("*"):
                if entry.is_file():
                    yield entry.relative_to(heads_dir).as_posix()
        except PermissionError:
            skip_report.record_permission(heads_dir)
        except OSError as exc:
            skip_report.record_read_error(heads_dir, type(exc).__name__)

    packed = git_dir / "packed-refs"
    if packed.is_file():
        try:
            for line in packed.read_text(errors="ignore").splitlines():
                if line.startswith("#") or line.startswith("^"):
                    continue
                parts = line.split(" ", 1)
                if len(parts) != 2:
                    continue
                ref = parts[1].strip()
                prefix = "refs/heads/"
                if ref.startswith(prefix):
                    yield ref[len(prefix) :]
        except PermissionError:
            skip_report.record_permission(packed)
        except OSError as exc:
            skip_report.record_read_error(packed, type(exc).__name__)


def _list_workflow_files(repo_root: Path, skip_report: SkipReport) -> Iterator[Path]:
    """Yield .github/workflows/*.y[a]ml files next to the repo root."""
    workflows = repo_root / ".github" / "workflows"
    if not workflows.is_dir():
        return
    try:
        for entry in workflows.iterdir():
            if entry.is_file() and entry.suffix in _WORKFLOW_SUFFIXES:
                yield entry
    except PermissionError:
        skip_report.record_permission(workflows)
    except OSError as exc:
        skip_report.record_read_error(workflows, type(exc).__name__)


def _read_recent_emails(repo_root: Path, git_available: bool) -> Iterator[str]:
    """Yield recent commit author emails via ``git log``.

    Silently yields nothing if ``git`` is not on PATH, the directory is
    not a real repo, or the subprocess times out.
    """
    if not git_available:
        return
    output = run_safe(
        [
            "git",
            "-C",
            str(repo_root),
            "log",
            f"-n{_AUTHOR_EMAIL_LOOKBACK}",
            "--format=%ae",
        ],
        timeout=2,
    )
    if not output:
        return
    seen: set[str] = set()
    for line in output.splitlines():
        email = line.strip()
        if email and email not in seen:
            seen.add(email)
            yield email
