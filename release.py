#!/usr/bin/env python3
"""Release script — single source of truth for version bumps and publishing.

Usage:
    python3 release.py 0.5.0

What it does:
    1. Validates the version argument
    2. Runs all pre-flight checks (tests, ruff, mypy)
    3. Updates version in pyproject.toml and __init__.py
    4. Verifies CHANGELOG.md mentions the new version
    5. Commits, tags, pushes
    6. Creates a GitHub release (triggers CI -> publish pipeline)
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

PYPROJECT = Path("pyproject.toml")
INIT_PY = Path("scan_supply_chain/__init__.py")
CHANGELOG = Path("CHANGELOG.md")

VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")


# ── Validation ──────────────────────────────────────────────────────────


def _parse_version(args: list[str]) -> str:
    if len(args) != 2:
        print(f"Usage: {args[0]} <version>  (e.g. 0.5.0)")
        sys.exit(2)
    version = args[1]
    if not VERSION_RE.match(version):
        print(f"Error: invalid version format: {version!r} (expected X.Y.Z)")
        sys.exit(2)
    return version


def _check_clean_worktree() -> None:
    result = subprocess.run(
        ["git", "status", "--porcelain"],
        capture_output=True,
        text=True,
    )
    if result.stdout.strip():
        print("Error: working tree is not clean. Commit or stash changes first.")
        print(result.stdout)
        sys.exit(1)


def _check_on_master() -> None:
    result = subprocess.run(
        ["git", "branch", "--show-current"],
        capture_output=True,
        text=True,
    )
    branch = result.stdout.strip()
    if branch != "master":
        print(f"Error: not on master branch (on {branch!r})")
        sys.exit(1)


# ── Pre-flight checks ──────────────────────────────────────────────────


def _run_check(description: str, command: list[str]) -> None:
    print(f"  {description}...", end=" ", flush=True)
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode != 0:
        print("FAILED")
        print(result.stdout)
        print(result.stderr)
        sys.exit(1)
    print("ok")


def _run_preflight_checks() -> None:
    print("Pre-flight checks:")
    _run_check("pytest", ["python3", "-m", "pytest", "--tb=short", "-q"])
    _run_check("ruff check", ["ruff", "check", "."])
    _run_check("ruff format", ["ruff", "format", "--check", "."])
    _run_check("mypy", ["mypy", "scan_supply_chain/"])


# ── Version bump ────────────────────────────────────────────────────────


def _update_version_in_file(path: Path, old: str, new: str) -> None:
    text = path.read_text()
    updated = text.replace(old, new, 1)
    if updated == text:
        print(f"Error: could not find version {old!r} in {path}")
        sys.exit(1)
    path.write_text(updated)


def _read_current_version() -> str:
    text = INIT_PY.read_text()
    match = re.search(r'__version__\s*=\s*"([^"]+)"', text)
    if not match:
        print(f"Error: cannot read current version from {INIT_PY}")
        sys.exit(1)
    return match.group(1)


def _bump_version(old_version: str, new_version: str) -> None:
    print(f"Bumping version: {old_version} -> {new_version}")
    _update_version_in_file(INIT_PY, f'"{old_version}"', f'"{new_version}"')
    _update_version_in_file(
        PYPROJECT, f'version = "{old_version}"', f'version = "{new_version}"'
    )


# ── Changelog check ────────────────────────────────────────────────────


def _verify_changelog(version: str) -> None:
    text = CHANGELOG.read_text()
    if f"## {version}" not in text:
        print(f"Error: CHANGELOG.md does not contain an entry for ## {version}")
        print("Add a changelog entry before releasing.")
        sys.exit(1)
    print(f"Changelog entry for {version} found.")


# ── Git + GitHub ────────────────────────────────────────────────────────


def _git_commit_tag_push(version: str) -> None:
    tag = f"v{version}"
    subprocess.run(["git", "add", str(PYPROJECT), str(INIT_PY)], check=True)
    subprocess.run(
        ["git", "commit", "-m", f"Bump version to {version}"],
        check=True,
    )
    subprocess.run(["git", "tag", tag], check=True)
    subprocess.run(["git", "push", "origin", "master"], check=True)
    subprocess.run(["git", "push", "origin", tag], check=True)
    print(f"Pushed {tag}")


def _create_github_release(version: str) -> None:
    tag = f"v{version}"
    result = subprocess.run(
        [
            "gh",
            "release",
            "create",
            tag,
            "--title",
            tag,
            "--notes",
            "See CHANGELOG.md for details.",
        ],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print(f"Warning: gh release create failed: {result.stderr}")
        print("Create the release manually on GitHub to trigger PyPI publish.")
    else:
        print(f"GitHub release created: {result.stdout.strip()}")
    print("\nCI will run tests -> lint -> typecheck -> build -> publish to PyPI.")


# ── Main ────────────────────────────────────────────────────────────────


def main() -> None:
    version = _parse_version(sys.argv)
    _check_on_master()
    _check_clean_worktree()
    _run_preflight_checks()

    old_version = _read_current_version()
    _bump_version(old_version, version)
    _verify_changelog(version)

    _git_commit_tag_push(version)
    _create_github_release(version)


if __name__ == "__main__":
    main()
