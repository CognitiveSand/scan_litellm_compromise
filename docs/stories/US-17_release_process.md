# US-17: Release new versions safely

## Persona

Alice

## User Story

As a maintainer releasing a new version, I want a release script that enforces pre-flight checks and prevents version desync so that broken or inconsistent releases never reach PyPI.

## Priority

Should Have

## Acceptance Criteria

- [ ] AC-1: `python3 release.py <version>` validates the version format (X.Y.Z), confirms the working tree is clean, and confirms we are on the master branch.
- [ ] AC-2: Pre-flight checks run in order: pytest, ruff check, ruff format, mypy. If any fail, the release is aborted.
- [ ] AC-3: The version is updated in both `pyproject.toml` and `scan_supply_chain/__init__.py` atomically — never one without the other.
- [ ] AC-4: The script verifies that `CHANGELOG.md` contains an entry for the new version before committing.
- [ ] AC-5: The CI pipeline's publish job requires all test/lint/typecheck/build jobs to pass before publishing to PyPI.

## Notes

This story exists because we shipped three releases (v0.4.1–v0.4.3) with version desync and missing changelog entries. The release script and CI gate prevent that class of error.
