# US-06: Detect a compromised package version

## Persona

Both

## User Story

As a user, I want the scanner to find every installed instance of a compromised package version so that I know exactly which environments are affected.

## Priority

Must Have

## Acceptance Criteria

- [ ] AC-1: The scanner discovers PyPI packages via `dist-info` and `egg-info` metadata directories.
- [ ] AC-2: The scanner discovers npm packages via `node_modules/{package}/package.json`.
- [ ] AC-3: The version is extracted from metadata files (PyPI: `METADATA`/`PKG-INFO`; npm: `package.json` `version` field).
- [ ] AC-4: Each installation is reported with its version and filesystem path.
- [ ] AC-5: Compromised versions are clearly flagged in red; safe versions in green.
- [ ] AC-6: Virtual environments (conda, pipx, venv), global npm, and nvm locations are all searched.

## Notes

This is the core detection capability. False negatives here are critical bugs.
