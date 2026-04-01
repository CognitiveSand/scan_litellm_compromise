# US-04: Scan using a custom threat profile

## Persona

Alice

## User Story

As a SecOps engineer responding to an internal or zero-day incident not yet covered by built-in profiles, I want to load a custom threat profile from a TOML file so that I can scan for novel threats immediately without waiting for a package update.

## Priority

Must Have

## Acceptance Criteria

- [ ] AC-1: `--threat-file <PATH>` loads the TOML file and runs the pipeline for that single threat.
- [ ] AC-2: The scanner exits with code 2 and a clear error if the file does not exist.
- [ ] AC-3: The scanner exits with a clear error if the TOML file is malformed or missing required fields (`id`, `name`, `ecosystem`, `package`).
- [ ] AC-4: The custom profile is not required to be in the built-in or user-local threats directory.
- [ ] AC-5: `--threat-file` is mutually exclusive with `--threat` and `--list-threats`.

## Notes

This is the fast-response path for Alice when a new advisory drops. She writes a TOML file and scans immediately.
