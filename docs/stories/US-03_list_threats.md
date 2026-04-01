# US-03: List available threat profiles

## Persona

Both

## User Story

As a user, I want to list all available threat profiles so that I know what the scanner can detect and which IDs to use with `--threat`.

## Priority

Must Have

## Acceptance Criteria

- [ ] AC-1: `--list-threats` prints the scanner version and every available threat profile.
- [ ] AC-2: Each profile shows: id, human-readable name, ecosystem, package name, compromised versions, and date.
- [ ] AC-3: Both built-in and user-defined profiles are listed.
- [ ] AC-4: User-defined profiles that override a built-in profile (same id) show the user version, not the built-in.
- [ ] AC-5: The scanner exits with code 0 after printing.

## Notes

This is a discovery command — it should never trigger a scan or produce any filesystem side-effects.
