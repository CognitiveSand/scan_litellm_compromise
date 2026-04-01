# US-02: Scan for a specific known threat

## Persona

Alice

## User Story

As an experienced SecOps engineer triaging a specific incident, I want to scan for a single threat by its ID so that I get focused results without noise from unrelated threat profiles.

## Priority

Must Have

## Acceptance Criteria

- [ ] AC-1: `--threat <ID>` runs only the pipeline for the matching threat profile.
- [ ] AC-2: The scanner exits with code 2 and a clear error message when the ID does not match any known profile.
- [ ] AC-3: The error message suggests running `--list-threats` to see available profiles.
- [ ] AC-4: `--threat` is mutually exclusive with `--threat-file` and `--list-threats`.

## Notes

Alice uses this during active incident response when she already knows which advisory applies.
