# US-01: Run a full system scan against all known threats

## Persona

Bob

## User Story

As a junior employee responding to a security advisory, I want to run the scanner with no arguments so that every known supply chain compromise is checked without me needing to know which specific threats exist.

## Priority

Must Have

## Acceptance Criteria

- [ ] AC-1: Running `scan-supply-chain` with no flags scans every built-in and user-defined threat profile.
- [ ] AC-2: The banner displays the scanner version and lists every threat profile that will be scanned (id, ecosystem, package, compromised versions).
- [ ] AC-3: The scanner exits with code 0 when no compromise is detected across any profile.
- [ ] AC-4: The scanner exits with code 1 when at least one compromise is detected in any profile.
- [ ] AC-5: Each threat profile produces its own section in the final report with a per-threat verdict.

## Notes

This is the primary entry point for most users. The zero-configuration default must be safe and complete — no threat should be silently skipped.
