# US-07: Detect IOC artifacts on disk

## Persona

Alice

## User Story

As a SecOps engineer, I want the scanner to check for known IOC files (backdoors, persistence mechanisms, staging artifacts) so that I can determine whether malicious payloads were deployed, not just installed.

## Priority

Must Have

## Acceptance Criteria

- [ ] AC-1: Walk-file IOCs (e.g., `litellm_init.pth`) are found by recursively searching the computed search roots.
- [ ] AC-2: When SHA-256 hashes are specified in the threat profile, files are verified by hash to reduce false positives.
- [ ] AC-3: Known-path IOCs (e.g., `~/.config/sysmon/sysmon.py`) are checked via direct path existence, expanded per platform (`~`, `%APPDATA%`).
- [ ] AC-4: Each found IOC is reported with its full filesystem path.
- [ ] AC-5: IOC discovery uses the same augmented search roots as package discovery (no detection gaps).

## Notes

IOC presence is a stronger signal than package version alone — it means the payload executed, not just that the package was installed.
