# US-16: Detect Windows persistence mechanisms

## Persona

Alice

## User Story

As a SecOps engineer investigating a compromised Windows workstation, I want the scanner to check Registry Run keys and Scheduled Tasks for attacker persistence so that I can identify backdoors that survive reboots.

## Priority

Should Have

## Acceptance Criteria

- [ ] AC-1: On Windows, the scanner queries `HKCU\...\Run` and `HKLM\...\Run` registry keys for keywords defined in the threat profile.
- [ ] AC-2: On Windows, the scanner queries `schtasks /query` for task names matching keywords defined in the threat profile.
- [ ] AC-3: Matches are reported as IOCs with the matched keyword and registry key or task name.
- [ ] AC-4: These checks run only on Windows — they are silently skipped on Linux and macOS.
- [ ] AC-5: If the threat profile's `windows.registry_keywords` and `windows.schtask_keywords` are both empty, the checks are skipped entirely.

## Technical Constraints

Requires `reg.exe` and `schtasks.exe` (present on all Windows 10/11 installations). Elevated privileges may be needed for `HKLM` keys.

## Notes

The LiteLLM attack installs persistence via sysmon entries in Startup folder and systemd (Linux). The Windows checks cover the equivalent persistence paths.
