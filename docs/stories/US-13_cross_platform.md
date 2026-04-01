# US-13: Run on Linux, macOS, and Windows

## Persona

Both

## User Story

As a user, I want the scanner to automatically detect my operating system and adjust its behavior so that I get correct results without platform-specific configuration.

## Priority

Must Have

## Acceptance Criteria

- [ ] AC-1: The scanner auto-detects the platform (Linux, macOS, Windows) at startup and displays it in the banner.
- [ ] AC-2: Search roots are platform-appropriate (Linux: `/home`, `/opt`; macOS: `/Users`, `/opt/homebrew`; Windows: `%USERPROFILE%`, `%APPDATA%`).
- [ ] AC-3: Network connection checks use the platform-appropriate tool (`ss`, `lsof`, `netstat`).
- [ ] AC-4: IOC known paths are expanded using platform-native variable syntax (`~` on Unix, `%VAR%` on Windows).
- [ ] AC-5: Terminal output uses ANSI colors on Linux/macOS and auto-enables Virtual Terminal Processing on Windows 10/11.
- [ ] AC-6: Windows-only IOC checks (Registry Run keys, Scheduled Tasks) run only on Windows.

## Technical Constraints

Requires Python 3.11+ (for `tomllib`). No external dependencies — standard library only.

## Notes

The scanner should work identically via `pip install` on all three platforms with zero platform-specific setup by the user.
