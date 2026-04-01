# US-05: Maintain a user-local threat library

## Persona

Alice

## User Story

As a SecOps engineer managing multiple teams, I want to drop TOML files into a well-known config directory so that custom threat profiles are automatically included in every scan without passing `--threat-file` each time.

## Priority

Should Have

## Acceptance Criteria

- [ ] AC-1: On Linux/macOS, TOML files in `~/.config/scan-supply-chain/threats/` (or `$XDG_CONFIG_HOME/scan-supply-chain/threats/`) are loaded automatically.
- [ ] AC-2: On Windows, TOML files in `%LOCALAPPDATA%\scan-supply-chain\threats\` are loaded automatically.
- [ ] AC-3: A user-local profile with the same `id` as a built-in profile replaces the built-in.
- [ ] AC-4: Malformed TOML files in the user directory are skipped with a warning; they do not prevent other profiles from loading.
- [ ] AC-5: User-local profiles appear in `--list-threats` output.

## Notes

This enables Alice to distribute org-specific threat profiles across workstations via config management tools.
