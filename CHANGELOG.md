# Changelog

## 0.3.1 — 2026-03-29

### Fixed
- Improved Quick Start with clear install instructions for Linux, macOS, and Windows.
- Added PEP 668 workaround guidance (pipx / venv) for modern Linux distributions.
- Added PyPI publish workflow via GitHub Actions trusted publisher (OIDC).

## 0.3.0 — 2026-03-29

### Added
- **`--scan-path DIR` flag** — Restrict Phase 1 (metadata discovery) and Phase 4 (source/config scanning) to a specific directory instead of walking the entire filesystem. Phase 3 IOC checks still run system-wide. Useful for incident responders targeting a known project.
- **`--resolve-c2` flag** — Opt-in live DNS resolution for C2 domains (`models.litellm.cloud`, `checkmarx.zone`). Off by default because the domains are attacker-controlled; DNS queries could alert the attacker or trigger your own security monitoring.
- **Hardcoded C2 known IPs** — The scanner now ships known IPs for C2 domains (`46.151.182.203` for `models.litellm.cloud`, `83.142.209.11` for `checkmarx.zone`, both AS205759 / Ghosty Networks LLC). Network connection checks use these by default with no DNS queries.
- **macOS (Darwin) platform support** — New `DarwinPolicy` with macOS-correct paths (`/Users`, `/opt/homebrew`, `/Library`), `lsof -i -P -n` for network checks, and macOS-appropriate remediation guidance. The malware's credential theft and `.pth` backdoor work on macOS; the systemd persistence is inert. **Note:** macOS support has not been tested on real hardware.
- **`--help` flag** — CLI argument parsing via `argparse` replaces ad-hoc `sys.argv` checks.
- **Test suite** — 299 pytest tests covering models, regex patterns, source pattern matching, metadata discovery, version extraction, file scanning, IOC detection, report formatting, CLI argument parsing, and all three platform policies.

## 0.2.2 — 2026-03-26

### Fixed
- Removed dead code and fixed Python 3.10/3.11 compatibility.

## 0.2.1 — 2026-03-25

### Added
- Filesystem-based metadata scanning (replaces subprocess version checking).
- `run_scan.bat` double-click launcher for Windows.

### Fixed
- Recommend `py` launcher on Windows to avoid DLL errors.

## 0.1.0 — 2026-03-25

### Added
- Initial release: 5-phase scan pipeline.
- Linux and Windows support via Strategy pattern.
- Detection of compromised litellm versions (v1.82.7, v1.82.8).
- IOC artifact scanning: `litellm_init.pth`, sysmon persistence, temp staging files, C2 network connections, Kubernetes malicious pods.
- Source and config file scanning for litellm references with pinned version flagging.
- Windows-specific checks: Registry Run keys, Scheduled Tasks.
