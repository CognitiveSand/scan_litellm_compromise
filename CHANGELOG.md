# Changelog

## 0.7.0 — 2026-04-01

### Performance
- **Root deduplication at source** — `build_search_roots()` now removes subdirectory overlaps before returning. On Linux, `/home/me` was a subtree of `/home` — every phase walked the user's home directory twice. Eliminates redundant walks across all phases.
- **IOC walk pruning** — `_scan_walk_files` now skips `.git`, `node_modules`, `__pycache__`, and other unproductive directories. Previously walked into `node_modules` trees (100k+ entries) searching for `.pth` files that cannot exist there.
- **Ecosystem plugin caching** — `get_ecosystem()` returns cached instances. For npm, avoids re-running `npm root -g` (~300ms) per threat. Search roots are also cached per ecosystem in the orchestrator.
- **String-based file dedup** — Source scanner uses `str(file_path)` instead of `Path.resolve()` for deduplication. Eliminates ~50k `realpath()` syscalls on large codebases. Safe because roots are pre-deduplicated.

### Added
- 10 new tests (root dedup, IOC pruning, ecosystem cache). 286 tests total.

## 0.6.1 — 2026-04-01

### Fixed
- **pnpm phantom dependency detection** — `pnpm-lock.yaml` is now parsed for phantom deps using line-anchored regex covering both v6 (`/name@version:`) and v9 (`name@version:`) key formats. Previously silently skipped.
- **Stale README example** — removed orphaned "Scan only a specific project directory" comment left over from `--scan-path` removal.

### Added
- **Fast-path documented** in README Limitations: files not containing the package name are skipped entirely before line-by-line scanning.
- 7 new pnpm phantom dep tests (v6, v9, not-found, missing file, dedup, full walk). 276 tests total.

## 0.6.0 — 2026-04-01

### Added
- **Renamed to `scan-supply-chain`** — ecosystem-neutral package name on PyPI. `scan-litellm` CLI alias kept for backward compatibility.
- **17 user stories** in `docs/stories/` covering both personas (Alice: SecOps, Bob: junior employee).
- **Project requirements document** (`docs/project_requirements.md`) — 33 functional requirements, 16 non-functional requirements, INCOSE compliance checklist, full traceability matrix.
- **`@req` traceability markers** on all 270 tests mapping to FRs and NFRs.
- **42 new tests** closing all FR coverage gaps: C2 port matching (FR-15), npm lockfile structural parsing (FR-17), PyPI phantom deps (FR-18), non-TTY ANSI output (FR-27), Windows Registry/Tasks (FR-28/FR-29), CLI alias and packaging (FR-33, NFR-01, NFR-12).

### Changed
- **`--scan-path` removed** — a scoped scan could produce misleading "clean" verdicts by missing system-wide IOCs. The scanner now always inspects all known locations.
- **Test coverage: 33/33 FRs, 5 NFRs** — zero gaps.

## 0.5.0 — 2026-04-01

### Fixed (from critique review)
- **Search-root consistency** — Discovery, IOC scanning, and source scanning now all use the same augmented search roots (conda, pipx, nvm, global npm). Previously, IOC phases missed locations that discovery could find. Roots are computed once and passed to every phase.
- **`--scan-path` fails fast** — Exits with error code 2 if path does not exist or is not a directory. Previously, a typo would silently produce an empty "clean" scan.
- **C2 port matching** — When threat profiles declare ports (e.g., axios C2 on port 8000), the network scanner matches `ip:port` in socket output instead of bare IP substring.
- **Structural npm lockfile parsing** — `package-lock.json` is now parsed as JSON (checks `packages` and `dependencies` keys) instead of raw substring search. `yarn.lock` uses line-anchored matching. Reduces false positives and catches resolved phantom dependency versions.
- **PyPI publish gated on CI** — Publish job now requires all test/lint/typecheck/build jobs to pass. Previously, the publish workflow ran independently of CI on release events.
- **Changelog hygiene** — Added missing entries for v0.4.1–v0.4.3.

### Added
- **Release script** (`release.py`) — Single command to bump version, run pre-flight checks (tests, ruff, mypy), verify changelog, commit, tag, push, and create GitHub release. Prevents version desync between `pyproject.toml` and `__init__.py`.
- **`search_roots.py`** — Shared module for computing augmented search roots (single source of truth).

### Changed
- Unified CI workflow — `ci.yml` now handles test, lint, typecheck, build, and publish (was split across two workflows).
- `discovery.py`, `ioc_scanner.py`, `source_scanner.py` — Accept pre-computed roots instead of computing their own.

## 0.4.3 — 2026-04-01

### Added
- mypy type checking in CI pipeline.
- `[tool.mypy]` configuration in `pyproject.toml`.

## 0.4.2 — 2026-04-01

### Added
- GitHub Actions CI workflow: test matrix (3.11/3.12/3.13 x Ubuntu/macOS/Windows), ruff lint+format, build verification.
- Applied ruff auto-formatting across all source and test files.

## 0.4.1 — 2026-04-01

### Added
- `__version__` displayed in banner and `--list-threats` output.
- Loaded threat profiles listed at startup with ecosystem, package, and compromised versions.

## 0.4.0 — 2026-04-01

### Added
- **Generic threat library** — Scanner is now data-driven via TOML threat profiles. Users can add custom threats by dropping `.toml` files into `~/.config/scan-supply-chain/threats/` (Linux/macOS) or `%LOCALAPPDATA%\scan-supply-chain\threats\` (Windows).
- **npm ecosystem support** — New `NpmPlugin` discovers packages in `node_modules/`, reads `package.json` versions, matches JS/TS import patterns (`require()`, `import`), and detects phantom dependencies.
- **Axios threat profile** (`axios-2026-03.toml`) — Detects the March 31, 2026 axios npm supply chain attack (BlueNoroff/UNC1069): compromised versions 1.14.1 and 0.30.4, phantom dependency `plain-crypto-js`, cross-platform RAT payloads, C2 at `sfrclak.com`.
- **Multi-threat scanning** — `--all` is the default; the scanner checks all known threats in a single run with per-threat reports.
- **`--threat ID`** — Scan for a specific threat only.
- **`--threat-file PATH`** — Load a custom threat profile from a TOML file.
- **`--list-threats`** — List all available threat profiles.
- **Phantom dependency detection** — Finds npm/PyPI packages that should not exist (e.g., `plain-crypto-js` injected by the axios attack).
- **SHA-256 hash verification** — Walk-file IOCs can optionally specify SHA-256 hashes to reduce false positives.

### Changed
- **Architecture refactored** — Three orthogonal axes: Platform (OS) × Ecosystem (PyPI/npm) × Threat (TOML profile). All attack-specific constants moved from code to threat profiles.
- **PlatformPolicy slimmed** — IOC paths, persistence paths, and remediation steps moved to threat profiles. Platform policies now contain only OS infrastructure (search roots, network commands).
- **`config.py` simplified** — Only generic skip-dir constants remain; all package-specific patterns removed.
- **`models.py` decoupled** — `ScanResults` accepts `compromised_versions` parameter instead of importing hardcoded constants.
- **Requires Python >= 3.11** (was >= 3.10) — Uses `tomllib` from the standard library for zero-dependency TOML parsing.
- **Test suite updated** — 230 tests covering both PyPI and npm ecosystems, threat profile loading, and multi-threat scanning.

## 0.3.2 — 2026-03-29

### Fixed
- Fix crash on Windows when `netstat -ano` output contains bytes not decodable by `cp1252`. Now decodes raw bytes with `errors="replace"` instead of relying on `text=True`.

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
