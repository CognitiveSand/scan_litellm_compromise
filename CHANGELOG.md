# Changelog

## Unreleased

### Added
- **`branch_name_regexes`** in `[ioc.git_artifacts]` — symmetric to `workflow_name_regexes`. Lets a profile match generated branch names that carry a timestamp or other variable component, e.g. Sha1-Hulud 2.0's `add-linter-workflow-<Date.now()>` dead-drop branches. Matches are deduplicated against the literal `branch_names` set so a branch covered by both forms emits a single finding. The `sha1-hulud-2025-11` profile now uses this to catch the 2.0-specific branch pattern.
- **Sha1-Hulud 2.0 threat profile** (`sha1-hulud-2025-11`) — November 2025 wave, anchored on `posthog-node` (4.18.1 / 5.11.3 / 5.13.3). Walk-files for `bun_environment.js` (three known SHA-256s) and `setup_bun.js` (one SHA-256). Adds `Sha1-Hulud: The Second Coming` / `Shai-Hulud: The Continued Coming` repo descriptions, `SHA1HULUD` self-hosted-runner keyword, and the Docker-sudoers privilege-escalation check in remediation guidance.
- **Mini Shai-Hulud threat profile** (`mini-shai-hulud-2026-05`) — TanStack wave, anchored on `@tanstack/react-router` (1.169.5 / 1.169.8). Walk-files for `router_init.js` and `tanstack_runner.js` (hash-verified). Adds the `git-tanstack.com` typosquat exfil domain, the `Shai-Hulud: Here We Go Again` repo description, and the campaign-unique PBKDF2 salt `svksjrhjkcejg` as a persistence keyword. Remediation includes auditing Claude Code / VS Code extension manifests for the post-reboot persistence hooks the worm installs.
- **Shai-Hulud threat profile** (`shai-hulud-2025-09`) — covers the September 2025 npm worm wave anchored on `@ctrl/tinycolor@4.1.1` / `4.1.2`. Detects the `bundle.js` payload by SHA-256, the `truffleSecrets.json` / `cloud.json` / `actionsSecrets.json` / `contents.json` / `environment.json` / `format.json` staging dumps under `/tmp` (or `%TEMP%`), the `shai-hulud-workflow.yml` / `discussion.yaml` / `formatter_*.yml` backdoor workflows, the `Shai-Hulud` / `Sha1-Hulud` repo descriptions, the Dune-universe branch fingerprints, the `claude@users.noreply.github.com` commit author, and the `gh-token-monitor` host-side persistence daemon used by later waves. Sha1-Hulud 2.0 (Nov 2025) and Mini Shai-Hulud (May 2026) are not yet shipped as separate profiles.
- **Anti-worm pre-pass** — single filesystem walk before the per-threat pipeline that discovers local git repositories and matches them against worm-class indicators aggregated from every loaded threat profile. Detects Shai-Hulud-style campaigns whose footprint is in `.git/description`, `.github/workflows/*.y[a]ml`, local branch names, and recent commit author emails. New modules: `git_repo_index.py`, `anti_worm_scanner.py`. New `[ioc.git_artifacts]` block in threat profiles (workflow filenames, regex patterns, branch names, commit author emails, repo descriptions). Per-repo corroboration scorer: workflow / description matches alone are HIGH; branch / author matches alone are LOW and escalate to HIGH when combined.
- **`[ioc.persistence_keywords].terms`** — extra terms (e.g. standalone daemon names like `gh-token-monitor`) that the persistence scanner matches in addition to the package name. Catches payloads whose persistence artifacts don't carry the parent package's name.
- New `FindingCategory.GIT_ARTIFACT`; scoring rules updated so a git artifact alone yields MEDIUM and version + git artifact yields HIGH.

### Changed
- `search_roots._deduplicate_roots` renamed to `deduplicate_roots` (now used by the anti-worm pre-pass to union ecosystem roots).

## 0.8.2 — 2026-04-02

### Changed
- **README overhaul** — Refined existing sections for clarity. Added detailed "How It Works" section explaining each pipeline phase, sub-scanner, and design rationale.

## 0.8.1 — 2026-04-02

### Changed
- **DRY: Platform base class** — `BasePlatformPolicy` provides default `home_conda_dirs()` and `_first_existing_dir()` helper. Linux and Darwin inherit defaults; Windows overrides casing.
- **DRY: Cache scanner** — Three near-identical cache walkers (`pip`, `npm`, `pnpm`) unified into `_scan_cache_dir()` with configurable search targets.
- **DRY: Subprocess helper** — New `subprocess_utils.run_safe()` replaces 4 identical `subprocess.run` try/except blocks across `persistence_scanner`, `ioc_windows`.
- **DRY: File read helper** — New `config.read_if_contains()` replaces repeated read-then-check patterns in `persistence_scanner`, `history_scanner`.
- **DRY: Scanner boilerplate** — New `scanner_check()` context manager combines `print_check_header()` + `track_findings()` into a single call.
- **DRY: Inlined wrappers** — Removed trivial `_add_persistence()` and `_add_cache_finding()` one-liner delegates.
- **DRY: Test helpers** — Shared `mock_run_safe`, `mock_subprocess_run`, `mock_tool_available`, `scan_results` fixture in `conftest.py`.
- Named magic constant `_SEPARATOR_WIDTH` in `formatting.py`.
- 355 tests, all passing.

## 0.8.0 — 2026-04-01

### Added
- **Evidence scoring** — 4-tier confidence (LOW/MEDIUM/HIGH/CRITICAL) replaces binary clean/compromised verdict. New `Confidence` enum, `FindingCategory` enum, `Finding` dataclass, and `scoring.py` module.
- **AST-based Python detection** — `ast_scanner.py` uses `ast.parse()` to find real imports and attribute access. Eliminates false positives from string literals, regex patterns, and comments. Falls back to regex on `SyntaxError`.
- **Structured socket parsing** — `network_scanner.py` parses `ss`/`lsof` output into typed `ConnectionRecord` structs. C2 detection reports process name, PID, and executable path (Linux `/proc` enrichment).
- **Persistence scanner** — `persistence_scanner.py` checks crontab, shell rc files, systemd user services, XDG autostart, `/tmp` scripts, and macOS LaunchAgents.
- **Cache scanner** — `cache_scanner.py` checks pip, npm, and pnpm caches for traces of compromised packages. Ecosystem-gated.
- **History scanner** — `history_scanner.py` searches `.bash_history` and `.zsh_history` for `pip install`/`npm install`/`yarn add`/`pnpm add` commands.
- **Lockfile version extraction** — `yarn.lock` and `pnpm-lock.yaml` phantom dep reports now include the resolved version (e.g., `phantom:plain-crypto-js@4.2.1`).
- 62 new tests. **348 tests total.**

### Changed
- C2 connection check uses structured parsing instead of IP substring matching.
- Python source scanning uses AST first, regex as fallback (no change for JS/TS).
- `ScanResults` gains a `findings` list alongside existing `iocs` (backward compatible).

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
