# Project Requirements — Supply Chain Compromise Scanner

## 1. Purpose

This document defines the functional and non-functional requirements for the Supply Chain Compromise Scanner (`scan-supply-chain`), a data-driven tool that detects indicators of compromise from known PyPI and npm supply chain attacks.

## 2. Scope

### 2.1 In Scope

- Detection of compromised package versions (PyPI, npm)
- Detection of IOC artifacts (files, persistence mechanisms, network connections, phantom dependencies, K8s pods)
- User-extensible threat library via TOML profiles
- Cross-platform support (Linux, macOS, Windows)
- CLI interface for manual and CI/CD use
- Remediation guidance generation

### 2.2 Language & Platform

| Attribute | Value |
|---|---|
| Language | Python 3.11+ |
| Dependencies | Standard library only (zero external deps) |
| Platforms | Linux, macOS, Windows 10/11 |
| Package format | PyPI (sdist + wheel) |
| Test framework | pytest |
| Linter | ruff |
| Type checker | mypy |

### 2.3 Out of Scope

- Scanning Docker/container image layers
- Scanning remote systems or CI/CD runner caches
- Decryption of exfiltrated data
- Automated remediation (file deletion, credential rotation)
- Real-time monitoring or daemon mode

## 3. Personas

| Persona | Role | Context |
|---|---|---|
| **Alice** | Experienced SecOps engineer | Leads incident response, writes custom threat profiles, manages fleet tooling, responsible for K8s clusters and CI/CD pipelines |
| **Bob** | Junior employee | Received a security advisory, needs to check his workstation, follows step-by-step remediation guidance |

## 4. User Stories

See [`docs/stories/`](stories/) for the full set of 17 user stories. Summary:

| ID | Title | Persona | Priority |
|---|---|---|---|
| US-01 | Default scan (all threats) | Bob | Must Have |
| US-02 | Scan specific threat | Alice | Must Have |
| US-03 | List available threats | Both | Must Have |
| US-04 | Custom threat file | Alice | Must Have |
| US-05 | User-local threat library | Alice | Should Have |
| US-06 | Detect compromised version | Both | Must Have |
| US-07 | Detect IOC artifacts | Alice | Must Have |
| US-08 | Detect C2 connections | Alice | Must Have |
| US-09 | Detect phantom dependencies | Alice | Must Have |
| US-10 | K8s lateral movement | Alice | Should Have |
| US-11 | Source & config scanning | Both | Must Have |
| US-12 | Remediation guidance | Bob | Must Have |
| US-13 | Cross-platform support | Both | Must Have |
| US-14 | CI/CD integration | Alice | Should Have |
| US-15 | Opt-in C2 DNS resolution | Alice | Nice to Have |
| US-16 | Windows persistence checks | Alice | Should Have |
| US-17 | Release process safety | Alice | Should Have |

## 5. Functional Requirements

| ID | Title | Description | Source(s) | Priority | Verification |
|---|---|---|---|---|---|
| FR-01 | Multi-threat default scan | The scanner scans all built-in and user-defined threat profiles when invoked with no flags. | US-01 | Must | Test: invoke with no args, verify all profiles run and report sections appear. |
| FR-02 | Single-threat selection | The scanner accepts `--threat <ID>` and runs only the matching profile. It exits with code 2 and an actionable error when the ID is unknown. | US-02 | Must | Test: invoke with valid and invalid IDs, verify correct behavior and exit codes. |
| FR-03 | Threat profile listing | `--list-threats` prints all available profiles (id, name, ecosystem, package, compromised versions, date) and exits with code 0. | US-03 | Must | Test: invoke `--list-threats`, verify output contains all built-in profiles. |
| FR-04 | Custom threat file loading | `--threat-file <PATH>` loads a TOML file and runs its pipeline. The scanner exits with code 2 when the file is missing or malformed. | US-04 | Must | Test: invoke with valid TOML, missing file, and malformed TOML. |
| FR-05 | User-local threat directory | TOML files in the platform-specific user config directory are loaded automatically and merged with built-in profiles. Same-id user profiles override built-in. | US-05 | Should | Test: place a TOML in the user dir, verify it appears in `--list-threats` and overrides a built-in. |
| FR-06 | PyPI package discovery | The scanner finds PyPI packages by walking filesystem for `{package}-{version}.dist-info` and `{package}-{version}.egg-info` directories. | US-06 | Must | Test: create mock dist-info in tmp_path, verify discovery. |
| FR-07 | npm package discovery | The scanner finds npm packages by walking filesystem for `node_modules/{package}/package.json`. | US-06 | Must | Test: create mock node_modules in tmp_path, verify discovery. |
| FR-08 | PyPI version extraction | The scanner reads the version from `METADATA` or `PKG-INFO` files, falling back to directory name parsing. | US-06 | Must | Test: create metadata files with various formats, verify correct version extraction. |
| FR-09 | npm version extraction | The scanner reads the version from `package.json`'s `version` field. | US-06 | Must | Test: create package.json with and without version field. |
| FR-10 | Compromised version flagging | Installed versions that match the threat profile's `compromised` set are flagged in the output and contribute to a non-zero exit code. | US-06 | Must | Test: install mock compromised and safe versions, verify flagging and exit code. |
| FR-11 | Walk-file IOC detection | The scanner recursively searches computed roots for filenames declared in `ioc.walk_files`, with optional SHA-256 hash verification. | US-07 | Must | Test: place a target file in tmp_path, verify detection with and without hash match. |
| FR-12 | Known-path IOC detection | The scanner checks platform-expanded absolute paths declared in `ioc.known_paths` for existence. | US-07 | Must | Test: create files at known paths, verify detection. |
| FR-13 | Consistent search roots | All phases (discovery, IOC walk, phantom deps, source scan) use the same augmented root set (platform roots + conda + pipx + ecosystem extras + $HOME). | US-07 | Must | Test: verify `build_search_roots` output is passed to every phase. |
| FR-14 | C2 connection detection (default) | The scanner matches active TCP connections against hardcoded known IPs from the threat profile using the platform-appropriate network tool. No DNS queries are made by default. | US-08 | Must | Test: mock network tool output containing a known IP, verify IOC reported. |
| FR-15 | C2 port matching | When `c2.ports` is non-empty in the threat profile, the scanner matches `ip:port` in network tool output instead of bare IP. | US-08 | Must | Test: mock output with IP on wrong port, verify no match; correct port, verify match. |
| FR-16 | C2 DNS resolution opt-in | `--resolve-c2` performs `gethostbyname()` on C2 domains and adds resolved IPs to the match set. A visible warning is printed. DNS failure does not prevent the scan. | US-15 | Nice | Test: mock DNS resolution, verify IPs added; mock failure, verify scan continues. |
| FR-17 | Phantom dependency detection (npm) | The scanner detects phantom npm packages by checking `node_modules/` directories and structurally parsing `package-lock.json` (JSON) and `yarn.lock` (line-anchored). | US-09 | Must | Test: create mock node_modules with phantom dep and lockfile, verify detection. |
| FR-18 | Phantom dependency detection (PyPI) | The scanner detects phantom PyPI packages by checking for their `dist-info`/`egg-info` in `site-packages/`. | US-09 | Must | Test: create mock dist-info for a phantom dep, verify detection. |
| FR-19 | Kubernetes pod inspection | When `kubectl` is available and `ioc.kubernetes.pod_patterns` is non-empty, the scanner queries pods in the specified namespace and flags matches. | US-10 | Should | Test: mock kubectl output with suspicious pods, verify IOC reported. |
| FR-20 | Source file scanning | The scanner finds imports/usage of the target package in source files (`.py` for PyPI; `.js`/`.ts`/`.mjs`/`.cjs`/`.jsx`/`.tsx` for npm) using ecosystem-specific regex patterns. | US-11 | Must | Test: create source files with and without imports, verify detection. |
| FR-21 | Config file scanning | The scanner finds package references in dependency config files (`pyproject.toml`, `requirements*.txt`, `package.json`, `package-lock.json`, `yarn.lock`, etc.). | US-11 | Must | Test: create config files with package references, verify detection. |
| FR-22 | Pinned version flagging | Config files that pin to a compromised version are flagged with a visible warning and listed in remediation output. | US-11, US-12 | Must | Test: create requirements.txt with pinned compromised version, verify flagging. |
| FR-23 | Remediation step generation | When compromise is detected, the report includes numbered, platform-specific remediation steps sourced from the threat profile. | US-12 | Must | Test: trigger compromise, verify remediation output includes all expected steps. |
| FR-24 | Advisory URL display | When the threat profile includes an `advisory` URL, it is shown at the end of remediation output. | US-12 | Must | Test: verify advisory URL appears in compromised report. |
| FR-25 | Platform auto-detection | The scanner detects the OS at startup and selects the correct search roots, network tool, and path expansion strategy. | US-13 | Must | Test: mock `sys.platform`, verify correct policy is returned. |
| FR-26 | Exit code semantics | Exit 0 = clean, exit 1 = compromise detected, exit 2 = argument/config error. | US-01, US-14 | Must | Test: verify exit codes for each scenario. |
| FR-27 | Non-TTY output | ANSI escape codes are disabled when stdout is not a TTY. | US-14 | Should | Test: verify `_enable_ansi()` returns False when `isatty()` is False. |
| FR-28 | Windows Registry checks | On Windows, the scanner queries `HKCU` and `HKLM` Run keys for keywords from the threat profile. | US-16 | Should | Test: mock `reg query` output, verify IOC flagged. |
| FR-29 | Windows Task Scheduler checks | On Windows, the scanner queries `schtasks` for keywords from the threat profile. | US-16 | Should | Test: mock `schtasks` output, verify IOC flagged. |
| FR-30 | Scanner self-exclusion | The scanner's own source files are excluded from Phase 4 source scanning results. | US-11 | Must | Test: verify scanner directory is filtered from results. |
| FR-31 | Version display | The scanner version is shown in the startup banner and in `--list-threats` output. | US-01, US-03 | Must | Test: verify `__version__` appears in output. |
| FR-32 | Mutual exclusivity of threat selection | `--threat`, `--threat-file`, and `--list-threats` are mutually exclusive. | US-02, US-04 | Must | Test: invoke with two exclusive flags, verify argparse error. |
| FR-33 | Backward-compatible CLI alias | The `scan-litellm` command is installed as an alias that invokes the same entry point as `scan-supply-chain`. | US-01 | Should | Test: verify both entry points are defined in pyproject.toml. |

## 6. Non-Functional Requirements

| ID | Title | Description | Category | Source(s) | Priority | Verification |
|---|---|---|---|---|---|---|
| NFR-01 | Zero external dependencies | The scanner has no runtime dependencies beyond the Python 3.11+ standard library. | Maint | US-14, US-13 | Must | Test: verify `pyproject.toml` has no `[project.dependencies]` section. Verify import succeeds in a clean venv with no pip packages. |
| NFR-02 | Read-only operation | The scanner never creates, modifies, or deletes files on the scanned system. All output goes to stdout/stderr. | Sec | US-01, US-12 | Must | Audit: review all source for file write operations. Test: run scan, verify no filesystem changes via snapshot diff. |
| NFR-03 | Graceful permission handling | Permission errors during filesystem walks or subprocess calls are logged at debug level and do not crash the scanner or alter the verdict. | Usab | US-01, US-13 | Must | Test: mock `PermissionError` on `os.walk` and `Path.exists`, verify scan completes. |
| NFR-04 | Subprocess timeout safety | All subprocess calls (`ss`, `lsof`, `netstat`, `kubectl`, `reg`, `schtasks`) have explicit timeouts (5–15 seconds). Timeout expiry is handled gracefully. | Sec | US-08, US-10, US-16 | Must | Test: mock `TimeoutExpired`, verify scan continues without crash. |
| NFR-05 | No outbound network by default | The scanner makes no outbound network connections unless `--resolve-c2` is explicitly passed. | Sec | US-08, US-15 | Must | Test: run scan without `--resolve-c2`, verify no `socket.gethostbyname` calls. |
| NFR-06 | Cross-platform portability | The scanner runs correctly on Linux, macOS, and Windows without platform-specific installation steps. | Port | US-13 | Must | CI: test matrix passes on ubuntu-latest, macos-latest, windows-latest with Python 3.11, 3.12, 3.13. |
| NFR-07 | Python version support | The scanner supports Python 3.11, 3.12, and 3.13. | Port | US-13 | Must | CI: test matrix covers all three versions. |
| NFR-08 | Threat profile forward compatibility | Unrecognized fields in TOML threat profiles are silently ignored, allowing newer profiles to be used with older scanner versions without error. | Maint | US-04, US-05 | Should | Test: load a TOML with extra unknown fields, verify no error. |
| NFR-09 | Malformed profile resilience | A malformed TOML file in the user-local threat directory produces a warning but does not prevent other profiles from loading. | Usab | US-05 | Must | Test: place an invalid TOML alongside a valid one, verify valid one loads. |
| NFR-10 | Terminal compatibility | Output is readable on terminals with and without ANSI color support. Colors are disabled when stdout is not a TTY. | Usab | US-14 | Should | Test: verify `_enable_ansi()` returns False when not a TTY. Visual review on Windows cmd.exe. |
| NFR-11 | Deterministic exit codes | Exit codes follow a strict contract: 0 = clean, 1 = compromised, 2 = usage error. No other exit codes are produced. | Usab | US-14 | Must | Test: trigger all three scenarios, assert exit codes. |
| NFR-12 | Version consistency | `__version__` in `__init__.py`, `version` in `pyproject.toml`, and the git tag all match for every release. | Maint | US-17 | Must | CI: `build` job verifies tag matches `__version__` on tagged builds. Release script updates both files atomically. |
| NFR-13 | CI-gated publishing | The PyPI publish job runs only after test, lint, typecheck, and build jobs all pass. | Maint | US-17 | Must | CI: publish job declares `needs: [test, lint, typecheck, build]`. |
| NFR-14 | Scan completeness | All scan phases use the same augmented search roots. No phase inspects a narrower set of directories than package discovery. | Sec | US-07 | Must | Test: verify IOC scanner and source scanner receive the same roots as discovery. |
| NFR-15 | File size tolerance | The source scanner reads files in full but applies a fast-path string check (`package_name not in text`) to skip irrelevant files before line-by-line scanning. | Perf | US-11 | Should | Benchmark: verify scan of a 10 MB Python file completes without excessive memory. |
| NFR-16 | Threat profile schema stability | The TOML schema for threat profiles is documented and backward-compatible across minor versions. | Maint | US-04, US-05 | Should | Docs: README contains a complete TOML schema example. Older profiles continue to load after scanner updates. |

## 7. INCOSE Compliance Checklist

| Criterion | Status | Notes |
|---|---|---|
| **Necessary** | Pass | Every FR traces to at least one user story. Every NFR traces to at least one FR or US. |
| **Appropriate** | Pass | All requirements are achievable within the current Python 3.11+ stdlib-only architecture. |
| **Unambiguous** | Pass | Requirements specify observable behaviors and exit codes, not implementation mechanisms. |
| **Complete** | Pass | Each requirement is self-contained. Platform variations are enumerated where applicable. |
| **Singular** | Pass | Each FR describes one capability. Compound behaviors are split into separate FRs (e.g., FR-06/FR-07 for PyPI/npm discovery). |
| **Feasible** | Pass | All requirements are implemented and passing in the current codebase. No speculative requirements. |
| **Verifiable** | Pass | Every FR has a verification column with a concrete test strategy. NFRs have either test or audit verification. |
| **Correct** | Pass | Requirements derive from real-world incidents (LiteLLM, axios) and the critique review findings. |
| **Conforming** | Pass | Follows project conventions: pytest for tests, ruff for formatting, mypy for types. |

## 8. Traceability

### 8.1 `@req` Marker Quick Reference

| Language | Marker syntax | File extensions scanned |
|---|---|---|
| Python | `# @req FR-01` | `.py` |

### 8.2 Coverage Summary

Traceability markers (`# @req FR-XX`) should be added to implementation and test files as requirements are verified. Run tests and grep for `@req` to generate coverage:

```bash
grep -rn "@req" scan_supply_chain/ tests/ | sort
```

### 8.3 User Story → FR Traceability Matrix

| US | Functional Requirements |
|---|---|
| US-01 | FR-01, FR-26, FR-31 |
| US-02 | FR-02, FR-32 |
| US-03 | FR-03, FR-31 |
| US-04 | FR-04, FR-32 |
| US-05 | FR-05 |
| US-06 | FR-06, FR-07, FR-08, FR-09, FR-10 |
| US-07 | FR-11, FR-12, FR-13 |
| US-08 | FR-14, FR-15 |
| US-09 | FR-17, FR-18 |
| US-10 | FR-19 |
| US-11 | FR-20, FR-21, FR-22, FR-30 |
| US-12 | FR-23, FR-24 |
| US-13 | FR-25, FR-27 |
| US-14 | FR-26, FR-27 |
| US-15 | FR-16 |
| US-16 | FR-28, FR-29 |
| US-17 | FR-33 (alias), NFR-12, NFR-13 |
