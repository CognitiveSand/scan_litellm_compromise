# Supply Chain Compromise Scanner

A data-driven scanner that detects indicators of compromise (IOCs) from known **PyPI and npm supply chain attacks**. Threat profiles are defined in TOML files and are user-extensible — add your own without writing code.

**Built-in threat profiles:**

| ID | Package | Ecosystem | Compromised Versions | Date |
|----|---------|-----------|---------------------|------|
| `shai-hulud-2025-09` | @ctrl/tinycolor (anchor) | npm | 4.1.1, 4.1.2 | 2025-09-15 |
| `sha1-hulud-2025-11` | posthog-node (anchor) | npm | 4.18.1, 5.11.3, 5.13.3 | 2025-11-24 |
| `litellm-2026-03` | litellm | PyPI | 1.82.7, 1.82.8 | 2026-03-24 |
| `axios-2026-03` | axios | npm | 1.14.1, 0.30.4 | 2026-03-31 |
| `mini-shai-hulud-2026-05` | @tanstack/react-router (anchor) | npm | 1.169.5, 1.169.8 | 2026-05-11 |

> **No guarantees.** This tool searches for known artifacts of specific supply chain compromises. It does **not** guarantee detection of all malicious activity, nor does a clean scan prove your system was unaffected. Attackers may have removed traces, and the tool cannot detect secrets that have already been exfiltrated. Use this scanner as one input in your incident response — not as a definitive verdict.

## Quick Start

### Option A: Install from PyPI

**Linux / macOS:**

```bash
# Recommended — installs in an isolated environment
pipx install scan-supply-chain
scan-supply-chain
```

If you don't have pipx: `sudo apt install pipx` (Debian/Ubuntu) or `brew install pipx` (macOS).

Alternatively, using pip inside a virtual environment:

```bash
python3 -m venv /tmp/scanner && /tmp/scanner/bin/pip install scan-supply-chain
/tmp/scanner/bin/scan-supply-chain
```

> **Note:** `pip install` directly will fail on modern Linux distributions (Debian 12+, Ubuntu 23.04+, Fedora 38+) due to [PEP 668](https://peps.python.org/pep-0668/). Use `pipx` or a virtual environment instead.

> **Migrating?** The old package `scan-litellm-compromise` is still available but will not receive updates. The `scan-litellm` CLI alias is included in the new package for backward compatibility.

**Windows:**

```cmd
pip install scan-supply-chain
scan-supply-chain
```

Or using a virtual environment:

```cmd
py -m venv %TEMP%\scanner && %TEMP%\scanner\Scripts\pip install scan-supply-chain
%TEMP%\scanner\Scripts\scan-supply-chain
```

### Option B: Run from source (no install needed)

**Linux / macOS:**

```bash
git clone https://github.com/CognitiveSand/scan-supply-chain.git
cd scan-supply-chain
python3 run_scan.py
```

**Windows** — double-click **`run_scan.bat`**, or from a terminal:

```cmd
git clone https://github.com/CognitiveSand/scan-supply-chain.git
cd scan-supply-chain
py run_scan.py
```

No dependencies required — uses only the Python 3.11+ standard library.

### Command-Line Options

| Flag | Description |
|------|-------------|
| *(no flags)* | **Scans all known threats** (default behavior). |
| `--threat ID` | Scan for a specific threat only (e.g. `--threat litellm-2026-03`). |
| `--threat-file PATH` | Load a custom threat profile from a TOML file. |
| `--list-threats` | List all available threat profiles and exit. |
| `--resolve-c2` | Enable live DNS queries to C2 domains (default: use known IPs only). |
| `--help` | Show usage information. |

> **Warning about `--resolve-c2`:** This flag causes the scanner to make live DNS queries to attacker-controlled domains. This carries real risks:
> - **Operational security:** Your DNS query is visible to the attacker's infrastructure.
> - **Network monitoring:** The queries may trigger alerts in your SIEM/IDS.
>
> **In most cases you do not need this flag.** The scanner ships hardcoded known IPs confirmed by multiple threat intelligence sources.

**Examples:**

```bash
# Scan for all known threats (default)
scan-supply-chain

# Scan for a specific threat only
scan-supply-chain --threat axios-2026-03

# List available threat profiles
scan-supply-chain --list-threats

# Use a custom threat profile
scan-supply-chain --threat-file ./my-threat.toml
```

## Threat Library

Threat profiles are TOML files that define everything about a specific supply chain attack: package name, ecosystem, compromised versions, C2 infrastructure, IOC file paths, and remediation steps.

### Built-in threats

Ship with the package in `scan_supply_chain/threats/`. Updated via `pip install --upgrade`.

### User-defined threats

Drop a `.toml` file into:
- **Linux/macOS:** `~/.config/scan-supply-chain/threats/`
- **Windows:** `%LOCALAPPDATA%\scan-supply-chain\threats\`

User profiles override built-in profiles with the same `id`.

### Writing a threat profile

Every section is validated against a known-key schema at load time. A typo
like `ecosytem = "npm"` raises `UnknownProfileKeyError` with the file
path and offending key — the scanner refuses to start on a malformed
profile rather than silently dropping the value. Same applies to invalid
regexes in `branch_name_regexes` / `workflow_name_regexes`: they fail
loud at load time, not at scan time.

```toml
[threat]
id          = "mypackage-2026-04"
name        = "MyPackage Supply Chain Attack"
date        = "2026-04-01"
ecosystem   = "pypi"          # "pypi" or "npm"
package     = "mypackage"
compromised = ["1.0.1"]
safe        = "1.0.0"
advisory    = "https://example.com/advisory"
description = "Description of what happened."

[c2]
domains = ["evil.example.com"]
ports   = []

[c2.ips]
"evil.example.com" = ["1.2.3.4"]

[[ioc.known_paths]]
description = "backdoor payload"
linux       = ["/tmp/backdoor.py"]
darwin      = ["/tmp/backdoor.py"]
windows     = ['%TEMP%\backdoor.exe']

[ioc.phantom_deps]
names = ["malicious-dep"]       # should NEVER exist

[ioc.kubernetes]
pod_patterns = []
namespace    = ""

[ioc.windows]
registry_keywords = []
schtask_keywords  = []

[ioc.persistence_keywords]
# Extra terms to match in crontab, shell rc, systemd/LaunchAgents/XDG
# autostart entries — useful for daemons whose name does not contain the
# package name (e.g. a standalone helper installed by the payload).
terms = []

[ioc.git_artifacts]
# Worm-class indicators that live in local git repositories. Consumed
# by the anti-worm pre-pass (single walk per scan, across all loaded
# threats). Workflow filenames and repo descriptions are independently
# HIGH-signal; branch names and commit author emails are LOW alone but
# escalate to HIGH when corroborated.
workflow_filenames    = []
workflow_name_regexes = []
branch_names          = []
branch_name_regexes   = []
commit_author_emails  = []
repo_descriptions     = []

[remediation]
rotate_secrets  = true
install_command = "pip install mypackage==1.0.0"

[remediation.remove_artifacts]
linux   = ["Remove /tmp/backdoor.py"]
darwin  = ["Remove /tmp/backdoor.py"]
windows = ['Remove %TEMP%\backdoor.exe']

[remediation.check_persistence]
linux   = ["Check crontab -l"]
darwin  = ["Check launchctl list"]
windows = ["Check Task Scheduler"]
```

## Video Overview

This scanner was inspired by [Fahd Mirza's video](https://www.youtube.com/watch?v=YoClPk7KqZc) highlighting the LiteLLM incident — thanks to him for bringing it to attention.

## Known Attacks

### Shai-Hulud npm Worm (September 2025, TeamPCP)

First successful self-propagating npm worm. ~500 packages compromised across multiple maintainers; `@ctrl/tinycolor` (~2M weekly downloads) was the most-cited anchor of the original wave.

- **Compromised versions:** `@ctrl/tinycolor@4.1.1` and `4.1.2` (others affected vary by maintainer).
- **Mechanism:** malicious `bundle.js` injected via npm `postinstall` runs TruffleHog against the build environment, harvests AWS/GCP/Azure/GitHub credentials, exfiltrates them to a `webhook.site` UUID URL, commits a backdoor GitHub Actions workflow under `.github/workflows/shai-hulud-workflow.yml` (and similar names), creates a public repository named `Shai-Hulud` under the victim's GitHub account containing the stolen secrets, then republishes infected versions of every other npm package the compromised maintainer owns.
- **Branch / commit fingerprints:** dead-drop branches are named after Dune-universe terms (`fremen`, `atreides`, `sandworm`, …); commits are authored as `claude@users.noreply.github.com`.

### Sha1-Hulud 2.0 npm Worm (November 24, 2025)

Second wave. ~800 npm packages compromised between 04:11 UTC and ~09:30 UTC including `posthog-node` (4.18.1, 5.11.3, 5.13.3), `posthog-js` (1.297.3), `@postman/tunnel-agent` (0.6.5–0.6.7), `@asyncapi/cli` (4.1.2, 4.1.3), `@zapier/zapier-sdk` (0.15.5–0.15.7), and `@ensdomains/*` packages.

- **Payload:** `setup_bun.js` drops a ~10 MB obfuscated `bun_environment.js` that runs TruffleHog against the build environment and exfiltrates the harvested credentials.
- **Repo descriptions:** `Sha1-Hulud: The Second Coming`, `Shai-Hulud: The Continued Coming`.
- **Persistence:** `gh-token-monitor` LaunchAgent / systemd daemon (polls GitHub every 60 s) and a self-hosted GitHub Actions runner named `SHA1HULUD`. Also injects entries into `/etc/sudoers` for Docker-based privilege escalation.

### Mini Shai-Hulud npm Worm — TanStack wave (May 11, 2026)

Third documented wave. 84 malicious npm package artifacts published across 42 `@tanstack/*` packages between 19:20 and 19:26 UTC, plus packages from Mistral AI, UiPath, Guardrails AI, and Squawk. First documented npm worm producing validly signed packages with **SLSA Build Level 3 provenance attestations** — the malicious versions were published through the projects' own GitHub Actions release pipelines using hijacked OIDC tokens.

- **Payload:** `router_init.js` embedded in each compromised package drops `tanstack_runner.js`, which reads GitHub Actions runner process memory to extract every secret in scope.
- **Exfiltration:** typosquat domain `git-tanstack.com`, Session messenger CDN, and GitHub GraphQL dead-drops.
- **Campaign marker:** the PBKDF2 salt `svksjrhjkcejg` is unique to this wave.
- **Repo description:** `Shai-Hulud: Here We Go Again`.
- **Persistence:** `gh-token-monitor` LaunchAgent / systemd daemon — if its token is revoked (40X), the daemon runs `rm -rf ~/`. Additionally installs hooks in Claude Code and VS Code that survive reboots.

### LiteLLM PyPI Compromise (March 24, 2026)

Two backdoored versions of the `litellm` Python package were published to PyPI:

- **v1.82.7** — malicious code injected into `proxy_server.py` (base64-encoded)
- **v1.82.8** — added a `litellm_init.pth` file that executes on every Python interpreter startup

Available for ~3 hours before PyPI quarantined them. LiteLLM has ~95 million monthly downloads. The attacker compromised BerriAI's PyPI token by poisoning the `aquasecurity/trivy-action` GitHub Action.

**Three-stage payload:** credential harvesting, AES-256+RSA-4096 encrypted exfiltration to C2, persistent backdoor polling every 50 minutes. If K8s credentials found, deploys privileged `node-setup-*` pods for lateral movement.

### Axios npm Compromise (March 31, 2026)

The `axios` npm package (100M weekly downloads) was compromised via maintainer account takeover attributed to North Korea's UNC1069/BlueNoroff:

- **v1.14.1** (tagged `latest`) and **v0.30.4** (tagged `legacy`)
- Injected phantom dependency `plain-crypto-js@4.2.1` with postinstall RAT dropper
- Cross-platform RAT payloads: PowerShell (Windows), compiled binary (macOS), Python script (Linux)
- Self-deleting dropper with double-layer obfuscation

Available for ~3 hours. C2 at `sfrclak.com:8000`.

## What This Scanner Detects

The scanner runs a **5-phase pipeline** for each threat profile. Every phase is described in detail in the [How It Works](#how-it-works) section at the end of this document. In short:

| Phase | Purpose |
|-------|---------|
| 1 — Discovery | Find every installation of the package across the filesystem |
| 2 — Version check | Read metadata to identify compromised versions |
| 3 — Evidence collection | Search for IOC artifacts, C2 connections, persistence, caches, and install history |
| 4 — Source & config scan | Find source files that import the package and dependency configs that pin it |
| 5 — Verdict & remediation | Compute a confidence tier and print actionable next steps |

### Evidence Scoring

Instead of a binary clean/compromised verdict, findings are scored into four confidence tiers:

| Tier | Meaning | Triggers |
|------|---------|----------|
| **CRITICAL** | Active compromise with live C2 | Compromised version + active C2 connection |
| **HIGH** | Strong compromise indicators | Compromised version + IOC file or phantom dependency |
| **MEDIUM** | Likely compromised | Compromised version alone, or persistence artifact |
| **LOW** | Circumstantial evidence | Source reference, cache trace, or install history only |

## Limitations

- **Cannot detect exfiltrated secrets.** Credential rotation is required regardless of scan results.
- **Artifacts may have been cleaned up.** Absence of IOC files does not prove the system was never compromised.
- **Does not inspect Docker image layers, CI/CD runner caches, or remote systems.**
- **Root-owned paths (`/root` on Linux) are excluded.**
- **Windows Registry scanning is best-effort.**
- **Broad filesystem walk by design.** The scanner walks system-wide search roots (e.g., `/home`, `/opt`, `/usr`) to maximize detection coverage. A fast-path filter skips files that don't contain the package name before line-by-line scanning, but the initial walk can be slow on machines with large filesystems. This is acceptable for incident response; it is not designed for continuous fleet monitoring.

## Platform Support

| Feature | Linux | macOS | Windows 10/11 |
|---------|-------|-------|---------------|
| Package detection | `/home`, `/opt`, `/usr`, `/srv`, `/var` | `/Users`, `/opt/homebrew`, `/usr/local`, `/Library` | `%USERPROFILE%`, `%APPDATA%`, `Program Files` |
| Conda/pipx/nvm detection | `/opt/conda`, `~/.local/share/pipx` | Homebrew Caskroom, `~/.local/share/pipx` | `%LOCALAPPDATA%\Miniconda3`, `%LOCALAPPDATA%\pipx` |
| Network (C2 detection) | `ss -tnp` with PID + `/proc` enrichment | `lsof -i -P -n` with PID | `netstat -ano` |
| Persistence scan | crontab, shell rc, systemd user, XDG autostart, `/tmp` | crontab, shell rc, LaunchAgents | Registry Run keys, Scheduled Tasks |
| Cache scan | `~/.cache/pip`, `~/.npm/_cacache`, pnpm store | Same (macOS pip path) | `%LOCALAPPDATA%\pip\Cache` |
| History scan | `.bash_history`, `.zsh_history` | Same | Same |
| Python detection | AST-based (no false positives from string literals) | Same | Same |
| ANSI terminal colors | Native | Native | Auto-enabled via Virtual Terminal Processing |

## If Compromise Is Detected

**Assume ALL secrets on the affected machine are compromised.** The scanner provides threat-specific remediation steps. General guidance:

1. **Rotate credentials immediately** — SSH keys, cloud credentials, API keys, database passwords, CI/CD tokens
2. **Remove malicious artifacts** — see scanner output for specific paths
3. **Fix the package** — install the safe version indicated by the scanner
4. **Update pinned versions** — check all dependency files for compromised version pins
5. **Block C2 domains** — at DNS/firewall level
6. **Audit cloud provider logs** — check for unauthorized API calls

## Advisories and References

### Shai-Hulud — September 2025 wave (`shai-hulud-2025-09`)

| ID | Source |
|----|--------|
| CISA Alert (2025-09-23) | [CISA](https://www.cisa.gov/news-events/alerts/2025/09/23/widespread-supply-chain-compromise-impacting-npm-ecosystem) |
| Unit 42 advisory | [Palo Alto Networks Unit 42](https://unit42.paloaltonetworks.com/npm-supply-chain-attack/) |

**Research:** [StepSecurity (Sept 2025)](https://www.stepsecurity.io/blog/ctrl-tinycolor-and-40-npm-packages-compromised), [Socket (Sept 2025)](https://socket.dev/blog/tinycolor-supply-chain-attack-affects-40-packages), [Trend Micro](https://www.trendmicro.com/en_us/research/25/i/npm-supply-chain-attack.html), [Phoenix Security](https://phoenix.security/npm-shai-hulud-tinycolor-compromise/), [Orca Security](https://orca.security/resources/blog/npm-malware-campaign-tinycolor/)

### Sha1-Hulud 2.0 — November 2025 wave (`sha1-hulud-2025-11`)

| ID | Source |
|----|--------|
| GHSA / PostHog disclosure | [PostHog issue #2633](https://github.com/PostHog/posthog-js/issues/2633) |
| Microsoft detection guidance | [Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2025/12/09/shai-hulud-2-0-guidance-for-detecting-investigating-and-defending-against-the-supply-chain-attack/) |

**Research:** [Wiz](https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack), [Netskope](https://www.netskope.com/blog/shai-hulud-2-0-aggressive-automated-one-of-fastest-spreading-npm-supply-chain-attacks-ever-observed), [PostHog post-mortem](https://posthog.com/blog/nov-24-shai-hulud-attack-post-mortem)

### Mini Shai-Hulud — May 2026 TanStack wave (`mini-shai-hulud-2026-05`)

| ID | Source |
|----|--------|
| GHSA-g7cv-rxg3-hmpx | [GitHub Advisory](https://github.com/advisories/GHSA-g7cv-rxg3-hmpx) |
| TanStack post-mortem | [TanStack blog](https://tanstack.com/blog/npm-supply-chain-compromise-postmortem) |

**Research:** [StepSecurity (TanStack)](https://www.stepsecurity.io/blog/mini-shai-hulud-is-back-a-self-spreading-supply-chain-attack-hits-the-npm-ecosystem), [Snyk (TanStack)](https://snyk.io/blog/tanstack-npm-packages-compromised/), [Wiz (Mini wave)](https://www.wiz.io/blog/mini-shai-hulud-strikes-again-tanstack-more-npm-packages-compromised), [Socket (TanStack)](https://socket.dev/blog/tanstack-npm-packages-compromised-mini-shai-hulud-supply-chain-attack), [Aikido](https://www.aikido.dev/blog/mini-shai-hulud-is-back-tanstack-compromised), [Endor Labs (TanStack)](https://www.endorlabs.com/learn/shai-hulud-compromises-the-tanstack-ecosystem-80-packages-compromised), [OpenAI response](https://openai.com/index/our-response-to-the-tanstack-npm-supply-chain-attack/)

### LiteLLM

| ID | Source |
|----|--------|
| PYSEC-2026-2 | [Python Packaging Authority (PyPA)](https://github.com/pypa/advisory-database/blob/main/vulns/litellm/PYSEC-2026-2.yaml) |
| SNYK-PYTHON-LITELLM-15762713 | [Snyk](https://security.snyk.io/vuln/SNYK-PYTHON-LITELLM-15762713) |
| GitHub Issue #24512 | [Initial disclosure](https://github.com/BerriAI/litellm/issues/24512) |

**Research:** [Endor Labs](https://www.endorlabs.com/learn/teampcp-isnt-done), [Datadog Security Labs](https://securitylabs.datadoghq.com/articles/litellm-compromised-pypi-teampcp-supply-chain-campaign/), [Snyk](https://snyk.io/articles/poisoned-security-scanner-backdooring-litellm/), [Sonatype](https://www.sonatype.com/blog/compromised-litellm-pypi-package-delivers-multi-stage-credential-stealer), [StepSecurity](https://www.stepsecurity.io/blog/trivy-compromised-a-second-time---malicious-v0-69-4-release)

### Axios

| ID | Source |
|----|--------|
| GHSA-fw8c-xr5c-95f9 | [GitHub Advisory](https://github.com/advisories/GHSA-fw8c-xr5c-95f9) |
| MAL-2026-2306 | Malicious Package Identifier |

**Research:** [Snyk](https://snyk.io/blog/axios-npm-package-compromised-supply-chain-attack-delivers-cross-platform/), [Socket](https://socket.dev/blog/axios-npm-package-compromised), [Huntress](https://www.huntress.com/blog/supply-chain-compromise-axios-npm-package), [Datadog Security Labs](https://securitylabs.datadoghq.com/articles/axios-npm-supply-chain-compromise/), [Wiz](https://www.wiz.io/blog/axios-npm-compromised-in-supply-chain-attack)

### Known IOC Hashes (SHA-256)

| File | SHA-256 |
|------|---------|
| `litellm_init.pth` (v1.82.8) | `71e35aef03099cd1f2d6446734273025a163597de93912df321ef118bf135238` |
| `proxy_server.py` (v1.82.7) | `a0d229be8efcb2f9135e2ad55ba275b76ddcfeb55fa4370e0a522a5bdee0120b` |
| `sysmon.py` (dropped backdoor) | `6cf223aea68b0e8031ff68251e30b6017a0513fe152e235c26f248ba1e15c92a` |
| `bundle.js` (Shai-Hulud, Sept 2025 wave) | `46faab8ab153fae6e80e7cca38eab363075bb524edd79e42269217a083628f09` |
| `bun_environment.js` (Sha1-Hulud 2.0, Nov 2025) | `62ee164b9b306250c1172583f138c9614139264f889fa99614903c12755468d0` |
| `bun_environment.js` (Sha1-Hulud 2.0, variant) | `f099c5d9ec417d4445a0328ac0ada9cde79fc37410914103ae9c609cbc0ee068` |
| `bun_environment.js` (Sha1-Hulud 2.0, variant) | `cbb9bc5a8496243e02f3cc080efbe3e4a1430ba0671f2e43a202bf45b05479cd` |
| `setup_bun.js` (Sha1-Hulud 2.0, Nov 2025) | `a3894003ad1d293ba96d77881ccd2071446dc3f65f434669b49b3da92421901a` |
| `router_init.js` (Mini Shai-Hulud, May 2026) | `ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c` |
| `tanstack_runner.js` (Mini Shai-Hulud, May 2026) | `2ec78d556d696e208927cc503d48e4b5eb56b31abc2870c2ed2e98d6be27fc96` |

## Project Structure

```
scan_supply_chain/
  threats/                       Threat profile TOML files (user-extensible)
    shai-hulud-2025-09.toml        Shai-Hulud npm worm — Sept 2025 wave (anchor @ctrl/tinycolor)
    sha1-hulud-2025-11.toml        Sha1-Hulud 2.0 — Nov 2025 wave (anchor posthog-node)
    mini-shai-hulud-2026-05.toml   Mini Shai-Hulud — May 2026 TanStack wave
    litellm-2026-03.toml           LiteLLM PyPI compromise
    axios-2026-03.toml             Axios npm compromise
  report/                Phase 5 — summary rendering, split by output type
    _references.py         Source/config file reference display
    _threat.py             Per-threat report (stats + verdict)
    _anti_worm.py          Anti-worm pre-pass section
    _skip.py               Post-scan skipped-paths summary
    _summary.py            Combined multi-threat header/footer
  threat_profile.py      ThreatProfile dataclass + TOML loader (strict schema)
  ecosystem_base.py      EcosystemPlugin protocol + factory
  ecosystem_pypi.py      PyPI: dist-info, METADATA, Python patterns
  ecosystem_npm.py       npm: node_modules, package.json, JS/TS patterns
  scanner.py             Orchestrator: CLI, phase 3 dispatch, multi-threat loop
  scan_context.py        Per-threat ScanContext dataclass passed through every phase
  skip_report.py         Per-scan record of paths the scanner could not walk/read
  config.py              Generic constants (skip dirs, file helpers)
  models.py              Data structures + Confidence/Finding enums
  scoring.py             Evidence scoring (findings → confidence tier)
  formatting.py          Terminal output (ANSI with Windows support)
  platform_policy.py     Platform abstraction (Strategy pattern)
  platform_linux.py      Linux paths and commands
  platform_darwin.py     macOS paths and commands
  platform_windows.py    Windows paths and commands
  search_roots.py        Deduplicated search root computation
  discovery.py           Phase 1 — find package metadata
  version_checker.py     Phase 2 — read package version
  anti_worm_scanner.py   Anti-worm pre-pass — match worm IOCs against local git repos
  git_repo_index.py      Build read-only snapshot of every local git repo
  ioc_scanner.py         Phase 3 — individual IOC scanners (walk_files, c2, k8s, etc.)
  ioc_windows.py         Windows-only IOC checks (Registry, Tasks)
  network_scanner.py     Structured ss/lsof parsing with PID correlation (IPv4 + IPv6)
  persistence_scanner.py Crontab, shell rc, systemd, LaunchAgents
  cache_scanner.py       pip/npm/pnpm cache scanning
  history_scanner.py     Shell history for install commands
  ast_scanner.py         AST-based Python import detection
  subprocess_utils.py    Safe subprocess execution helper
  source_scanner.py      Phase 4 — source/config file scanning
tests/                   pytest test suite (413 tests)
run_scan.py              Direct entry point
run_scan.bat             Double-click launcher for Windows
```

---

## How It Works

This section explains what the scanner does at each step, why it does it, and what the design tradeoffs are. It is intended for security engineers evaluating the tool, contributors, and anyone who wants to understand what is happening on their machine when they run it.

### Overview

The scanner is organized around two abstractions:

- **Threat profiles** — TOML files that describe a specific supply chain attack: which package, which versions are compromised, what C2 infrastructure the attacker used, what IOC files the payload drops, and what remediation steps to take. The scanner ships five built-in profiles (see the table at the top of this document) and supports user-defined profiles.
- **Ecosystem plugins** — Python classes that know how each package manager stores metadata on disk. The PyPI plugin knows about `dist-info`/`egg-info` directories and `METADATA` files. The npm plugin knows about `node_modules/*/package.json`. Each plugin also provides the regex patterns for detecting imports and dependencies in source and config files.

For each threat profile, the scanner runs a 5-phase pipeline. Each phase feeds data into a shared `ScanResults` object that accumulates installations, IOCs, source references, config references, and typed findings. At the end, the results are scored and a verdict is printed.

### Before the pipeline: search root computation

Before any scanning begins, the scanner builds a **deduplicated list of filesystem roots** to walk. This happens once per ecosystem and the same roots are shared by all phases.

The roots come from:

1. **Platform policy** — the OS-specific set of top-level directories where packages might be installed. On Linux: `/home`, `/opt`, `/usr`, `/srv`, `/var`. On macOS: `/Users`, `/opt/homebrew`, `/usr/local`, `/Library`. On Windows: `%USERPROFILE%`, `%APPDATA%`, `Program Files`, etc.
2. **Conda/pipx/nvm directories** — well-known locations under `$HOME` where isolated environments live (`~/miniconda3`, `~/.local/share/pipx`, `~/.nvm`, etc.), added if they exist.
3. **Ecosystem extras** — the npm plugin adds the global `node_modules` directory (found via `npm root -g`); the PyPI plugin adds nothing extra.
4. **`$HOME` itself** — always included so that source/config scans cover user project directories.

After collecting all candidates, the list is **deduplicated by containment**: if `/home` is a root, `/home/me` is dropped because it would be walked anyway. This prevents double-scanning.

**Why it works this way:** Supply chain compromises install packages into virtual environments, conda envs, nvm prefixes, and global site-packages. No single directory covers all cases. Walking a broad set of roots is the only way to catch installations in unusual locations (e.g., a CI runner's custom venv under `/srv`). The deduplication keeps this practical.

### Phase 1: Discovery

**Goal:** Find every installation of the target package on the filesystem.

The scanner walks every search root using `os.walk()` with **directory pruning** — it skips `__pycache__`, `.git`, `.tox`, `dist`, `build`, and other directories that never contain package metadata. For each directory name encountered:

- **PyPI:** checks if the directory name matches the pattern `{package}-*.dist-info` or `{package}-*.egg-info` (case-insensitive, with `-` and `_` treated as equivalent, per PEP 503 normalization).
- **npm:** checks if the current directory is `node_modules`, and if so, looks for a `{package}/package.json` subdirectory.

Each match is recorded as a metadata directory path. Duplicates that resolve to the same real path (via symlinks) are removed.

**Why it works this way:** Package managers don't maintain a centralized registry of what's installed where. The only reliable way to find all installations is to walk the filesystem. The pruning keeps it fast — skipping `__pycache__` and `.git` alone eliminates a huge fraction of the directory tree. The pattern matching is intentionally loose (case-insensitive, dash/underscore equivalence) because package managers normalize names inconsistently.

### Phase 2: Version check

**Goal:** Determine the installed version of each discovered installation and flag compromised versions.

For each metadata directory found in Phase 1:

- **PyPI:** reads the `METADATA` file (or `PKG-INFO` for egg-info) and extracts the `Version:` header.
- **npm:** reads `package.json` and extracts the `"version"` field.

Each installation is recorded with its path and version. If the version matches one of the compromised versions listed in the threat profile, it is flagged. The output shows `! COMPROMISED` or `+ clean` for each installation.

**Why it works this way:** The version check is the single highest-signal indicator. If you have `litellm==1.82.7` installed, you were almost certainly affected. Everything else the scanner does is gathering supporting evidence — this is the core question.

### Phase 3: Evidence collection

**Goal:** Search for artifacts, network activity, and persistence mechanisms that indicate active or past compromise.

Phase 3 runs multiple independent sub-scanners. Each one appends its findings to the shared `ScanResults`. They run in order but are logically independent.

#### IOC file walk

Walks all search roots looking for specific filenames defined in the threat profile. For example, the LiteLLM profile searches for `litellm_init.pth` — the auto-executing backdoor file that v1.82.8 dropped into `site-packages/`. When SHA-256 hashes are provided in the profile, found files are verified against them — a file named `litellm_init.pth` with a different hash is not flagged (it might be a legitimate file in a different project). When the file can't be read (permission denied), it is still reported as suspicious.

**Why:** IOC files are the most direct evidence of a payload being dropped. The hash check reduces false positives. The walk covers all search roots because the attacker's payload may end up in any Python environment on the machine.

#### Known path check

Checks a list of absolute paths from the threat profile. These are paths where the specific attack is known to drop files — for example, `~/.config/sysmon/sysmon.py` (the LiteLLM persistent backdoor) or `%APPDATA%\sysmon\sysmon.py` (Windows equivalent). Paths are platform-specific and are expanded (`~` and `%VAR%`) at runtime.

**Why:** Unlike the IOC file walk (which searches by filename), this check looks at exact locations. Some payloads drop files with generic names in specific directories — you can't walk the whole filesystem looking for "sysmon.py", but you can check the three places the attacker is known to put it.

#### C2 connection check

Checks active TCP connections for communication with known attacker infrastructure.

1. Selects the right network tool for the OS: `ss -tnp` on Linux, `lsof -i -P -n` on macOS, `netstat -ano` on Windows.
2. Runs the command and **parses the output into structured records** (`ConnectionRecord` objects with `peer_ip`, `peer_port`, `pid`, and `process_name`). The parser understands the output format of `ss` and `lsof`.
3. Matches each connection against the C2 IP addresses from the threat profile. If the threat profile specifies ports (e.g., Axios uses port 8000), only connections to those ports are flagged. If no ports are specified (e.g., LiteLLM), any connection to a C2 IP is flagged.
4. On Linux, enriches matched connections with the executable path by reading `/proc/{pid}/exe`.

If `--resolve-c2` is enabled, the scanner also performs live DNS lookups on the C2 domains and adds any resolved IPs to the match set. This is disabled by default because the DNS queries are visible to the attacker's infrastructure.

**Why structured parsing instead of substring matching:** The original approach checked if a C2 IP appeared anywhere in the `ss` output as a substring. This would incorrectly match `21.2.3.45` when looking for `1.2.3.4`. Structured parsing extracts actual IP:port pairs and matches them precisely. The PID and process name are included in the output so the operator can immediately identify which process is talking to the attacker.

#### Kubernetes pod check

If `kubectl` is available and the threat profile defines suspicious pod patterns, queries the specified namespace for pods whose names start with those patterns. The LiteLLM attack deploys privileged `node-setup-*` pods in `kube-system` for lateral movement.

**Why:** This only runs when `kubectl` is present and the threat profile requests it. Most users won't have `kubectl` configured, and the check is skipped silently.

#### Phantom dependency check

Checks for packages that should never exist in your dependency tree. These are malicious dependencies injected by the compromised package — for example, Axios v1.14.1 added `plain-crypto-js` as a dependency.

- **npm:** parses `package-lock.json` structurally (JSON), and uses line-anchored regex for `yarn.lock` and `pnpm-lock.yaml`. Extracts the resolved version when possible (e.g., `phantom:plain-crypto-js@4.2.1`).
- **PyPI:** walks `dist-info` directories looking for metadata referencing the phantom package name.

**Why:** Phantom dependencies are strong evidence of compromise — they only exist because the malicious version pulled them in. Even after you upgrade the parent package, the phantom dependency may still be installed. The lockfile check catches cases where the phantom dependency is recorded in version control even after the package itself was removed.

#### Windows-specific checks

On Windows, queries the Registry Run keys (`HKCU\...\Run`, `HKLM\...\Run`) and Scheduled Tasks for persistence keywords defined in the threat profile. For example, the LiteLLM profile searches for "sysmon", "litellm", and "system telemetry" in registry entries and scheduled task names.

**Why:** These are the standard Windows persistence mechanisms. The check is keyword-based because the attacker may use slightly different paths or task names across variants.

#### Persistence scan

Checks generic persistence locations that any supply chain attack might abuse, filtering by the target package name:

- **Crontab:** runs `crontab -l` and searches for lines mentioning the package name (ignoring comments).
- **Shell rc files:** reads `.bashrc`, `.zshrc`, `.profile`, `.bash_profile` looking for the package name in non-comment lines. Reports the specific line number.
- **`/tmp` scripts:** lists `.py`, `.sh`, and `.bash` files in `/tmp`. For Python files, uses the AST scanner to check if the file actually imports the target package (not just mentions it in a string). For shell scripts, checks non-comment lines.
- **systemd user services** (Linux): reads `~/.config/systemd/user/*.service` files for the package name.
- **XDG autostart** (Linux): reads `~/.config/autostart/*.desktop` files for the package name.
- **LaunchAgents** (macOS): reads `~/Library/LaunchAgents/*.plist` files for the package name.

**Why:** Supply chain attacks commonly install persistence mechanisms to survive package upgrades. The crontab check catches the LiteLLM backdoor's 50-minute polling timer. The `/tmp` check catches dropped scripts. Every check filters by the package name to avoid drowning the operator in noise from unrelated crontab entries or shell configuration.

#### Cache scan

Checks package manager caches for traces of the compromised package. The scan is ecosystem-gated — PyPI threats only check the pip cache, npm threats check npm and pnpm caches.

- **pip cache:** walks `~/.cache/pip` (Linux), `~/Library/Caches/pip` (macOS), or `%LOCALAPPDATA%\pip\Cache` (Windows) looking for files or directories with the package name in their name.
- **npm cache:** walks `~/.npm/_cacache` looking for files with the package name.
- **pnpm store:** walks `~/.local/share/pnpm/store` looking for directories with the package name.

One hit per cache is enough — the scanner stops after the first match.

**Why:** Even after uninstalling a compromised package, traces remain in the package manager's cache. Finding `litellm-1.82.7.whl` in the pip cache confirms the compromised version was downloaded on this machine. This is LOW confidence evidence on its own but contributes to the overall picture.

#### History scan

Searches `.bash_history` and `.zsh_history` for install commands (`pip install`, `npm install`, `yarn add`, `pnpm add`, etc.) that mention the target package. The command patterns are ecosystem-gated.

**Why:** Shell history is another trace that survives package removal. Finding `pip install litellm==1.82.7` in your history confirms you installed the compromised version, even if it's been uninstalled since.

### Phase 4: Source and config scan

**Goal:** Find every source file that uses the package and every dependency config that references it. Flag configs that pin a compromised version.

The scanner walks all search roots, skipping `site-packages` and `node_modules` (third-party code is not interesting — you want to know about *your* code). For each file:

1. **Classification:** the file is categorized as a source file (`.py`, `.js`, `.ts`, etc.) or a config file (`requirements.txt`, `pyproject.toml`, `package.json`, etc.) based on the ecosystem plugin's patterns.
2. **Fast-path filter:** the entire file is read, and if the package name doesn't appear anywhere in the text, the file is skipped immediately. This eliminates the vast majority of files without line-by-line scanning.
3. **Source file scanning:**
   - For **Python files**, the scanner uses `ast.parse()` to build an Abstract Syntax Tree and walks it looking for `import litellm`, `from litellm import X`, `from litellm.utils import Y`, and `litellm.completion()` attribute access. This produces zero false positives from string literals (`"litellm"` in a comment or docstring) and regex patterns (`re.compile(r"litellm\.")`) that merely mention the name. If the file has a syntax error and can't be parsed, the scanner falls back to regex matching.
   - For **JavaScript/TypeScript files**, the scanner uses regex patterns for `require('package')` and `import ... from 'package'`.
4. **Config file scanning:** checks for dependency declarations using ecosystem-specific regex. If a pinned version is found (e.g., `litellm==1.82.7` in `requirements.txt`), extracts the version and flags it if compromised.

The scanner excludes its own source directory to avoid reporting on itself.

**Why AST-based detection:** This scanner is designed to scan systems that *use* the target package legitimately. A machine running LiteLLM in production will have many `.py` files that mention "litellm" in strings, comments, and variable names. Without AST parsing, these would all be false positives. The AST approach means the scanner only reports files that actually `import` or call the package.

### Phase 5: Verdict and remediation

**Goal:** Produce a summary and actionable guidance.

The scanner computes a **confidence tier** from all collected findings:

1. Extracts the set of finding categories present (version match, IOC file, C2 connection, persistence, cache trace, etc.).
2. Applies precedence rules:
   - Compromised version + active C2 connection = **CRITICAL**
   - Compromised version + IOC file or phantom dependency = **HIGH**
   - Compromised version alone, or persistence artifact = **MEDIUM**
   - Anything else (source ref, cache trace, history) = **LOW**
   - No findings at all = no confidence tier displayed.
3. Prints statistics: environments scanned, installations found, compromised versions, IOC artifacts, source files, config files, and the confidence tier.

If compromise is detected (`is_clean` is false — meaning compromised installations, IOC artifacts, or compromised config pins were found), the scanner prints **threat-specific remediation steps** from the TOML profile:

1. Credential rotation warning (if `rotate_secrets = true` in the profile).
2. Artifact removal instructions (platform-specific paths).
3. Safe version install command.
4. Config file update guidance (specific files and line numbers where compromised versions are pinned).
5. Persistence check commands (platform-specific).
6. Link to the advisory.

If no compromise is detected but source/config references were found, a warning is printed advising the user to verify their version is safe.

**Why a tiered verdict instead of binary:** A machine that has `litellm==1.82.7` installed AND is actively connecting to the C2 server is in a fundamentally different situation from a machine where someone once ran `pip install litellm` and it appeared in their shell history. The tiers help the operator prioritize their response.

### Design rationale: broad filesystem walk

The scanner deliberately walks large portions of the filesystem. This is slow on machines with large disks and many files. It is also the only reliable approach for an incident response tool that needs to find *every* installation, not just the one in the current virtualenv. Package managers install into conda envs, pipx venvs, nvm prefixes, system site-packages, and project-local `.venv` directories. A compromised package in a forgotten virtualenv is still a compromised package.

The fast-path filter (checking if the package name appears in the file content before line-by-line scanning) and directory pruning (skipping `.git`, `__pycache__`, etc.) keep the cost manageable. On a typical developer machine, the full scan takes a few seconds.

### Design rationale: data-driven threat profiles

The scanner doesn't hardcode any package names, versions, file paths, or C2 addresses. Everything attack-specific lives in the TOML threat profile. This means:

- **New threats can be added without code changes.** Drop a TOML file and the scanner picks it up.
- **Users can define their own threats.** If your organization discovers an internal compromise, write a TOML file describing it and the scanner works immediately.
- **The scanner code is purely mechanical.** It walks, reads, parses, matches, and reports. The intelligence is in the profiles.

## Disclaimer

This tool is provided as-is, with no warranty of any kind. It searches for known indicators of supply chain compromises but **cannot guarantee** complete detection. A clean scan does not mean your system was unaffected. Always perform credential rotation if there is any possibility that a compromised package was installed in your environment, even briefly.
