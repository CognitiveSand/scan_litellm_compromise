# Supply Chain Compromise Scanner

A data-driven scanner that detects indicators of compromise (IOCs) from known **PyPI and npm supply chain attacks**. Threat profiles are defined in TOML files and are user-extensible — add your own without writing code.

**Built-in threat profiles:**

| ID | Package | Ecosystem | Compromised Versions | Date |
|----|---------|-----------|---------------------|------|
| `litellm-2026-03` | litellm | PyPI | 1.82.7, 1.82.8 | 2026-03-24 |
| `axios-2026-03` | axios | npm | 1.14.1, 0.30.4 | 2026-03-31 |

> **No guarantees.** This tool attempts to find known artifacts associated with supply chain compromises. It does **not** guarantee detection of all malicious activity, nor does it guarantee that a clean scan means your system was not affected. A determined attacker may have removed traces, and the tool cannot detect secrets that have already been exfiltrated. Use this scanner as one input in your incident response — not as a definitive verdict.

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
| `--scan-path DIR` | Restrict scanning to a specific directory instead of system-wide search. |
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

# Scan only a specific project directory
scan-supply-chain --scan-path /home/user/myproject

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

The scanner runs a 5-phase pipeline for each threat profile:

| Phase | What It Looks For |
|-------|-------------------|
| 1 | Package metadata directories across the filesystem (PyPI: `dist-info`/`egg-info`; npm: `node_modules/*/package.json`) |
| 2 | Package version from metadata — flags compromised versions |
| 3 | IOC artifacts: backdoor files, persistence mechanisms, temp staging files, C2 network connections, suspicious Kubernetes pods, phantom dependencies, Windows Registry/Tasks |
| 4 | Source files and dependency configs referencing the package, flagging pinned compromised versions |
| 5 | Per-threat summary, verdicts, and remediation guidance |

## Limitations

- **Cannot detect exfiltrated secrets.** Credential rotation is required regardless of scan results.
- **Artifacts may have been cleaned up.** Absence of IOC files does not prove the system was never compromised.
- **Does not inspect Docker image layers, CI/CD runner caches, or remote systems.**
- **Root-owned paths (`/root` on Linux) are excluded.**
- **Windows Registry scanning is best-effort.**

## Platform Support

| Feature | Linux | macOS | Windows 10/11 |
|---------|-------|-------|---------------|
| Package detection | `/home`, `/opt`, `/usr`, `/srv`, `/var` | `/Users`, `/opt/homebrew`, `/usr/local`, `/Library` | `%USERPROFILE%`, `%APPDATA%`, `Program Files` |
| Conda/pipx/nvm detection | `/opt/conda`, `~/.local/share/pipx` | Homebrew Caskroom, `~/.local/share/pipx` | `%LOCALAPPDATA%\Miniconda3`, `%LOCALAPPDATA%\pipx` |
| Network connections | `ss -tnp` | `lsof -i -P -n` | `netstat -ano` |
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

## Project Structure

```
scan_supply_chain/
  threats/               Threat profile TOML files (user-extensible)
    litellm-2026-03.toml   LiteLLM PyPI compromise
    axios-2026-03.toml     Axios npm compromise
  threat_profile.py      ThreatProfile dataclass + TOML loader
  ecosystem_base.py      EcosystemPlugin protocol + factory
  ecosystem_pypi.py      PyPI: dist-info, METADATA, Python patterns
  ecosystem_npm.py       npm: node_modules, package.json, JS/TS patterns
  scanner.py             Orchestrator (multi-threat CLI)
  config.py              Generic constants (skip dirs)
  models.py              Typed data structures
  formatting.py          Terminal output (ANSI with Windows support)
  platform_policy.py     Platform abstraction (Strategy pattern)
  platform_linux.py      Linux paths and commands
  platform_darwin.py     macOS paths and commands
  platform_windows.py    Windows paths and commands
  ioc_windows.py         Windows-only IOC checks (Registry, Tasks)
  discovery.py           Phase 1 — find package metadata
  version_checker.py     Phase 2 — read package version
  ioc_scanner.py         Phase 3 — IOC artifact detection
  source_scanner.py      Phase 4 — source/config file scanning
  report.py              Phase 5 — summary and remediation
tests/                   pytest test suite (230 tests)
run_scan.py              Direct entry point
run_scan.bat             Double-click launcher for Windows
```

## Disclaimer

This tool is provided as-is, with no warranty of any kind. It **attempts to find** known indicators of supply chain compromises but **cannot guarantee** complete detection. A clean scan does not mean your system was unaffected. Always perform credential rotation if there is any possibility that a compromised package was installed in your environment, even briefly.
