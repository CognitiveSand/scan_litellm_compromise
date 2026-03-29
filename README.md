# LiteLLM Supply Chain Attack Scanner

A best-effort scanner that **attempts to detect** indicators of compromise (IOCs) left by the malicious LiteLLM PyPI packages v1.82.7 and v1.82.8, published on March 24, 2026. The compromise was identified by security researchers at **Endor Labs**, **Datadog Security Labs**, **Snyk**, and **Sonatype**, with the initial public disclosure filed as [GitHub Issue #24512](https://github.com/BerriAI/litellm/issues/24512).

> **No guarantees.** This tool attempts to find known artifacts associated with the compromise. It does **not** guarantee detection of all malicious activity, nor does it guarantee that a clean scan means your system was not affected. A determined attacker may have removed traces, and the tool cannot detect secrets that have already been exfiltrated. Use this scanner as one input in your incident response — not as a definitive verdict.

## Quick Start

### Option A: Install from PyPI

```bash
# Recommended — installs in an isolated environment
pipx install scan-litellm-compromise

# Then run:
scan-litellm
```

If you don't have pipx: `sudo apt install pipx` (Debian/Ubuntu) or `brew install pipx` (macOS).

Alternatively, using pip inside a virtual environment:

```bash
python3 -m venv /tmp/scanner && /tmp/scanner/bin/pip install scan-litellm-compromise
/tmp/scanner/bin/scan-litellm
```

> **Note:** `pip install` directly will fail on modern Linux distributions (Debian 12+, Ubuntu 23.04+, Fedora 38+) due to [PEP 668](https://peps.python.org/pep-0668/). Use `pipx` or a virtual environment instead.

### Option B: Run from source (no install needed)

```bash
git clone https://github.com/CognitiveSand/scan_litellm_compromise.git
cd scan_litellm_compromise
python3 run_scan.py
```

On **Windows** — double-click **`run_scan.bat`**, or from a terminal:

```cmd
py run_scan.py
```

No dependencies required — uses only the Python standard library.

### Command-Line Options

| Flag | Description |
|------|-------------|
| `--scan-path DIR` | Restrict Phase 1 (discovery) and Phase 4 (source scan) to a specific directory instead of scanning the entire system. IOC artifact checks (Phase 3) still run system-wide. |
| `--resolve-c2` | Enable live DNS queries to C2 domains in addition to using hardcoded known IPs. See warning below. |
| `--help` | Show usage information. |

> **Warning about `--resolve-c2`:** This flag causes the scanner to make live DNS queries to `models.litellm.cloud` and `checkmarx.zone` — both **attacker-controlled domains**. This carries real risks:
> - **Operational security:** Your DNS query is visible to the attacker's infrastructure, revealing that you are actively investigating the compromise. This could prompt them to rotate infrastructure, wipe logs, or accelerate exploitation of already-stolen credentials.
> - **Network monitoring:** The queries may trigger alerts in your own SIEM, IDS, or SOC dashboards, creating noise during an active incident response.
> - **DNS logging:** Corporate DNS resolvers and upstream providers log queries. The domains may already be on threat intel blocklists, which could flag your machine as compromised.
>
> **In most cases you do not need this flag.** The scanner ships hardcoded known IPs (`46.151.182.203`, `83.142.209.11`) confirmed by multiple threat intelligence sources. Live DNS is only useful if you suspect the attacker has rotated to new infrastructure since this tool was last updated.

**Examples:**

```bash
# Scan only a specific project directory
python3 -m scan_litellm_compromise --scan-path /home/user/myproject

# Enable live DNS resolution for C2 connection checks
python3 -m scan_litellm_compromise --resolve-c2

# Combine both
python3 -m scan_litellm_compromise --scan-path ./myproject --resolve-c2
```

## Video Overview

This scanner was inspired by [Fahd Mirza's video](https://www.youtube.com/watch?v=YoClPk7KqZc) highlighting the incident — thanks to him for bringing it to attention.

## What Happened

On March 24, 2026, two backdoored versions of the `litellm` Python package were published to PyPI:

- **v1.82.7** (uploaded ~10:39 UTC) — malicious code injected into `litellm/proxy/proxy_server.py` (base64-encoded)
- **v1.82.8** (uploaded ~10:52 UTC) — added a `litellm_init.pth` file that executes on **every Python interpreter startup**, regardless of whether litellm is imported

The packages were available for approximately **3 hours** before PyPI quarantined them. LiteLLM has roughly 95 million monthly downloads.

### How the Attack Worked

The attacker compromised BerriAI's `PYPI_PUBLISH` token by poisoning the `aquasecurity/trivy-action` GitHub Action used in LiteLLM's CI/CD pipeline. Malicious commits were force-pushed onto 75 of 76 existing version tags in the Trivy action repository. When LiteLLM's CI ran, it fetched the attacker-controlled action, which exfiltrated the PyPI publishing token. This was identified and documented by researchers at **Endor Labs**, **Snyk**, and **StepSecurity**.

### Three-Stage Payload

**Stage 1 — Credential Harvester:**
Sweeps the local filesystem and live process environments for secrets including:
- SSH private keys (`~/.ssh/`)
- AWS, GCP, and Azure credentials
- Kubernetes kubeconfig and service account tokens
- Database credentials (PostgreSQL, MySQL, Redis)
- CI/CD tokens (PyPI, npm, Docker registry, GitHub PATs)
- All environment variables (capturing API keys for OpenAI, Anthropic, etc.)
- `.env` files (recursively discovered)
- Shell histories, git credentials, TLS private keys
- Cryptocurrency wallets

**Stage 2 — Encrypted Exfiltration:**
Harvested data is encrypted with AES-256-CBC (random session key) and the session key is encrypted with a hardcoded RSA-4096 public key. The bundle is archived as `/tmp/tpcp.tar.gz` and sent via HTTPS POST to `models.litellm.cloud`.

**Stage 3 — Persistence Backdoor:**
- Drops `~/.config/sysmon/sysmon.py`
- Creates `~/.config/systemd/user/sysmon.service` ("System Telemetry Service")
- Every 50 minutes, polls `checkmarx.zone/raw` for a secondary payload, downloads it to `/tmp/pglog`, and executes it
- Tracks state in `/tmp/.pg_state`

### Kubernetes Lateral Movement

If a Kubernetes service account token is found, the payload deploys **privileged pods** named `node-setup-{node_name}` into the `kube-system` namespace on every node. These pods mount the host root filesystem and install the sysmon backdoor at the node level.

## What This Scanner Attempts to Find

This scanner makes a best-effort attempt to detect known IOCs. It automatically detects the platform (Linux, macOS, or Windows) and adjusts scan paths accordingly.

| Phase | What It Looks For |
|-------|-------------------|
| 1 | litellm metadata directories (`dist-info` / `egg-info`) across filesystem (Linux: `/home`, `/opt`, `/usr`, `/srv`, `/var`; macOS: `/Users`, `/opt/homebrew`, `/Library`; Windows: `%USERPROFILE%`, `%APPDATA%`, `Program Files`). Can be restricted with `--scan-path`. |
| 2 | litellm version from metadata files — no Python interpreter execution needed |
| 3 | IOC artifacts: `litellm_init.pth`, sysmon persistence, temp staging files, C2 network connections (matched against hardcoded known IPs by default; `--resolve-c2` enables live DNS), suspicious Kubernetes pods. On Windows: also checks Registry Run keys and Scheduled Tasks |
| 4 | Source files and dependency configs (pyproject.toml, requirements.txt, etc.) that reference litellm, flagging any pinned to compromised versions |

## Limitations

- **This scanner cannot detect exfiltrated secrets.** If your credentials were sent to the attacker's C2 server, no local scan can undo that. Credential rotation is required regardless of scan results.
- **Artifacts may have been cleaned up.** The absence of IOC files does not prove the system was never compromised.
- **The scanner does not inspect Docker image layers, CI/CD runner caches, or remote systems.** Each environment must be checked independently.
- **Root-owned paths (`/root` on Linux) are excluded.** If you need to scan those, run a separate check with appropriate privileges.
- **The scanner cannot decrypt exfiltrated data.** Only the attacker holds the RSA-4096 private key.
- **Windows Registry scanning is best-effort.** The scanner checks common Run key locations but cannot cover all possible persistence mechanisms (WMI subscriptions, COM hijacking, etc.).

## Usage

**Linux / macOS:**

```bash
python3 run_scan.py
# or
python3 -m scan_litellm_compromise
# or, if installed via pip:
scan-litellm
```

**Windows — double-click `run_scan.bat`**, or from a terminal:

```cmd
py run_scan.py
```

The scanner auto-detects the platform (Linux, macOS, or Windows) and adjusts scan paths, network commands, and persistence checks accordingly.

Exit code is `1` if compromise indicators are found, `0` otherwise.

See [Command-Line Options](#command-line-options) for `--scan-path` and `--resolve-c2`.

## Platform Support

| Feature | Linux | macOS | Windows 10/11 |
|---------|-------|-------|---------------|
| litellm detection | `/home`, `/opt`, `/usr`, `/srv`, `/var` | `/Users`, `/opt/homebrew`, `/usr/local`, `/Library` | `%USERPROFILE%`, `%APPDATA%`, `Program Files` |
| Conda/pipx detection | `/opt/conda`, `~/.local/share/pipx` | Homebrew Caskroom, `~/.local/share/pipx` | `%LOCALAPPDATA%\Miniconda3`, `%LOCALAPPDATA%\pipx` |
| Persistence check | systemd user services | sysmon files (inert without systemd) | Registry Run keys, Scheduled Tasks, Startup folder |
| Temp artifacts | `/tmp/` | `/tmp/` | `%TEMP%` |
| Network connections | `ss -tnp` | `lsof -i -P -n` | `netstat -ano` |
| C2 IP matching | Hardcoded known IPs (opt-in live DNS via `--resolve-c2`) | Same | Same |
| ANSI terminal colors | Native | Native | Auto-enabled via Virtual Terminal Processing |

### macOS Note

macOS support was added based on threat intelligence analysis of the TeamPCP malware's behavior on Darwin systems. **It has not been tested on actual macOS hardware** as the maintainer does not currently have access to a Mac. The malware's credential theft and `.pth` backdoor are confirmed to work on macOS, but the systemd persistence mechanism is inert (macOS uses launchd, not systemd). If you run this scanner on macOS and encounter issues, please open an issue.

## If Compromise Is Detected

**Assume ALL secrets on the affected machine are compromised.** The following steps are recommended — this list is not exhaustive:

1. **Rotate credentials immediately** — SSH keys, cloud provider credentials (AWS/GCP/Azure), API keys, database passwords, CI/CD tokens, `.env` file contents
2. **Remove malicious artifacts** — delete `litellm_init.pth`, sysmon persistence files, and temp staging files (see platform-specific paths above)
3. **Downgrade litellm** — `pip install litellm==1.82.6` (last known clean version) or upgrade past the compromised range once verified safe
4. **Update pinned versions** — check all `requirements.txt`, `pyproject.toml`, and lock files for references to 1.82.7 or 1.82.8
5. **Inspect Kubernetes clusters** — look for `node-setup-*` pods in `kube-system`, audit ClusterRoleBindings
6. **Block C2 domains** — `models.litellm.cloud` and `checkmarx.zone` at DNS/firewall level
7. **Audit cloud provider logs** — check AWS CloudTrail, GCP Audit Logs, Azure Activity Logs for unauthorized API calls using potentially stolen credentials

## Advisories and References

| ID | Source |
|----|--------|
| PYSEC-2026-2 | [Python Packaging Authority (PyPA)](https://github.com/pypa/advisory-database/blob/main/vulns/litellm/PYSEC-2026-2.yaml) |
| SNYK-PYTHON-LITELLM-15762713 | [Snyk](https://security.snyk.io/vuln/SNYK-PYTHON-LITELLM-15762713) |
| GitHub Issue #24512 | [Initial disclosure](https://github.com/BerriAI/litellm/issues/24512) |
| GitHub Issue #24518 | [Official timeline](https://github.com/BerriAI/litellm/issues/24518) |

### Security Research and Technical Analyses

- [Endor Labs](https://www.endorlabs.com/learn/teampcp-isnt-done) — full campaign timeline and attribution
- [Datadog Security Labs](https://securitylabs.datadoghq.com/articles/litellm-compromised-pypi-teampcp-supply-chain-campaign/) — payload and artifact analysis
- [Snyk](https://snyk.io/articles/poisoned-security-scanner-backdooring-litellm/) — IOC hashes and advisory
- [Sonatype](https://www.sonatype.com/blog/compromised-litellm-pypi-package-delivers-multi-stage-credential-stealer) — stage-by-stage payload analysis
- [StepSecurity](https://www.stepsecurity.io/blog/trivy-compromised-a-second-time---malicious-v0-69-4-release) — Trivy supply chain compromise analysis
- [Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/03/24/detecting-investigating-defending-against-trivy-supply-chain-compromise/) — detection and defense guidance

### Known IOC Hashes (SHA-256)

| File | SHA-256 |
|------|---------|
| `litellm_init.pth` (v1.82.8) | `71e35aef03099cd1f2d6446734273025a163597de93912df321ef118bf135238` |
| `proxy_server.py` (v1.82.7) | `a0d229be8efcb2f9135e2ad55ba275b76ddcfeb55fa4370e0a522a5bdee0120b` |
| `sysmon.py` (dropped backdoor) | `6cf223aea68b0e8031ff68251e30b6017a0513fe152e235c26f248ba1e15c92a` |

## Project Structure

```
scan_litellm_compromise/
  __main__.py            Entry point for python -m
  scanner.py             Orchestrator (argparse CLI)
  config.py              Cross-platform constants, patterns, and known C2 IPs
  models.py              Typed data structures
  formatting.py          Terminal output (ANSI with Windows support)
  platform_policy.py     Platform abstraction (Strategy pattern)
  platform_linux.py      Linux-specific paths and commands
  platform_darwin.py     macOS-specific paths and commands
  platform_windows.py    Windows-specific paths and commands
  ioc_windows.py         Windows-only IOC checks (Registry, Tasks)
  discovery.py           Phase 1 — find litellm metadata directories
  version_checker.py     Phase 2 — read litellm version from metadata
  ioc_scanner.py         Phase 3 — IOC artifact detection
  source_scanner.py      Phase 4 — source/config file scanning
  report.py              Phase 5 — summary and remediation
tests/                   pytest test suite (299 tests)
run_scan.py              Direct entry point
run_scan.bat             Double-click launcher for Windows
```

## Disclaimer

This tool is provided as-is, with no warranty of any kind. It **attempts to find** known indicators of the LiteLLM v1.82.7/v1.82.8 compromise but **cannot guarantee** complete detection. A clean scan does not mean your system was unaffected. Always perform credential rotation if there is any possibility that a compromised version was installed in your environment, even briefly.
