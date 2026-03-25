# LiteLLM Supply Chain Attack Scanner

A best-effort scanner that **attempts to detect** indicators of compromise (IOCs) left by the malicious LiteLLM PyPI packages v1.82.7 and v1.82.8, published on March 24, 2026 by the threat actor known as **TeamPCP**.

> **No guarantees.** This tool attempts to find known artifacts associated with the compromise. It does **not** guarantee detection of all malicious activity, nor does it guarantee that a clean scan means your system was not affected. A determined attacker may have removed traces, and the tool cannot detect secrets that have already been exfiltrated. Use this scanner as one input in your incident response — not as a definitive verdict.

## Quick Start

**1. Download the scanner:**

```bash
git clone https://github.com/CognitiveSand/scan_litellm_compromise.git
cd scan_litellm_compromise
```

**2. Run it:**

On **Linux / macOS** — open a terminal and run:

```bash
python3 run_scan.py
```

On **Windows** — double-click **`run_scan.bat`**. That's it.

Alternatively, open PowerShell or Command Prompt and run:

```cmd
py run_scan.py
```

No dependencies required — uses only the Python standard library.

## Video Overview

This scanner was inspired by [Fahd Mirza's video](https://www.youtube.com/watch?v=YoClPk7KqZc) highlighting the incident — thanks to him for bringing it to attention.

## What Happened

On March 24, 2026, two backdoored versions of the `litellm` Python package were published to PyPI:

- **v1.82.7** (uploaded ~10:39 UTC) — malicious code injected into `litellm/proxy/proxy_server.py` (base64-encoded)
- **v1.82.8** (uploaded ~10:52 UTC) — added a `litellm_init.pth` file that executes on **every Python interpreter startup**, regardless of whether litellm is imported

The packages were available for approximately **3 hours** before PyPI quarantined them. LiteLLM has roughly 95 million monthly downloads.

### How the Attack Worked

TeamPCP compromised BerriAI's `PYPI_PUBLISH` token by poisoning the `aquasecurity/trivy-action` GitHub Action used in LiteLLM's CI/CD pipeline. The attacker force-pushed malicious commits onto 75 of 76 existing version tags in the Trivy action repository. When LiteLLM's CI ran, it fetched the attacker-controlled action, which exfiltrated the PyPI publishing token.

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

This scanner makes a best-effort attempt to detect known IOCs. It automatically detects the platform (Linux or Windows) and adjusts scan paths accordingly.

| Phase | What It Looks For |
|-------|-------------------|
| 1 | Python interpreters (Linux: `/home`, `/opt`, `/usr`, `/srv`, `/var`; Windows: `%USERPROFILE%`, `%APPDATA%`, `Program Files`) |
| 2 | Installed litellm versions in discovered Python environments |
| 3 | IOC artifacts: `litellm_init.pth`, sysmon persistence, temp staging files, C2 network connections, suspicious Kubernetes pods. On Windows: also checks Registry Run keys and Scheduled Tasks |
| 4 | Source files and dependency configs (pyproject.toml, requirements.txt, etc.) that reference litellm, flagging any pinned to compromised versions |

## Limitations

- **This scanner cannot detect exfiltrated secrets.** If your credentials were sent to the attacker's C2 server, no local scan can undo that. Credential rotation is required regardless of scan results.
- **Artifacts may have been cleaned up.** The absence of IOC files does not prove the system was never compromised.
- **The scanner does not inspect Docker image layers, CI/CD runner caches, or remote systems.** Each environment must be checked independently.
- **Root-owned paths (`/root` on Linux) are excluded.** If you need to scan those, run a separate check with appropriate privileges.
- **The scanner cannot decrypt exfiltrated data.** Only the attacker holds the RSA-4096 private key.
- **Windows Registry scanning is best-effort.** The scanner checks common Run key locations but cannot cover all possible persistence mechanisms (WMI subscriptions, COM hijacking, etc.).

## Usage

```bash
# Linux / macOS
python3 run_scan.py
python3 -m scan_litellm_compromise

# Windows (PowerShell or cmd.exe) — use py, or python as fallback
py run_scan.py
py -m scan_litellm_compromise
```

The scanner auto-detects the platform and adjusts scan paths, network commands, and persistence checks accordingly.

Exit code is `1` if compromise indicators are found, `0` otherwise.

## Platform Support

| Feature | Linux | Windows 10/11 |
|---------|-------|---------------|
| Python environment discovery | `/home`, `/opt`, `/usr`, `/srv`, `/var` | `%USERPROFILE%`, `%APPDATA%`, `Program Files` |
| Conda/pipx detection | `/opt/conda`, `~/.local/share/pipx` | `%LOCALAPPDATA%\Miniconda3`, `%LOCALAPPDATA%\pipx` |
| Persistence check | systemd user services | Registry Run keys, Scheduled Tasks, Startup folder |
| Temp artifacts | `/tmp/` | `%TEMP%` |
| Network connections | `ss -tnp` | `netstat -ano` |
| ANSI terminal colors | Native | Auto-enabled via Virtual Terminal Processing |

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

### Technical Analyses

- [Endor Labs: TeamPCP Isn't Done](https://www.endorlabs.com/learn/teampcp-isnt-done) — full campaign timeline
- [Datadog Security Labs](https://securitylabs.datadoghq.com/articles/litellm-compromised-pypi-teampcp-supply-chain-campaign/) — payload and artifact details
- [Snyk](https://snyk.io/articles/poisoned-security-scanner-backdooring-litellm/) — IOC hashes
- [Sonatype](https://www.sonatype.com/blog/compromised-litellm-pypi-package-delivers-multi-stage-credential-stealer) — stage-by-stage analysis

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
  scanner.py             Orchestrator
  config.py              Cross-platform constants and patterns
  models.py              Typed data structures
  formatting.py          Terminal output (ANSI with Windows support)
  platform_policy.py     Platform abstraction (Strategy pattern)
  platform_linux.py      Linux-specific paths and commands
  platform_windows.py    Windows-specific paths and commands
  ioc_windows.py         Windows-only IOC checks (Registry, Tasks)
  discovery.py           Phase 1 — find Python environments
  version_checker.py     Phase 2 — check litellm versions
  ioc_scanner.py         Phase 3 — IOC artifact detection
  source_scanner.py      Phase 4 — source/config file scanning
  report.py              Phase 5 — summary and remediation
run_scan.py              Direct entry point
```

## Disclaimer

This tool is provided as-is, with no warranty of any kind. It **attempts to find** known indicators of the LiteLLM v1.82.7/v1.82.8 compromise but **cannot guarantee** complete detection. A clean scan does not mean your system was unaffected. Always perform credential rotation if there is any possibility that a compromised version was installed in your environment, even briefly.
