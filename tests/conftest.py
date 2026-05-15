"""Shared fixtures for the scan_supply_chain test suite."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import Any

import pytest

from scan_supply_chain.ecosystem_base import EcosystemPlugin
from scan_supply_chain.models import (
    ConfigReference,
    Installation,
    ScanResults,
    SourceReference,
)
from scan_supply_chain.platform_policy import PlatformPolicy
from scan_supply_chain.scan_context import ScanContext
from scan_supply_chain.skip_report import SkipReport
from scan_supply_chain.threat_profile import (
    C2Info,
    KnownPathIOC,
    KubernetesIOC,
    RemediationInfo,
    ThreatProfile,
    WalkFileIOC,
    WindowsIOC,
)


# ── Compromised version sets ──────────────────────────────────────────

LITELLM_COMPROMISED = frozenset({"1.82.7", "1.82.8"})
AXIOS_COMPROMISED = frozenset({"1.14.1", "0.30.4"})


# ── Stub policy ────────────────────────────────────────────────────────


class StubPolicy:
    """Minimal PlatformPolicy satisfying the Protocol for tests."""

    name: str = "TestOS"
    platform_key: str = "linux"
    search_roots: list[str] = []
    conda_globs: list[str] = []
    network_check_command: list[str] | None = None
    exclusion_note: str = "test note"

    def home_conda_dirs(self) -> list[str]:
        return []

    def home_pipx_dir(self) -> Path | None:
        return None


# ── Stub ecosystem ────────────────────────────────────────────────────


class StubEcosystem:
    """Minimal EcosystemPlugin for tests."""

    name: str = "stub"
    source_extensions: frozenset[str] = frozenset({".py"})
    config_filenames: frozenset[str] = frozenset({"requirements.txt"})
    config_extensions: frozenset[str] = frozenset({".toml"})

    def metadata_dir_pattern(self, package: str) -> re.Pattern[str]:

        return re.compile(rf"^{re.escape(package)}-([^/\\]+)\.(dist-info|egg-info)$")

    def extract_version(
        self, metadata_path: Path, skip_report: SkipReport
    ) -> str | None:
        return None

    def import_patterns(self, package: str) -> list[re.Pattern[str]]:
        return []

    def dep_patterns(self, package: str) -> list[re.Pattern[str]]:
        return []

    def pinned_version_pattern(self, package: str) -> re.Pattern[str]:

        return re.compile(rf"{re.escape(package)}==([0-9][0-9a-zA-Z.*]+)")

    def config_filename_pattern(self) -> re.Pattern[str] | None:
        return None

    def extra_search_roots(self) -> list[str]:
        return []

    def find_phantom_deps(
        self, names: list[str], roots: list[str], skip_report: SkipReport
    ) -> list[str]:
        return []


# ── Stub threat profiles ──────────────────────────────────────────────


def make_litellm_threat(**overrides: Any) -> ThreatProfile:
    """Build a litellm ThreatProfile with sensible test defaults."""
    defaults: dict[str, Any] = dict(
        id="litellm-test",
        name="LiteLLM Test",
        date="2026-03-24",
        ecosystem="pypi",
        package="litellm",
        compromised=LITELLM_COMPROMISED,
        safe="1.82.6",
        advisory="https://example.com/litellm",
        description="test",
        c2=C2Info(
            domains=["models.litellm.cloud", "checkmarx.zone"],
            ips={
                "models.litellm.cloud": ["46.151.182.203"],
                "checkmarx.zone": ["83.142.209.11"],
            },
        ),
        walk_files=[
            WalkFileIOC(
                description="litellm_init.pth (auto-exec backdoor)",
                filenames=["litellm_init.pth"],
                sha256=[
                    "71e35aef03099cd1f2d6446734273025a163597de93912df321ef118bf135238"
                ],
            ),
        ],
        known_paths=[
            KnownPathIOC(
                description="sysmon persistence",
                linux=["~/.config/sysmon/sysmon.py"],
            ),
        ],
        phantom_deps=[],
        kubernetes=KubernetesIOC(
            pod_patterns=["node-setup-"],
            namespace="kube-system",
        ),
        windows_ioc=WindowsIOC(
            registry_keywords=["sysmon", "litellm"],
            schtask_keywords=["sysmon"],
        ),
        remediation=RemediationInfo(
            rotate_secrets=True,
            install_command="pip install litellm==1.82.6",
            remove_artifacts={"linux": ["Remove litellm_init.pth"]},
            check_persistence={"linux": ["systemctl --user list-units | grep sysmon"]},
        ),
    )
    defaults.update(overrides)
    return ThreatProfile(**defaults)


def make_axios_threat(**overrides: Any) -> ThreatProfile:
    """Build an axios ThreatProfile with sensible test defaults."""
    defaults: dict[str, Any] = dict(
        id="axios-test",
        name="Axios Test",
        date="2026-03-31",
        ecosystem="npm",
        package="axios",
        compromised=AXIOS_COMPROMISED,
        safe="1.14.0",
        advisory="https://example.com/axios",
        description="test",
        c2=C2Info(
            domains=["sfrclak.com"],
            ips={"sfrclak.com": ["142.11.206.73"]},
            ports=[8000],
        ),
        walk_files=[],
        known_paths=[
            KnownPathIOC(
                description="RAT payload",
                linux=["/tmp/ld.py"],
            ),
        ],
        phantom_deps=["plain-crypto-js"],
        kubernetes=KubernetesIOC(),
        windows_ioc=WindowsIOC(),
        remediation=RemediationInfo(
            rotate_secrets=True,
            install_command="npm install axios@1.14.0",
            remove_artifacts={"linux": ["Remove /tmp/ld.py"]},
            check_persistence={"linux": ["ps aux | grep ld.py"]},
        ),
    )
    defaults.update(overrides)
    return ThreatProfile(**defaults)


def make_scan_context(
    threat: ThreatProfile,
    ecosystem: EcosystemPlugin,
    roots: list[str],
    *,
    policy: PlatformPolicy | None = None,
    resolve_c2: bool = False,
) -> ScanContext:
    """Build a ScanContext for tests with sensible defaults."""
    return ScanContext(
        threat=threat,
        ecosystem=ecosystem,
        policy=policy or StubPolicy(),
        roots=roots,
        resolve_c2=resolve_c2,
    )


# ── Model fixtures ─────────────────────────────────────────────────────


@pytest.fixture
def clean_results() -> ScanResults:
    return ScanResults(compromised_versions=LITELLM_COMPROMISED)


@pytest.fixture
def compromised_installation() -> Installation:
    return Installation(env_path="/fake/env", version="1.82.7")


@pytest.fixture
def safe_installation() -> Installation:
    return Installation(env_path="/fake/env", version="1.82.6")


@pytest.fixture
def sample_source_ref() -> SourceReference:
    return SourceReference(
        file_path="/fake/app.py", line_number=10, line_content="import litellm"
    )


@pytest.fixture
def sample_config_ref_compromised() -> ConfigReference:
    return ConfigReference(
        file_path="/fake/requirements.txt",
        line_number=3,
        line_content="litellm==1.82.7",
        pinned_version="1.82.7",
    )


@pytest.fixture
def sample_config_ref_safe() -> ConfigReference:
    return ConfigReference(
        file_path="/fake/requirements.txt",
        line_number=3,
        line_content="litellm==1.80.0",
        pinned_version="1.80.0",
    )


@pytest.fixture
def stub_policy() -> StubPolicy:
    return StubPolicy()


@pytest.fixture
def stub_ecosystem() -> StubEcosystem:
    return StubEcosystem()


@pytest.fixture
def litellm_threat() -> ThreatProfile:
    return make_litellm_threat()


@pytest.fixture
def axios_threat() -> ThreatProfile:
    return make_axios_threat()


# ── Shared test helpers ───────────────────────────────────────────────


@pytest.fixture
def scan_results() -> ScanResults:
    """Fresh ScanResults with no compromised versions set."""
    return ScanResults()


def matches_any(patterns: list[re.Pattern[str]], line: str) -> bool:
    """Check if any regex pattern matches a line."""
    return any(p.search(line) for p in patterns)


def mock_subprocess_run(
    monkeypatch: pytest.MonkeyPatch, module: str, stdout: str
) -> None:
    """Patch subprocess.run in a scan_supply_chain module."""
    monkeypatch.setattr(
        f"scan_supply_chain.{module}.subprocess.run",
        lambda *a, **kw: subprocess.CompletedProcess(
            args=a[0],
            returncode=0,
            stdout=stdout,
        ),
    )


def mock_subprocess_timeout(monkeypatch: pytest.MonkeyPatch, module: str) -> None:
    """Patch subprocess.run in a module to raise TimeoutExpired."""
    monkeypatch.setattr(
        f"scan_supply_chain.{module}.subprocess.run",
        lambda *a, **kw: (_ for _ in ()).throw(
            subprocess.TimeoutExpired(cmd=a[0], timeout=5),
        ),
    )


def mock_run_safe(
    monkeypatch: pytest.MonkeyPatch, module: str, stdout: str | None
) -> None:
    """Patch run_safe in a scan_supply_chain module."""
    monkeypatch.setattr(
        f"scan_supply_chain.{module}.run_safe",
        lambda *a, **kw: stdout,
    )


def mock_tool_available(
    monkeypatch: pytest.MonkeyPatch, module: str, tool: str
) -> None:
    """Patch shutil.which to find a specific tool."""
    monkeypatch.setattr(
        f"scan_supply_chain.{module}.shutil.which",
        lambda cmd: f"/usr/bin/{tool}" if cmd == tool else None,
    )


@pytest.fixture
def fake_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Redirect Path.home() to tmp_path for scanner modules."""
    for mod in (
        "cache_scanner",
        "history_scanner",
        "persistence_scanner",
    ):
        monkeypatch.setattr(f"scan_supply_chain.{mod}.Path.home", lambda: tmp_path)
    return tmp_path


@pytest.fixture
def tmp_as_tmp(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Make /tmp point to tmp_path for persistence scanner tests."""
    monkeypatch.setattr(
        "scan_supply_chain.persistence_scanner.Path",
        lambda p: tmp_path if str(p) == "/tmp" else Path(p),
    )
    return tmp_path
