"""Shared fixtures for the scan_supply_chain test suite."""

from pathlib import Path

import pytest

from scan_supply_chain.models import (
    ConfigReference,
    Installation,
    ScanResults,
    SourceReference,
)
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

    name = "TestOS"
    platform_key = "linux"
    search_roots: list[str] = []
    conda_globs: list[str] = []
    network_check_command = None
    exclusion_note = "test note"

    def home_conda_dirs(self) -> list[str]:
        return []

    def home_pipx_dir(self) -> Path | None:
        return None


# ── Stub ecosystem ────────────────────────────────────────────────────


class StubEcosystem:
    """Minimal EcosystemPlugin for tests."""

    name = "stub"
    source_extensions = frozenset({".py"})
    config_filenames = frozenset({"requirements.txt"})
    config_extensions = frozenset({".toml"})

    def metadata_dir_pattern(self, package):
        import re

        return re.compile(rf"^{re.escape(package)}-([^/\\]+)\.(dist-info|egg-info)$")

    def extract_version(self, metadata_path):
        return None

    def import_patterns(self, package):
        return []

    def dep_patterns(self, package):
        return []

    def pinned_version_pattern(self, package):
        import re

        return re.compile(rf"{re.escape(package)}==([0-9][0-9a-zA-Z.*]+)")

    def config_filename_pattern(self):
        return None

    def extra_search_roots(self):
        return []

    def find_phantom_deps(self, names, roots):
        return []


# ── Stub threat profiles ──────────────────────────────────────────────


def make_litellm_threat(**overrides) -> ThreatProfile:
    """Build a litellm ThreatProfile with sensible test defaults."""
    defaults = dict(
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


def make_axios_threat(**overrides) -> ThreatProfile:
    """Build an axios ThreatProfile with sensible test defaults."""
    defaults = dict(
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


def matches_any(patterns: list, line: str) -> bool:
    """Check if any regex pattern matches a line."""
    return any(p.search(line) for p in patterns)


@pytest.fixture
def fake_home(tmp_path, monkeypatch):
    """Redirect Path.home() to tmp_path for scanner modules."""
    for mod in (
        "cache_scanner",
        "history_scanner",
        "persistence_scanner",
    ):
        monkeypatch.setattr(f"scan_supply_chain.{mod}.Path.home", lambda: tmp_path)
    return tmp_path


@pytest.fixture
def tmp_as_tmp(tmp_path):
    """Make /tmp point to tmp_path for persistence scanner tests."""
    import scan_supply_chain.persistence_scanner as ps

    original = ps.Path
    ps.Path = lambda p: tmp_path if str(p) == "/tmp" else original(p)
    yield tmp_path
    ps.Path = original
