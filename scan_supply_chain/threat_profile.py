"""Threat profile loader — reads TOML definitions into typed dataclasses."""

from __future__ import annotations

import logging
import os
import sys
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

# ── Sub-structures ──────────────────────────────────────────────────────


@dataclass(frozen=True)
class C2Info:
    domains: list[str] = field(default_factory=list)
    ports: list[int] = field(default_factory=list)
    ips: dict[str, list[str]] = field(default_factory=dict)


@dataclass(frozen=True)
class WalkFileIOC:
    """IOC files to locate by walking filesystem search roots."""

    description: str = ""
    filenames: list[str] = field(default_factory=list)
    sha256: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class KnownPathIOC:
    """IOC files at known absolute paths, per platform."""

    description: str = ""
    linux: list[str] = field(default_factory=list)
    darwin: list[str] = field(default_factory=list)
    windows: list[str] = field(default_factory=list)

    def paths_for_platform(self) -> list[str]:
        """Return paths for the current OS."""
        if sys.platform == "win32":
            return self.windows
        if sys.platform == "darwin":
            return self.darwin
        return self.linux


@dataclass(frozen=True)
class KubernetesIOC:
    pod_patterns: list[str] = field(default_factory=list)
    namespace: str = ""


@dataclass(frozen=True)
class WindowsIOC:
    registry_keywords: list[str] = field(default_factory=list)
    schtask_keywords: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class RemediationInfo:
    rotate_secrets: bool = True
    install_command: str = ""
    remove_artifacts: dict[str, list[str]] = field(default_factory=dict)
    check_persistence: dict[str, list[str]] = field(default_factory=dict)

    def artifact_lines_for_platform(self) -> list[str]:
        if sys.platform == "win32":
            return self.remove_artifacts.get("windows", [])
        if sys.platform == "darwin":
            return self.remove_artifacts.get("darwin", [])
        return self.remove_artifacts.get("linux", [])

    def persistence_steps_for_platform(self) -> list[str]:
        if sys.platform == "win32":
            return self.check_persistence.get("windows", [])
        if sys.platform == "darwin":
            return self.check_persistence.get("darwin", [])
        return self.check_persistence.get("linux", [])


# ── Main profile ───────────────────────────────────────────────────────


@dataclass(frozen=True)
class ThreatProfile:
    id: str
    name: str
    date: str
    ecosystem: str  # "pypi" or "npm"
    package: str
    compromised: frozenset[str]
    safe: str
    advisory: str
    description: str = ""
    c2: C2Info = field(default_factory=C2Info)
    walk_files: list[WalkFileIOC] = field(default_factory=list)
    known_paths: list[KnownPathIOC] = field(default_factory=list)
    phantom_deps: list[str] = field(default_factory=list)
    kubernetes: KubernetesIOC = field(default_factory=KubernetesIOC)
    windows_ioc: WindowsIOC = field(default_factory=WindowsIOC)
    remediation: RemediationInfo = field(default_factory=RemediationInfo)


# ── TOML parsing ────────────────────────────────────────────────────────


def _parse_c2(raw: dict) -> C2Info:
    return C2Info(
        domains=raw.get("domains", []),
        ports=raw.get("ports", []),
        ips=raw.get("ips", {}),
    )


def _parse_walk_files(raw_list: list[dict]) -> list[WalkFileIOC]:
    return [
        WalkFileIOC(
            description=item.get("description", ""),
            filenames=item.get("filenames", []),
            sha256=item.get("sha256", []),
        )
        for item in raw_list
    ]


def _parse_known_paths(raw_list: list[dict]) -> list[KnownPathIOC]:
    return [
        KnownPathIOC(
            description=item.get("description", ""),
            linux=item.get("linux", []),
            darwin=item.get("darwin", []),
            windows=item.get("windows", []),
        )
        for item in raw_list
    ]


def _parse_remediation(raw: dict) -> RemediationInfo:
    return RemediationInfo(
        rotate_secrets=raw.get("rotate_secrets", True),
        install_command=raw.get("install_command", ""),
        remove_artifacts=raw.get("remove_artifacts", {}),
        check_persistence=raw.get("check_persistence", {}),
    )


def _parse_profile(data: dict) -> ThreatProfile:
    """Parse a raw TOML dict into a ThreatProfile."""
    threat = data.get("threat", {})
    ioc = data.get("ioc", {})

    return ThreatProfile(
        id=threat["id"],
        name=threat["name"],
        date=threat.get("date", ""),
        ecosystem=threat["ecosystem"],
        package=threat["package"],
        compromised=frozenset(threat.get("compromised", [])),
        safe=threat.get("safe", ""),
        advisory=threat.get("advisory", ""),
        description=threat.get("description", ""),
        c2=_parse_c2(data.get("c2", {})),
        walk_files=_parse_walk_files(ioc.get("walk_files", [])),
        known_paths=_parse_known_paths(ioc.get("known_paths", [])),
        phantom_deps=ioc.get("phantom_deps", {}).get("names", []),
        kubernetes=KubernetesIOC(
            pod_patterns=ioc.get("kubernetes", {}).get("pod_patterns", []),
            namespace=ioc.get("kubernetes", {}).get("namespace", ""),
        ),
        windows_ioc=WindowsIOC(
            registry_keywords=ioc.get("windows", {}).get("registry_keywords", []),
            schtask_keywords=ioc.get("windows", {}).get("schtask_keywords", []),
        ),
        remediation=_parse_remediation(data.get("remediation", {})),
    )


# ── Loading functions ───────────────────────────────────────────────────

# Built-in threats ship inside the package.
_BUILTIN_DIR = Path(__file__).resolve().parent / "threats"

# User-local overrides / additions.
if sys.platform == "win32":
    _base = os.environ.get("LOCALAPPDATA", "")
    _USER_DIR = Path(_base) / "scan-supply-chain" / "threats" if _base else None
else:
    _xdg = os.environ.get("XDG_CONFIG_HOME", "")
    _home_config = Path(_xdg) if _xdg else Path.home() / ".config"
    _USER_DIR = _home_config / "scan-supply-chain" / "threats"


def load_threat_file(path: Path) -> ThreatProfile:
    """Load a single threat profile from a TOML file."""
    with open(path, "rb") as f:
        data = tomllib.load(f)
    return _parse_profile(data)


def _load_from_dir(directory: Path) -> dict[str, ThreatProfile]:
    """Load all .toml profiles from a directory, keyed by threat id."""
    profiles: dict[str, ThreatProfile] = {}
    if not directory.is_dir():
        return profiles
    for toml_path in sorted(directory.glob("*.toml")):
        try:
            profile = load_threat_file(toml_path)
            profiles[profile.id] = profile
        except (KeyError, tomllib.TOMLDecodeError) as exc:
            logger.warning("Skipping %s: %s", toml_path.name, exc)
    return profiles


def load_all_threats() -> list[ThreatProfile]:
    """Load all threat profiles (built-in + user-local, user overrides built-in)."""
    profiles = _load_from_dir(_BUILTIN_DIR)
    if _USER_DIR is not None:
        user_profiles = _load_from_dir(_USER_DIR)
        profiles.update(user_profiles)  # user overrides built-in by id
    return sorted(profiles.values(), key=lambda p: p.date)


def load_threat_by_id(threat_id: str) -> ThreatProfile | None:
    """Load a specific threat profile by id."""
    for profile in load_all_threats():
        if profile.id == threat_id:
            return profile
    return None


def list_available_threats() -> list[ThreatProfile]:
    """Return all available threat profiles for --list-threats."""
    return load_all_threats()
