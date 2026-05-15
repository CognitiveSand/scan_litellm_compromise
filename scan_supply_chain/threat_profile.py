"""Threat profile loader — reads TOML definitions into typed dataclasses."""

from __future__ import annotations

import logging
import os
import re
import sys
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, TypeVar

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


_PlatformT = TypeVar("_PlatformT")


def _for_current_platform(
    *, linux: _PlatformT, darwin: _PlatformT, windows: _PlatformT
) -> _PlatformT:
    """Select the value matching the current OS."""
    if sys.platform == "win32":
        return windows
    if sys.platform == "darwin":
        return darwin
    return linux


@dataclass(frozen=True)
class KnownPathIOC:
    """IOC files at known absolute paths, per platform."""

    description: str = ""
    linux: list[str] = field(default_factory=list)
    darwin: list[str] = field(default_factory=list)
    windows: list[str] = field(default_factory=list)

    def paths_for_platform(self) -> list[str]:
        """Return paths for the current OS."""
        return _for_current_platform(
            linux=self.linux, darwin=self.darwin, windows=self.windows
        )


@dataclass(frozen=True)
class KubernetesIOC:
    pod_patterns: list[str] = field(default_factory=list)
    namespace: str = ""


@dataclass(frozen=True)
class WindowsIOC:
    registry_keywords: list[str] = field(default_factory=list)
    schtask_keywords: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class GitArtifactsIOC:
    """Worm-class indicators that live in local git repos.

    Consumed by the anti-worm pre-pass (``anti_worm_scanner``). Threat
    profiles that describe self-propagating campaigns (Shai-Hulud and
    similar) define this block; threats that don't, leave it empty.

    Regex fields are validated and compiled at load time: an invalid
    pattern raises ``re.error`` from ``load_threat_file`` so the
    operator sees the malformed indicator immediately, rather than the
    pattern being silently dropped from the scan.
    """

    workflow_filenames: tuple[str, ...] = ()
    workflow_name_regexes: tuple[re.Pattern[str], ...] = ()
    branch_names: tuple[str, ...] = ()
    branch_name_regexes: tuple[re.Pattern[str], ...] = ()
    commit_author_emails: tuple[str, ...] = ()
    repo_descriptions: tuple[str, ...] = ()

    @property
    def is_empty(self) -> bool:
        return not (
            self.workflow_filenames
            or self.workflow_name_regexes
            or self.branch_names
            or self.branch_name_regexes
            or self.commit_author_emails
            or self.repo_descriptions
        )


@dataclass(frozen=True)
class RemediationInfo:
    rotate_secrets: bool = True
    install_command: str = ""
    remove_artifacts: dict[str, list[str]] = field(default_factory=dict)
    check_persistence: dict[str, list[str]] = field(default_factory=dict)

    def artifact_lines_for_platform(self) -> list[str]:
        return _for_current_platform(
            linux=self.remove_artifacts.get("linux", []),
            darwin=self.remove_artifacts.get("darwin", []),
            windows=self.remove_artifacts.get("windows", []),
        )

    def persistence_steps_for_platform(self) -> list[str]:
        return _for_current_platform(
            linux=self.check_persistence.get("linux", []),
            darwin=self.check_persistence.get("darwin", []),
            windows=self.check_persistence.get("windows", []),
        )


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
    persistence_keywords: tuple[str, ...] = ()
    git_artifacts: GitArtifactsIOC = field(default_factory=GitArtifactsIOC)
    remediation: RemediationInfo = field(default_factory=RemediationInfo)


# ── TOML parsing ────────────────────────────────────────────────────────

# Known-key schemas — every section's expected keys are listed here.
# An unknown key (typically a typo like ``ecosytem``) raises
# ``UnknownProfileKeyError`` at parse time so the operator sees the bad
# field rather than silently losing the value to a default.
_TOP_LEVEL_KEYS: frozenset[str] = frozenset({"threat", "c2", "ioc", "remediation"})
_THREAT_KEYS: frozenset[str] = frozenset(
    {
        "id",
        "name",
        "date",
        "ecosystem",
        "package",
        "compromised",
        "safe",
        "advisory",
        "description",
    }
)
_C2_KEYS: frozenset[str] = frozenset({"domains", "ports", "ips"})
_IOC_KEYS: frozenset[str] = frozenset(
    {
        "walk_files",
        "known_paths",
        "phantom_deps",
        "kubernetes",
        "windows",
        "persistence_keywords",
        "git_artifacts",
    }
)
_WALK_FILE_KEYS: frozenset[str] = frozenset({"description", "filenames", "sha256"})
_KNOWN_PATH_KEYS: frozenset[str] = frozenset(
    {
        "description",
        "linux",
        "darwin",
        "windows",
    }
)
_PHANTOM_DEPS_KEYS: frozenset[str] = frozenset({"names"})
_KUBERNETES_KEYS: frozenset[str] = frozenset({"pod_patterns", "namespace"})
_WINDOWS_KEYS: frozenset[str] = frozenset({"registry_keywords", "schtask_keywords"})
_PERSISTENCE_KEYWORDS_KEYS: frozenset[str] = frozenset({"terms"})
_GIT_ARTIFACTS_KEYS: frozenset[str] = frozenset(
    {
        "workflow_filenames",
        "workflow_name_regexes",
        "branch_names",
        "branch_name_regexes",
        "commit_author_emails",
        "repo_descriptions",
    }
)
_REMEDIATION_KEYS: frozenset[str] = frozenset(
    {
        "rotate_secrets",
        "install_command",
        "remove_artifacts",
        "check_persistence",
    }
)
_PLATFORM_KEYS: frozenset[str] = frozenset({"linux", "darwin", "windows"})


class UnknownProfileKeyError(ValueError):
    """A threat-profile section contains a key not in the documented schema.

    Almost always a typo (e.g. ``ecosytem`` instead of ``ecosystem``).
    Raised at parse time so the value is not silently lost to a default.
    """


def _check_keys(section_label: str, raw: dict[str, Any], known: frozenset[str]) -> None:
    extra = set(raw) - known
    if extra:
        raise UnknownProfileKeyError(
            f"unknown key(s) in [{section_label}]: {sorted(extra)} "
            f"(expected one of: {sorted(known)})"
        )


def _parse_c2(raw: dict[str, Any]) -> C2Info:
    _check_keys("c2", raw, _C2_KEYS)
    return C2Info(
        domains=raw.get("domains", []),
        ports=raw.get("ports", []),
        ips=raw.get("ips", {}),
    )


def _parse_walk_files(raw_list: list[dict[str, Any]]) -> list[WalkFileIOC]:
    profiles: list[WalkFileIOC] = []
    for item in raw_list:
        _check_keys("ioc.walk_files", item, _WALK_FILE_KEYS)
        profiles.append(
            WalkFileIOC(
                description=item.get("description", ""),
                filenames=item.get("filenames", []),
                sha256=item.get("sha256", []),
            )
        )
    return profiles


def _parse_known_paths(raw_list: list[dict[str, Any]]) -> list[KnownPathIOC]:
    profiles: list[KnownPathIOC] = []
    for item in raw_list:
        _check_keys("ioc.known_paths", item, _KNOWN_PATH_KEYS)
        profiles.append(
            KnownPathIOC(
                description=item.get("description", ""),
                linux=item.get("linux", []),
                darwin=item.get("darwin", []),
                windows=item.get("windows", []),
            )
        )
    return profiles


def _compile_patterns(raw: list[str], field_name: str) -> tuple[re.Pattern[str], ...]:
    """Compile a list of regex strings at load time.

    A malformed pattern raises ``re.error`` with a message that names
    the offending field and pattern so the operator can find it in the
    TOML file.
    """
    compiled: list[re.Pattern[str]] = []
    for pattern_str in raw:
        try:
            compiled.append(re.compile(pattern_str))
        except re.error as exc:
            raise re.error(
                f"invalid pattern in {field_name}: {pattern_str!r} ({exc})"
            ) from exc
    return tuple(compiled)


def _parse_git_artifacts(raw: dict[str, Any]) -> GitArtifactsIOC:
    _check_keys("ioc.git_artifacts", raw, _GIT_ARTIFACTS_KEYS)
    return GitArtifactsIOC(
        workflow_filenames=tuple(raw.get("workflow_filenames", [])),
        workflow_name_regexes=_compile_patterns(
            raw.get("workflow_name_regexes", []),
            "ioc.git_artifacts.workflow_name_regexes",
        ),
        branch_names=tuple(raw.get("branch_names", [])),
        branch_name_regexes=_compile_patterns(
            raw.get("branch_name_regexes", []),
            "ioc.git_artifacts.branch_name_regexes",
        ),
        commit_author_emails=tuple(raw.get("commit_author_emails", [])),
        repo_descriptions=tuple(raw.get("repo_descriptions", [])),
    )


def _parse_remediation(raw: dict[str, Any]) -> RemediationInfo:
    _check_keys("remediation", raw, _REMEDIATION_KEYS)
    remove_artifacts = raw.get("remove_artifacts", {})
    _check_keys("remediation.remove_artifacts", remove_artifacts, _PLATFORM_KEYS)
    check_persistence = raw.get("check_persistence", {})
    _check_keys("remediation.check_persistence", check_persistence, _PLATFORM_KEYS)
    return RemediationInfo(
        rotate_secrets=raw.get("rotate_secrets", True),
        install_command=raw.get("install_command", ""),
        remove_artifacts=remove_artifacts,
        check_persistence=check_persistence,
    )


def _parse_kubernetes(raw: dict[str, Any]) -> KubernetesIOC:
    _check_keys("ioc.kubernetes", raw, _KUBERNETES_KEYS)
    return KubernetesIOC(
        pod_patterns=raw.get("pod_patterns", []),
        namespace=raw.get("namespace", ""),
    )


def _parse_windows_ioc(raw: dict[str, Any]) -> WindowsIOC:
    _check_keys("ioc.windows", raw, _WINDOWS_KEYS)
    return WindowsIOC(
        registry_keywords=raw.get("registry_keywords", []),
        schtask_keywords=raw.get("schtask_keywords", []),
    )


def _parse_phantom_deps(raw: dict[str, Any]) -> list[str]:
    _check_keys("ioc.phantom_deps", raw, _PHANTOM_DEPS_KEYS)
    names = raw.get("names", [])
    return list(names) if isinstance(names, list) else []


def _parse_persistence_keywords(raw: dict[str, Any]) -> tuple[str, ...]:
    _check_keys("ioc.persistence_keywords", raw, _PERSISTENCE_KEYWORDS_KEYS)
    return tuple(raw.get("terms", []))


def _parse_profile(data: dict[str, Any]) -> ThreatProfile:
    """Parse a raw TOML dict into a ThreatProfile."""
    _check_keys("<root>", data, _TOP_LEVEL_KEYS)
    threat = data.get("threat", {})
    _check_keys("threat", threat, _THREAT_KEYS)
    ioc = data.get("ioc", {})
    _check_keys("ioc", ioc, _IOC_KEYS)

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
        phantom_deps=_parse_phantom_deps(ioc.get("phantom_deps", {})),
        kubernetes=_parse_kubernetes(ioc.get("kubernetes", {})),
        windows_ioc=_parse_windows_ioc(ioc.get("windows", {})),
        persistence_keywords=_parse_persistence_keywords(
            ioc.get("persistence_keywords", {})
        ),
        git_artifacts=_parse_git_artifacts(ioc.get("git_artifacts", {})),
        remediation=_parse_remediation(data.get("remediation", {})),
    )


# ── Loading functions ───────────────────────────────────────────────────

# Built-in threats ship inside the package.
_BUILTIN_DIR = Path(__file__).resolve().parent / "threats"


def _user_threat_dir() -> Path | None:
    """Return the per-user threats directory, resolved lazily.

    Environment variables (``LOCALAPPDATA`` on Windows,
    ``XDG_CONFIG_HOME`` elsewhere) are read at call time rather than
    module import so tests that monkeypatch the environment see the
    override. Returns ``None`` on Windows when ``LOCALAPPDATA`` is
    unset — there is no sensible fallback for that platform.
    """
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA", "")
        return Path(base) / "scan-supply-chain" / "threats" if base else None
    xdg = os.environ.get("XDG_CONFIG_HOME", "")
    home_config = Path(xdg) if xdg else Path.home() / ".config"
    return home_config / "scan-supply-chain" / "threats"


def load_threat_file(path: Path) -> ThreatProfile:
    """Load a single threat profile from a TOML file."""
    with open(path, "rb") as f:
        data = tomllib.load(f)
    return _parse_profile(data)


def _load_from_dir(directory: Path) -> dict[str, ThreatProfile]:
    """Load all .toml profiles from a directory, keyed by threat id.

    A malformed profile raises ``InvalidThreatProfileError`` with the
    file path — the scanner refuses to start on a broken profile rather
    than silently skipping it. A user who wrote a profile expects it
    to be active; if it can't be loaded, they need to know.
    """
    profiles: dict[str, ThreatProfile] = {}
    if not directory.is_dir():
        return profiles
    for toml_path in sorted(directory.glob("*.toml")):
        try:
            profile = load_threat_file(toml_path)
        except (
            KeyError,
            tomllib.TOMLDecodeError,
            re.error,
            UnknownProfileKeyError,
        ) as exc:
            raise InvalidThreatProfileError(toml_path, exc) from exc
        profiles[profile.id] = profile
    return profiles


class InvalidThreatProfileError(ValueError):
    """A threat-profile TOML failed to load.

    Wraps the underlying ``KeyError`` / ``tomllib.TOMLDecodeError`` /
    ``re.error`` with the file path so the operator can locate the bad
    profile.
    """

    def __init__(self, path: Path, cause: BaseException) -> None:
        super().__init__(f"invalid threat profile {path}: {cause}")
        self.path = path
        self.__cause__ = cause


def load_all_threats() -> list[ThreatProfile]:
    """Load all threat profiles (built-in + user-local, user overrides built-in)."""
    profiles = _load_from_dir(_BUILTIN_DIR)
    user_dir = _user_threat_dir()
    if user_dir is not None:
        user_profiles = _load_from_dir(user_dir)
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
