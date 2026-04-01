"""Data structures for scan results."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field
from enum import Enum
from typing import Generator


@dataclass(frozen=True)
class Installation:
    """A package installation found via filesystem metadata."""

    env_path: str
    version: str


@dataclass(frozen=True)
class SourceReference:
    """A reference to the package found in a source file."""

    file_path: str
    line_number: int
    line_content: str


@dataclass(frozen=True)
class ConfigReference:
    """A reference to the package found in a config/dependency file."""

    file_path: str
    line_number: int
    line_content: str
    pinned_version: str | None = None


class Confidence(Enum):
    """4-tier evidence confidence level."""

    LOW = "LOW"  # source ref or cache trace only
    MEDIUM = "MEDIUM"  # compromised version OR persistence artifact
    HIGH = "HIGH"  # version + IOC file or phantom dep
    CRITICAL = "CRITICAL"  # version + IOC + active C2 connection


class FindingCategory(Enum):
    """What type of evidence a finding represents."""

    VERSION_MATCH = "version_match"
    IOC_FILE = "ioc_file"
    C2_CONNECTION = "c2_connection"
    PERSISTENCE = "persistence"
    CACHE_TRACE = "cache_trace"
    HISTORY = "history"
    SOURCE_REF = "source_ref"
    PHANTOM_DEP = "phantom_dep"


@dataclass(frozen=True)
class Finding:
    """A single piece of evidence from any scan phase."""

    category: FindingCategory
    description: str
    evidence: str  # path, command output, version string, etc.
    weight: int  # 1=low, 2=medium, 3=high, 4=critical


@dataclass
class ScanResults:
    """Aggregated results from all scan phases for a single threat."""

    compromised_versions: frozenset[str] = frozenset()
    envs_scanned: int = 0
    installations: list[Installation] = field(default_factory=list)
    iocs: list[str] = field(default_factory=list)
    source_refs: list[SourceReference] = field(default_factory=list)
    config_refs: list[ConfigReference] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    def add_finding(
        self,
        category: FindingCategory,
        description: str,
        evidence: str,
        weight: int,
    ) -> None:
        """Record a finding: print, append to iocs, append to findings."""
        from .formatting import print_ioc_found

        print_ioc_found(description)
        self.iocs.append(f"{category.value}:{description}")
        self.findings.append(Finding(category, description, evidence, weight))

    @property
    def compromised_installations(self) -> list[Installation]:
        return [i for i in self.installations if i.version in self.compromised_versions]

    @property
    def compromised_configs(self) -> list[ConfigReference]:
        return [
            r for r in self.config_refs if r.pinned_version in self.compromised_versions
        ]

    @property
    def is_clean(self) -> bool:
        return not (
            self.compromised_installations or self.iocs or self.compromised_configs
        )

    @property
    def source_files(self) -> set[str]:
        return {ref.file_path for ref in self.source_refs}

    @property
    def config_files(self) -> set[str]:
        return {ref.file_path for ref in self.config_refs}


@contextmanager
def track_findings(
    results: ScanResults, clean_message: str
) -> Generator[None, None, None]:
    """Context manager: print clean_message if no findings were added inside the block."""
    before = len(results.findings)
    yield
    if len(results.findings) == before:
        from .formatting import print_clean

        print_clean(clean_message)
