"""Data structures for scan results."""

from dataclasses import dataclass, field


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


@dataclass
class ScanResults:
    """Aggregated results from all scan phases for a single threat."""

    compromised_versions: frozenset[str] = frozenset()
    envs_scanned: int = 0
    installations: list[Installation] = field(default_factory=list)
    iocs: list[str] = field(default_factory=list)
    source_refs: list[SourceReference] = field(default_factory=list)
    config_refs: list[ConfigReference] = field(default_factory=list)

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
