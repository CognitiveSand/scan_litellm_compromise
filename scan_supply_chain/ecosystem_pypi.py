"""PyPI ecosystem plugin — finds Python packages via dist-info/egg-info."""

from __future__ import annotations

import logging
import re
from pathlib import Path

logger = logging.getLogger(__name__)


class PyPIPlugin:
    """Discovers Python packages installed via pip/setuptools."""

    @property
    def name(self) -> str:
        return "PyPI"

    @property
    def source_extensions(self) -> frozenset[str]:
        return frozenset({".py"})

    @property
    def config_filenames(self) -> frozenset[str]:
        return frozenset(
            {
                "pyproject.toml",
                "setup.cfg",
                "setup.py",
                "requirements.txt",
                "requirements-dev.txt",
                "requirements-prod.txt",
                "Pipfile",
                "Pipfile.lock",
                "poetry.lock",
                "pdm.lock",
                "uv.lock",
            }
        )

    @property
    def config_extensions(self) -> frozenset[str]:
        return frozenset({".toml", ".cfg"})

    def metadata_dir_pattern(self, package: str) -> re.Pattern:
        escaped = re.escape(package)
        return re.compile(rf"^{escaped}-([^/\\]+)\.(dist-info|egg-info)$")

    def extract_version(self, metadata_path: Path) -> str | None:
        """Read Version from METADATA or PKG-INFO; fallback to dir name."""
        version_re = re.compile(r"^Version:\s*(.+)$", re.MULTILINE)

        for filename in ("METADATA", "PKG-INFO"):
            candidate = metadata_path / filename
            if candidate.is_file():
                try:
                    text = candidate.read_text(errors="ignore")
                except (PermissionError, OSError):
                    continue
                match = version_re.search(text)
                if match:
                    return match.group(1).strip()

        # Fallback: parse version from directory name
        # Works for both dist-info and egg-info
        dir_match = re.match(
            r"^.+-([^/\\]+)\.(dist-info|egg-info)$",
            metadata_path.name,
        )
        if dir_match:
            return dir_match.group(1)
        return None

    def import_patterns(self, package: str) -> list[re.Pattern]:
        escaped = re.escape(package)
        return [
            re.compile(rf"^\s*import\s+{escaped}"),
            re.compile(rf"^\s*from\s+{escaped}[\s.]"),
            re.compile(rf"(?<![a-zA-Z0-9_]){escaped}\."),
            re.compile(rf"""["']{escaped}["']"""),
        ]

    def dep_patterns(self, package: str) -> list[re.Pattern]:
        escaped = re.escape(package)
        return [
            # TOML dependency: litellm>=1.0
            re.compile(rf"(?<![a-zA-Z0-9_-]){escaped}\s*[=<>!~]"),
            # Bare quoted: "litellm"
            re.compile(rf"""["']{escaped}["']"""),
            # Requirements line: litellm or litellm==1.0
            re.compile(rf"^\s*{escaped}\s*([=<>!~]|$)"),
        ]

    def pinned_version_pattern(self, package: str) -> re.Pattern:
        escaped = re.escape(package)
        return re.compile(rf"(?<![a-zA-Z0-9_-]){escaped}\s*==\s*([0-9][0-9a-zA-Z.*]+)")

    def config_filename_pattern(self) -> re.Pattern | None:
        return re.compile(r"^requirements.*\.txt$")

    def extra_search_roots(self) -> list[str]:
        return []

    def find_phantom_deps(
        self,
        names: list[str],
        search_roots: list[str],
    ) -> list[str]:
        """Check for phantom PyPI packages in site-packages."""
        if not names:
            return []
        found: list[str] = []
        for root in search_roots:
            root_path = Path(root)
            if not root_path.is_dir():
                continue
            try:
                for dirpath, dirnames, _ in _walk_site_packages(root_path):
                    for name in names:
                        pattern = re.compile(
                            rf"^{re.escape(name)}-[^/\\]+\.(dist-info|egg-info)$"
                        )
                        for d in dirnames:
                            if pattern.match(d):
                                full = Path(dirpath) / d
                                found.append(f"phantom:{name} at {full}")
            except PermissionError:
                logger.debug("Permission denied walking %s", root)
        return found


def _walk_site_packages(root: Path):
    """Walk looking for site-packages, then check contents."""
    import os

    for dirpath, dirnames, filenames in os.walk(root):
        if Path(dirpath).name == "site-packages":
            yield dirpath, dirnames, filenames
        # Prune non-productive subtrees
        dirnames[:] = [
            d
            for d in dirnames
            if d not in {"__pycache__", ".git", "node_modules", ".tox"}
        ]
