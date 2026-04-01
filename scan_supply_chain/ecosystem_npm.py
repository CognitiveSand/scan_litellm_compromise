"""npm ecosystem plugin — finds Node.js packages via node_modules."""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)


class NpmPlugin:
    """Discovers npm packages installed in node_modules."""

    @property
    def name(self) -> str:
        return "npm"

    @property
    def source_extensions(self) -> frozenset[str]:
        return frozenset({".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx"})

    @property
    def config_filenames(self) -> frozenset[str]:
        return frozenset(
            {
                "package.json",
                "package-lock.json",
                "yarn.lock",
                "pnpm-lock.yaml",
                ".npmrc",
            }
        )

    @property
    def config_extensions(self) -> frozenset[str]:
        return frozenset()  # no extension-based matching for npm configs

    def metadata_dir_pattern(self, package: str) -> re.Pattern:
        # npm packages live in node_modules/{package}/
        # For scoped packages: node_modules/@scope/name/
        escaped = re.escape(package)
        return re.compile(rf"^{escaped}$")

    def extract_version(self, metadata_path: Path) -> str | None:
        """Read version from node_modules/{pkg}/package.json."""
        pkg_json = metadata_path / "package.json"
        if not pkg_json.is_file():
            return None
        try:
            data = json.loads(pkg_json.read_text(errors="ignore"))
            return data.get("version")
        except (json.JSONDecodeError, PermissionError, OSError):
            logger.debug("Cannot read %s", pkg_json)
            return None

    def import_patterns(self, package: str) -> list[re.Pattern]:
        escaped = re.escape(package)
        return [
            # require('axios') or require("axios")
            re.compile(rf"""require\s*\(\s*['"]({escaped})(?:/[^'"]*)?['"]\s*\)"""),
            # import axios from 'axios'
            re.compile(rf"""import\s+\w+\s+from\s+['"]({escaped})(?:/[^'"]*)?['"]"""),
            # import { ... } from 'axios'
            re.compile(rf"""from\s+['"]({escaped})(?:/[^'"]*)?['"]"""),
            # import 'axios' (side-effect import)
            re.compile(rf"""import\s+['"]({escaped})(?:/[^'"]*)?['"]"""),
        ]

    def dep_patterns(self, package: str) -> list[re.Pattern]:
        escaped = re.escape(package)
        return [
            # package.json: "axios": "^1.14.0"
            re.compile(rf"""["']{escaped}["']\s*:"""),
            # yarn.lock / pnpm-lock: axios@^1.14.0
            re.compile(rf"(?<![a-zA-Z0-9_@/-]){escaped}@"),
            # package-lock.json: "node_modules/axios"
            re.compile(rf"""["']node_modules/{escaped}["']"""),
        ]

    def pinned_version_pattern(self, package: str) -> re.Pattern:
        escaped = re.escape(package)
        # Matches both:
        #   "axios": "1.14.1"  (package.json dependency)
        #   "version": "1.14.1"  (package-lock.json resolved entry)
        return re.compile(
            rf"""(?:["']{escaped}["']|["']version["'])\s*:\s*["']([0-9][0-9a-zA-Z.*-]*)["']"""
        )

    def config_filename_pattern(self) -> re.Pattern | None:
        return None  # no dynamic config filenames for npm

    def extra_search_roots(self) -> list[str]:
        """Add global npm prefix to search roots."""
        roots: list[str] = []
        # Global npm modules
        if shutil.which("npm"):
            try:
                result = subprocess.run(
                    ["npm", "root", "-g"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                if result.returncode == 0:
                    global_root = result.stdout.strip()
                    if global_root and Path(global_root).is_dir():
                        roots.append(global_root)
            except (subprocess.TimeoutExpired, OSError):
                logger.debug("Failed to get global npm root")

        # nvm installations
        home = Path.home()
        nvm_dir = home / ".nvm" / "versions" / "node"
        if nvm_dir.is_dir():
            for node_version in nvm_dir.iterdir():
                lib_nm = node_version / "lib" / "node_modules"
                if lib_nm.is_dir():
                    roots.append(str(lib_nm))

        return roots

    def find_phantom_deps(
        self,
        names: list[str],
        search_roots: list[str],
    ) -> list[str]:
        """Check for phantom npm dependencies in node_modules."""
        if not names:
            return []
        found: list[str] = []
        seen: set[str] = set()

        for root in search_roots:
            root_path = Path(root)
            if not root_path.is_dir():
                continue
            try:
                for dirpath, dirnames, filenames in os.walk(root_path):
                    dp = Path(dirpath)
                    # Only inspect node_modules directories
                    if dp.name == "node_modules":
                        for name in names:
                            phantom_dir = dp / name
                            if phantom_dir.is_dir():
                                resolved = str(phantom_dir.resolve())
                                if resolved not in seen:
                                    seen.add(resolved)
                                    found.append(f"phantom:{name} at {phantom_dir}")
                    # Also check lockfiles in project directories
                    for fn in filenames:
                        if fn == "package-lock.json":
                            lock_path = dp / fn
                            for hit in _check_package_lock_json(lock_path, names, seen):
                                found.append(hit)
                        elif fn == "yarn.lock":
                            lock_path = dp / fn
                            for hit in _check_yarn_lock(lock_path, names, seen):
                                found.append(hit)
                        elif fn == "pnpm-lock.yaml":
                            lock_path = dp / fn
                            for hit in _check_pnpm_lock(lock_path, names, seen):
                                found.append(hit)
                    # Prune unproductive subtrees
                    dirnames[:] = [
                        d
                        for d in dirnames
                        if d
                        not in {
                            ".git",
                            "__pycache__",
                            ".tox",
                            "dist",
                            "build",
                            ".cache",
                        }
                    ]
            except PermissionError:
                logger.debug("Permission denied walking %s", root)
        return found


def _check_package_lock_json(
    lock_path: Path,
    names: list[str],
    seen: set[str],
) -> list[str]:
    """Structurally parse package-lock.json for phantom dependencies."""
    found: list[str] = []
    try:
        data = json.loads(lock_path.read_text(errors="ignore"))
    except (json.JSONDecodeError, PermissionError, OSError):
        return found

    name_set = set(names)

    # lockfileVersion 2/3: "packages" has keys like "node_modules/plain-crypto-js"
    packages = data.get("packages", {})
    for pkg_key in packages:
        pkg_name = (
            pkg_key.rsplit("node_modules/", 1)[-1] if "node_modules/" in pkg_key else ""
        )
        if pkg_name in name_set:
            key = f"{lock_path}:{pkg_name}"
            if key not in seen:
                seen.add(key)
                version = packages[pkg_key].get("version", "?")
                found.append(f"phantom:{pkg_name}@{version} in {lock_path}")

    # lockfileVersion 1: "dependencies" at top level
    deps = data.get("dependencies", {})
    for dep_name, dep_info in deps.items():
        if dep_name in name_set:
            key = f"{lock_path}:{dep_name}"
            if key not in seen:
                seen.add(key)
                version = (
                    dep_info.get("version", "?") if isinstance(dep_info, dict) else "?"
                )
                found.append(f"phantom:{dep_name}@{version} in {lock_path}")

    return found


def _check_yarn_lock(
    lock_path: Path,
    names: list[str],
    seen: set[str],
) -> list[str]:
    """Check yarn.lock for phantom dependencies by line matching.

    yarn.lock is not JSON — it uses a custom format where each entry
    starts with the package name at column 0. We match lines like:
      plain-crypto-js@^4.2.1:
    """
    found: list[str] = []
    try:
        text = lock_path.read_text(errors="ignore")
    except (PermissionError, OSError):
        return found

    for name in names:
        # Match "name@" at start of line (yarn.lock entry header)
        if f"\n{name}@" in text or text.startswith(f"{name}@"):
            key = f"{lock_path}:{name}"
            if key not in seen:
                seen.add(key)
                found.append(f"phantom:{name} in {lock_path}")

    return found


def _check_pnpm_lock(
    lock_path: Path,
    names: list[str],
    seen: set[str],
) -> list[str]:
    """Check pnpm-lock.yaml for phantom dependencies by line matching.

    pnpm-lock.yaml uses two key formats across versions:
      v6 (packages section):  /plain-crypto-js@4.2.1:
      v9 (packages section):  plain-crypto-js@4.2.1:
      v6/v9 (importers):        plain-crypto-js:
    The regex ^/?{name}@ covers both package key formats.
    """
    found: list[str] = []
    try:
        text = lock_path.read_text(errors="ignore")
    except (PermissionError, OSError):
        return found

    for name in names:
        escaped = re.escape(name)
        # Match packages/snapshots keys: /name@version: (v6) or name@version: (v9)
        # Keys may be indented with whitespace in the YAML
        pattern = re.compile(rf"^\s*/?{escaped}@", re.MULTILINE)
        if pattern.search(text):
            key = f"{lock_path}:{name}"
            if key not in seen:
                seen.add(key)
                found.append(f"phantom:{name} in {lock_path}")

    return found
