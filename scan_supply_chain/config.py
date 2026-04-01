"""Generic constants shared across the scanner.

All threat-specific values (package name, compromised versions, C2 info,
IOC paths, remediation) live in threats/*.toml and are loaded via
threat_profile.py.  This module holds only ecosystem-neutral defaults.
"""

# Directories always skipped during any filesystem walk
_COMMON_SKIP_DIRS = frozenset(
    {
        "__pycache__",
        ".git",
        ".tox",
        ".mypy_cache",
        ".pytest_cache",
        ".venv-bak",
        "dist",
        "build",
        ".eggs",
        ".cache",
    }
)

# Phase 1/2 discovery needs to enter site-packages / node_modules
DISCOVERY_SKIP_DIRS = _COMMON_SKIP_DIRS

# Phase 4 source scanner skips third-party code
SOURCE_SCAN_SKIP_DIRS = _COMMON_SKIP_DIRS | {"site-packages", "node_modules"}
