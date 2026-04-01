"""Phase 2: Check package versions from discovered metadata directories."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING

from .formatting import BOLD, GREEN, RED, RESET
from .models import Installation, ScanResults

if TYPE_CHECKING:
    from .ecosystem_base import EcosystemPlugin
    from .threat_profile import ThreatProfile

logger = logging.getLogger(__name__)


def _report_installation(
    installation: Installation,
    package: str,
    compromised: frozenset[str],
) -> None:
    """Print a single installation's status."""
    if installation.version in compromised:
        print(
            f"  {RED}{BOLD}! COMPROMISED{RESET}  "
            f"{package}=={installation.version}  ->  {installation.env_path}"
        )
    else:
        print(
            f"  {GREEN}+ clean{RESET}        "
            f"{package}=={installation.version}  ->  {installation.env_path}"
        )


def scan_environments(
    metadata_dirs: list[Path],
    results: ScanResults,
    ecosystem: EcosystemPlugin,
    threat: ThreatProfile,
) -> None:
    """Check each discovered metadata directory for package version."""
    for metadata_dir in metadata_dirs:
        results.envs_scanned += 1
        version = ecosystem.extract_version(metadata_dir)
        if version is None:
            logger.debug("Could not determine version from %s", metadata_dir)
            continue

        installation = Installation(env_path=str(metadata_dir), version=version)
        results.installations.append(installation)
        _report_installation(installation, threat.package, threat.compromised)

    if not results.installations:
        print(
            f"  {GREEN}No {threat.package} installations found "
            f"in {results.envs_scanned} locations.{RESET}"
        )
