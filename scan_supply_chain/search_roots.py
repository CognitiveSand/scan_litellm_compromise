"""Build the complete list of search roots — single source of truth.

Called once by the orchestrator, passed to every phase.
Discovery, IOC scanning, and source scanning all see the same roots.
"""

from __future__ import annotations

import glob as globmod
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .ecosystem_base import EcosystemPlugin
    from .platform_policy import PlatformPolicy


def build_search_roots(
    policy: PlatformPolicy,
    ecosystem: EcosystemPlugin,
) -> list[str]:
    """Combine platform roots, conda/pipx dirs, and ecosystem extras."""
    roots = list(policy.search_roots)
    home = Path.home()

    for subdir in policy.home_conda_dirs():
        candidate = home / subdir
        if candidate.is_dir():
            roots.append(str(candidate))

    pipx_dir = policy.home_pipx_dir()
    if pipx_dir is not None:
        roots.append(str(pipx_dir))

    for pattern in policy.conda_globs:
        roots.extend(globmod.glob(pattern))

    roots.extend(ecosystem.extra_search_roots())

    # Include $HOME so source/config scans cover user project directories
    home_str = str(home)
    if home_str not in roots:
        roots.append(home_str)

    return roots
