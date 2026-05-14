"""Per-threat scan context — bundles parameters that flow through every phase."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .ecosystem_base import EcosystemPlugin
    from .platform_policy import PlatformPolicy
    from .threat_profile import ThreatProfile


@dataclass(frozen=True)
class ScanContext:
    """Per-threat scan context.

    Collapses ``(threat, ecosystem, policy, roots, resolve_c2)`` — five
    values that flow together through every phase — into a single
    carrier. Phase signatures become ``(results, ctx)`` instead of a
    long parameter list, and the data dependencies are visible in one
    place.
    """

    threat: ThreatProfile
    ecosystem: EcosystemPlugin
    policy: PlatformPolicy
    roots: list[str]
    resolve_c2: bool = False
