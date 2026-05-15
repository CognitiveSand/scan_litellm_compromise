"""Per-threat scan context — bundles parameters that flow through every phase."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from .skip_report import SkipReport

if TYPE_CHECKING:
    from .ecosystem_base import EcosystemPlugin
    from .platform_policy import PlatformPolicy
    from .threat_profile import ThreatProfile


@dataclass(frozen=True)
class ScanContext:
    """Per-threat scan context.

    Collapses ``(threat, ecosystem, policy, roots, resolve_c2,
    skip_report)`` — six values that flow together through every
    phase — into a single carrier. Phase signatures become
    ``(results, ctx)`` instead of a long parameter list, and the
    data dependencies are visible in one place.

    The ``skip_report`` field is shared across all threats in a
    single scan: the orchestrator constructs one ``SkipReport`` and
    each per-threat context references it, so the post-scan summary
    aggregates skips from every threat's filesystem walk.
    """

    threat: ThreatProfile
    ecosystem: EcosystemPlugin
    policy: PlatformPolicy
    roots: list[str]
    resolve_c2: bool = False
    skip_report: SkipReport = field(default_factory=SkipReport)
