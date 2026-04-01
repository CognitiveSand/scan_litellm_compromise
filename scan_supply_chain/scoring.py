"""Evidence scoring — computes confidence tier from findings.

Pure function: no I/O, no side effects, easy to test.
"""

from __future__ import annotations

from .models import Confidence, Finding, FindingCategory


def compute_confidence(findings: list[Finding]) -> Confidence | None:
    """Compute a confidence tier from a list of findings.

    Returns None when there are no findings at all.
    """
    if not findings:
        return None

    categories = {f.category for f in findings}

    has_version = FindingCategory.VERSION_MATCH in categories
    has_ioc_file = FindingCategory.IOC_FILE in categories
    has_c2 = FindingCategory.C2_CONNECTION in categories
    has_phantom = FindingCategory.PHANTOM_DEP in categories
    has_persistence = FindingCategory.PERSISTENCE in categories

    if has_version and has_c2:
        return Confidence.CRITICAL
    if has_version and (has_ioc_file or has_phantom):
        return Confidence.HIGH
    if has_version or has_persistence:
        return Confidence.MEDIUM
    return Confidence.LOW
