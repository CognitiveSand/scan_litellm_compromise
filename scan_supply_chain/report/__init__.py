"""Phase 5: Summary report and remediation guidance.

Split along output type into four modules. ``from .report import X``
continues to work; the modules below own the rendering of one
section each:

* ``_references``    — source/config file reference display
* ``_threat``        — per-threat report (stats + clean/remediation verdicts)
* ``_anti_worm``     — anti-worm pre-pass section
* ``_skip``          — post-scan skipped-paths summary
* ``_summary``       — combined multi-threat header / footer
"""

from ._anti_worm import print_anti_worm_report
from ._references import print_config_refs, print_source_refs
from ._skip import print_skip_summary
from ._summary import print_multi_threat_summary
from ._threat import print_threat_report

__all__ = [
    "print_anti_worm_report",
    "print_config_refs",
    "print_multi_threat_summary",
    "print_skip_summary",
    "print_source_refs",
    "print_threat_report",
]
