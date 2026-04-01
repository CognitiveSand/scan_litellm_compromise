"""Tests for evidence scoring — confidence tier computation.

Module under test: scan_supply_chain.scoring
"""

from scan_supply_chain.models import Confidence, Finding, FindingCategory
from scan_supply_chain.scoring import compute_confidence


class TestComputeConfidence:
    def test_no_findings_returns_none(self):
        # @req FR-35
        assert compute_confidence([]) is None

    def test_source_ref_only_returns_low(self):
        # @req FR-35
        findings = [
            Finding(FindingCategory.SOURCE_REF, "import litellm", "/app.py:1", 1),
        ]
        assert compute_confidence(findings) == Confidence.LOW

    def test_cache_trace_only_returns_low(self):
        # @req FR-35
        findings = [
            Finding(FindingCategory.CACHE_TRACE, "pip cache", "~/.cache/pip", 1),
        ]
        assert compute_confidence(findings) == Confidence.LOW

    def test_history_only_returns_low(self):
        # @req FR-35
        findings = [
            Finding(FindingCategory.HISTORY, "pip install litellm", ".bash_history", 1),
        ]
        assert compute_confidence(findings) == Confidence.LOW

    def test_version_match_returns_medium(self):
        # @req FR-35
        findings = [
            Finding(FindingCategory.VERSION_MATCH, "litellm==1.82.7", "/env", 3),
        ]
        assert compute_confidence(findings) == Confidence.MEDIUM

    def test_persistence_alone_returns_medium(self):
        # @req FR-35
        findings = [
            Finding(FindingCategory.PERSISTENCE, "crontab entry", "crontab -l", 2),
        ]
        assert compute_confidence(findings) == Confidence.MEDIUM

    def test_version_plus_ioc_file_returns_high(self):
        # @req FR-35
        findings = [
            Finding(FindingCategory.VERSION_MATCH, "litellm==1.82.7", "/env", 3),
            Finding(FindingCategory.IOC_FILE, "litellm_init.pth", "/site-packages", 3),
        ]
        assert compute_confidence(findings) == Confidence.HIGH

    def test_version_plus_phantom_dep_returns_high(self):
        # @req FR-35
        findings = [
            Finding(FindingCategory.VERSION_MATCH, "axios==1.14.1", "/nm", 3),
            Finding(FindingCategory.PHANTOM_DEP, "plain-crypto-js", "/nm", 3),
        ]
        assert compute_confidence(findings) == Confidence.HIGH

    def test_version_plus_c2_returns_critical(self):
        # @req FR-35
        findings = [
            Finding(FindingCategory.VERSION_MATCH, "litellm==1.82.7", "/env", 3),
            Finding(FindingCategory.C2_CONNECTION, "python3 -> C2", "142.11.206.73", 4),
        ]
        assert compute_confidence(findings) == Confidence.CRITICAL

    def test_version_plus_ioc_plus_c2_returns_critical(self):
        # @req FR-35
        findings = [
            Finding(FindingCategory.VERSION_MATCH, "litellm==1.82.7", "/env", 3),
            Finding(FindingCategory.IOC_FILE, "litellm_init.pth", "/sp", 3),
            Finding(FindingCategory.C2_CONNECTION, "python3 -> C2", "142.11.206.73", 4),
        ]
        assert compute_confidence(findings) == Confidence.CRITICAL

    def test_c2_without_version_returns_low(self):
        # @req FR-35
        findings = [
            Finding(FindingCategory.C2_CONNECTION, "unknown -> C2", "142.11.206.73", 4),
        ]
        assert compute_confidence(findings) == Confidence.LOW
