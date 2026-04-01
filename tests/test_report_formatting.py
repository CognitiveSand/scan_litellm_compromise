"""Tests for Phase 5: summary report and output formatting.

Module under test: scan_supply_chain.report
"""

from scan_supply_chain.models import (
    ConfigReference,
    Installation,
    ScanResults,
    SourceReference,
)
from scan_supply_chain.report import (
    print_config_refs,
    print_source_refs,
    print_threat_report,
    print_multi_threat_summary,
)

from tests.conftest import LITELLM_COMPROMISED, make_litellm_threat


# ── print_source_refs ─────────────────────────────────────────────────


class TestPrintSourceRefs:
    def test_prints_clean_message_when_no_refs(self, capsys):
        # @req FR-20
        print_source_refs([], "litellm")
        captured = capsys.readouterr().out
        assert "No litellm imports found" in captured

    def test_groups_refs_by_file(self, capsys):
        # @req FR-20
        refs = [
            SourceReference("/a.py", 1, "import litellm"),
            SourceReference("/a.py", 5, "litellm.completion()"),
            SourceReference("/b.py", 3, "from litellm import x"),
        ]
        print_source_refs(refs, "litellm")
        captured = capsys.readouterr().out
        assert "2 files" in captured
        assert "/a.py" in captured
        assert "/b.py" in captured

    def test_truncates_long_file_lists(self, capsys):
        # @req FR-20
        refs = [SourceReference("/a.py", i, f"line{i}") for i in range(1, 10)]
        print_source_refs(refs, "litellm")
        captured = capsys.readouterr().out
        assert "more references" in captured


# ── print_config_refs ─────────────────────────────────────────────────


class TestPrintConfigRefs:
    def test_prints_clean_message_when_no_refs(self, capsys):
        # @req FR-21
        print_config_refs([], "litellm", LITELLM_COMPROMISED)
        captured = capsys.readouterr().out
        assert "No litellm dependencies found" in captured

    def test_prints_compromised_version_tag(self, capsys):
        # @req FR-22
        refs = [
            ConfigReference("r.txt", 1, "litellm==1.82.7", "1.82.7"),
        ]
        print_config_refs(refs, "litellm", LITELLM_COMPROMISED)
        captured = capsys.readouterr().out
        assert "COMPROMISED" in captured

    def test_prints_safe_version_tag(self, capsys):
        # @req FR-21
        refs = [
            ConfigReference("r.txt", 1, "litellm==1.80.0", "1.80.0"),
        ]
        print_config_refs(refs, "litellm", LITELLM_COMPROMISED)
        captured = capsys.readouterr().out
        assert "v1.80.0" in captured


# ── print_threat_report ───────────────────────────────────────────────


class TestPrintThreatReport:
    def test_prints_clean_verdict(self, capsys):
        # @req FR-26
        threat = make_litellm_threat()
        results = ScanResults(compromised_versions=LITELLM_COMPROMISED)
        print_threat_report(results, threat)
        captured = capsys.readouterr().out
        assert "No compromise detected" in captured

    def test_prints_compromised_verdict(self, capsys):
        # @req FR-23
        threat = make_litellm_threat()
        results = ScanResults(
            compromised_versions=LITELLM_COMPROMISED,
            installations=[Installation("/env", "1.82.7")],
        )
        print_threat_report(results, threat)
        captured = capsys.readouterr().out
        assert "COMPROMISE DETECTED" in captured
        assert "pip install litellm==1.82.6" in captured

    def test_prints_ioc_count(self, capsys):
        # @req FR-23
        threat = make_litellm_threat()
        results = ScanResults(
            compromised_versions=LITELLM_COMPROMISED,
            iocs=["/tmp/pglog"],
        )
        print_threat_report(results, threat)
        captured = capsys.readouterr().out
        assert "1" in captured

    def test_shows_advisory_url(self, capsys):
        # @req FR-24
        threat = make_litellm_threat()
        results = ScanResults(
            compromised_versions=LITELLM_COMPROMISED,
            iocs=["/tmp/pglog"],
        )
        print_threat_report(results, threat)
        captured = capsys.readouterr().out
        assert threat.advisory in captured


# ── print_multi_threat_summary ────────────────────────────────────────


class TestPrintMultiThreatSummary:
    def test_all_clean(self, capsys):
        # @req FR-01 FR-26
        threat = make_litellm_threat()
        results = ScanResults(compromised_versions=LITELLM_COMPROMISED)
        print_multi_threat_summary([(threat, results)])
        captured = capsys.readouterr().out
        assert "All checks passed" in captured

    def test_any_compromised(self, capsys):
        # @req FR-01 FR-26
        threat = make_litellm_threat()
        results = ScanResults(
            compromised_versions=LITELLM_COMPROMISED,
            iocs=["/tmp/pglog"],
        )
        print_multi_threat_summary([(threat, results)])
        captured = capsys.readouterr().out
        assert "COMPROMISES DETECTED" in captured

    def test_shows_profile_count(self, capsys):
        # @req FR-01 FR-31
        threat = make_litellm_threat()
        results = ScanResults(compromised_versions=LITELLM_COMPROMISED)
        print_multi_threat_summary([(threat, results)])
        captured = capsys.readouterr().out
        assert "1 threat profile" in captured
