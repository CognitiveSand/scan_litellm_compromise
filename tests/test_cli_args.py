"""Tests for CLI argument parsing.

Module under test: scan_supply_chain.scanner._parse_args
"""

from scan_supply_chain.scanner import _parse_args


class TestParseArgs:
    def test_defaults_when_no_args(self, monkeypatch):
        # @req FR-01 FR-26
        monkeypatch.setattr("sys.argv", ["scan-supply-chain"])
        args = _parse_args()
        assert args.resolve_c2 is False
        assert args.threat is None
        assert args.threat_file is None
        assert args.list_threats is False

    def test_resolve_c2_flag(self, monkeypatch):
        # @req FR-16
        monkeypatch.setattr("sys.argv", ["scan-supply-chain", "--resolve-c2"])
        args = _parse_args()
        assert args.resolve_c2 is True

    def test_threat_selects_specific_id(self, monkeypatch):
        # @req FR-02 FR-32
        monkeypatch.setattr(
            "sys.argv", ["scan-supply-chain", "--threat", "litellm-2026-03"]
        )
        args = _parse_args()
        assert args.threat == "litellm-2026-03"

    def test_threat_file_path(self, monkeypatch):
        # @req FR-04 FR-32
        monkeypatch.setattr(
            "sys.argv", ["scan-supply-chain", "--threat-file", "/tmp/t.toml"]
        )
        args = _parse_args()
        assert args.threat_file == "/tmp/t.toml"

    def test_list_threats_flag(self, monkeypatch):
        # @req FR-03 FR-32
        monkeypatch.setattr("sys.argv", ["scan-supply-chain", "--list-threats"])
        args = _parse_args()
        assert args.list_threats is True
