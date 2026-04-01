"""Tests for CLI argument parsing.

Module under test: scan_supply_chain.scanner._parse_args
"""

from scan_supply_chain.scanner import _parse_args


class TestParseArgs:
    def test_defaults_when_no_args(self, monkeypatch):
        monkeypatch.setattr("sys.argv", ["scan-litellm"])
        args = _parse_args()
        assert args.scan_path is None
        assert args.resolve_c2 is False
        assert args.threat is None
        assert args.threat_file is None
        assert args.list_threats is False

    def test_scan_path_captures_directory(self, monkeypatch):
        monkeypatch.setattr("sys.argv", ["scan-litellm", "--scan-path", "/some/dir"])
        args = _parse_args()
        assert args.scan_path == "/some/dir"

    def test_resolve_c2_flag(self, monkeypatch):
        monkeypatch.setattr("sys.argv", ["scan-litellm", "--resolve-c2"])
        args = _parse_args()
        assert args.resolve_c2 is True

    def test_threat_selects_specific_id(self, monkeypatch):
        monkeypatch.setattr("sys.argv", ["scan-litellm", "--threat", "litellm-2026-03"])
        args = _parse_args()
        assert args.threat == "litellm-2026-03"

    def test_threat_file_path(self, monkeypatch):
        monkeypatch.setattr(
            "sys.argv", ["scan-litellm", "--threat-file", "/tmp/t.toml"]
        )
        args = _parse_args()
        assert args.threat_file == "/tmp/t.toml"

    def test_list_threats_flag(self, monkeypatch):
        monkeypatch.setattr("sys.argv", ["scan-litellm", "--list-threats"])
        args = _parse_args()
        assert args.list_threats is True

    def test_both_flags_together(self, monkeypatch):
        monkeypatch.setattr(
            "sys.argv",
            ["scan-litellm", "--scan-path", "./project", "--resolve-c2"],
        )
        args = _parse_args()
        assert args.scan_path == "./project"
        assert args.resolve_c2 is True
