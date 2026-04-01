"""Tests for ANSI formatting and terminal output.

Module under test: scan_supply_chain.formatting
"""

from unittest.mock import patch


class TestEnableAnsi:
    def test_returns_false_when_not_a_tty(self):
        # @req FR-27
        from scan_supply_chain.formatting import _enable_ansi

        with patch("scan_supply_chain.formatting.sys.stdout") as mock_stdout:
            mock_stdout.isatty.return_value = False
            assert _enable_ansi() is False

    def test_returns_true_on_unix_tty(self):
        # @req FR-27
        from scan_supply_chain.formatting import _enable_ansi

        with (
            patch("scan_supply_chain.formatting.sys.stdout") as mock_stdout,
            patch("scan_supply_chain.formatting.sys.platform", "linux"),
        ):
            mock_stdout.isatty.return_value = True
            assert _enable_ansi() is True


class TestCodeHelper:
    def test_returns_escape_when_enabled(self):
        # @req FR-27
        from scan_supply_chain.formatting import _code

        with patch("scan_supply_chain.formatting._ANSI_ENABLED", True):
            assert _code("\033[1m") == "\033[1m"

    def test_returns_empty_when_disabled(self):
        # @req FR-27
        from scan_supply_chain.formatting import _code

        with patch("scan_supply_chain.formatting._ANSI_ENABLED", False):
            assert _code("\033[1m") == ""
