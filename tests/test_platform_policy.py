"""Tests for platform detection and policy implementations.

Modules under test: scan_supply_chain.platform_policy,
    scan_supply_chain.platform_linux,
    scan_supply_chain.platform_darwin,
    scan_supply_chain.platform_windows
"""

import sys

import pytest

from scan_supply_chain.platform_darwin import DarwinPolicy
from scan_supply_chain.platform_linux import LinuxPolicy
from scan_supply_chain.platform_policy import detect_platform


# ── detect_platform ──────────────────────────────────────────────────


class TestDetectPlatform:
    def test_returns_linux_policy_on_linux(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "linux")
        policy = detect_platform()
        assert policy.name == "Linux"

    def test_returns_windows_policy_on_win32(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "win32")
        policy = detect_platform()
        assert policy.name == "Windows"

    def test_returns_darwin_policy_on_darwin(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "darwin")
        policy = detect_platform()
        assert policy.name == "macOS"


# ── LinuxPolicy ──────────────────────────────────────────────────────


class TestLinuxPolicy:
    @pytest.fixture
    def policy(self):
        return LinuxPolicy()

    def test_name_is_linux(self, policy):
        assert policy.name == "Linux"

    def test_platform_key_is_linux(self, policy):
        assert policy.platform_key == "linux"

    def test_search_roots_excludes_root_home(self, policy):
        assert "/root" not in policy.search_roots

    def test_search_roots_includes_common_paths(self, policy):
        roots = policy.search_roots
        assert "/home" in roots
        assert "/opt" in roots
        assert "/usr/local" in roots

    def test_network_check_command_is_ss(self, policy):
        assert policy.network_check_command == ["ss", "-tnp"]

    def test_home_conda_dirs_returns_known_names(self, policy):
        dirs = policy.home_conda_dirs()
        assert "miniconda3" in dirs
        assert "anaconda3" in dirs


# ── DarwinPolicy ────────────────────────────────────────────────────


class TestDarwinPolicy:
    @pytest.fixture
    def policy(self):
        return DarwinPolicy()

    def test_name_is_macos(self, policy):
        assert policy.name == "macOS"

    def test_platform_key_is_darwin(self, policy):
        assert policy.platform_key == "darwin"

    def test_search_roots_uses_users_not_home(self, policy):
        roots = policy.search_roots
        assert "/Users" in roots
        assert "/home" not in roots

    def test_search_roots_includes_homebrew(self, policy):
        assert "/opt/homebrew" in policy.search_roots

    def test_network_check_command_is_lsof(self, policy):
        assert policy.network_check_command == ["lsof", "-i", "-P", "-n"]

    def test_home_conda_dirs_returns_known_names(self, policy):
        dirs = policy.home_conda_dirs()
        assert "miniconda3" in dirs
        assert "anaconda3" in dirs


# ── WindowsPolicy (env-var dependent) ────────────────────────────────


class TestWindowsPolicy:
    @pytest.fixture
    def policy(self, monkeypatch):
        monkeypatch.setenv("USERPROFILE", "/tmp/fakehome")
        monkeypatch.setenv("APPDATA", "/tmp/fakehome/AppData/Roaming")
        monkeypatch.setenv("LOCALAPPDATA", "/tmp/fakehome/AppData/Local")
        monkeypatch.setenv("TEMP", "/tmp/faketemp")
        monkeypatch.setenv("ProgramFiles", "/tmp/Program Files")

        from scan_supply_chain.platform_windows import WindowsPolicy

        return WindowsPolicy()

    def test_name_is_windows(self, policy):
        assert policy.name == "Windows"

    def test_platform_key_is_windows(self, policy):
        assert policy.platform_key == "windows"

    def test_home_conda_dirs_returns_windows_names(self, policy):
        dirs = policy.home_conda_dirs()
        assert "Miniconda3" in dirs
        assert "Anaconda3" in dirs
