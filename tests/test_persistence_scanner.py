"""Tests for generic persistence location scanner.

Module under test: scan_supply_chain.persistence_scanner
"""

from pathlib import Path

import sys

import pytest

from scan_supply_chain.models import ScanResults
from scan_supply_chain.skip_report import SkipReport
from tests.conftest import mock_run_safe, mock_tool_available
from scan_supply_chain.persistence_scanner import (
    _check_config_dir,
    _check_crontab,
    _check_shell_rc,
    _check_tmp_scripts,
    scan_persistence,
)

# _check_tmp_scripts itself short-circuits on win32 (persistence_scanner.py
# guards Path("/tmp") behind sys.platform != "win32"), so the whole class
# below is POSIX-only by design.
_TMP_SCRIPTS_POSIX_ONLY = pytest.mark.skipif(
    sys.platform == "win32",
    reason="_check_tmp_scripts is POSIX-only (no /tmp on Windows)",
)


# ── _check_crontab ──────────────────────────────────────────────────


class TestCheckCrontab:
    def test_detects_package_in_crontab(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # @req FR-41
        mock_tool_available(monkeypatch, "persistence_scanner", "crontab")
        mock_run_safe(
            monkeypatch,
            "persistence_scanner",
            "*/5 * * * * python3 -c 'import litellm'\n",
        )

        results = ScanResults()
        _check_crontab(results, ["litellm"])

        assert len(results.findings) == 1
        assert "crontab" in results.findings[0].description

    def test_clean_when_no_match(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # @req FR-41
        mock_tool_available(monkeypatch, "persistence_scanner", "crontab")
        mock_run_safe(
            monkeypatch,
            "persistence_scanner",
            "0 * * * * /usr/bin/backup\n",
        )

        results = ScanResults()
        _check_crontab(results, ["litellm"])

        assert results.findings == []

    def test_skips_when_crontab_unavailable(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # @req FR-41 NFR-03
        monkeypatch.setattr(
            "scan_supply_chain.persistence_scanner.shutil.which",
            lambda cmd: None,
        )

        results = ScanResults()
        _check_crontab(results, ["litellm"])

        assert results.findings == []

    def test_handles_timeout(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # @req FR-41 NFR-04
        mock_tool_available(monkeypatch, "persistence_scanner", "crontab")
        mock_run_safe(monkeypatch, "persistence_scanner", None)

        results = ScanResults()
        _check_crontab(results, ["litellm"])

        assert results.findings == []


# ── _check_shell_rc ─────────────────────────────────────────────────


class TestCheckShellRc:
    def test_detects_package_in_bashrc(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # @req FR-41
        monkeypatch.setattr(
            "scan_supply_chain.persistence_scanner.Path.home", lambda: tmp_path
        )
        (tmp_path / ".bashrc").write_text("alias ll='ls -la'\nexport LITELLM_KEY=abc\n")

        results = ScanResults()
        _check_shell_rc(results, ["LITELLM"], SkipReport())

        assert len(results.findings) == 1

    def test_ignores_normal_rc(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # @req FR-41
        monkeypatch.setattr(
            "scan_supply_chain.persistence_scanner.Path.home", lambda: tmp_path
        )
        (tmp_path / ".bashrc").write_text("alias ll='ls -la'\nexport PATH=$PATH\n")

        results = ScanResults()
        _check_shell_rc(results, ["litellm"], SkipReport())

        assert results.findings == []


# ── _check_config_dir (DRY helper) ──────────────────────────────────


class TestCheckConfigDir:
    def test_flags_file_mentioning_package(self, tmp_path: Path) -> None:
        # @req FR-41
        config_dir = tmp_path / "systemd" / "user"
        config_dir.mkdir(parents=True)
        (config_dir / "sysmon.service").write_text(
            "[Service]\nExecStart=/usr/bin/python3 litellm_backdoor.py\n"
        )

        results = ScanResults()
        _check_config_dir(
            results, config_dir, "*.service", "systemd", ["litellm"], SkipReport()
        )

        assert len(results.findings) == 1
        assert "systemd" in results.findings[0].description

    def test_ignores_file_without_package(self, tmp_path: Path) -> None:
        # @req FR-41
        config_dir = tmp_path / "systemd" / "user"
        config_dir.mkdir(parents=True)
        (config_dir / "syncthing.service").write_text(
            "[Service]\nExecStart=/usr/bin/syncthing\n"
        )

        results = ScanResults()
        _check_config_dir(
            results, config_dir, "*.service", "systemd", ["litellm"], SkipReport()
        )

        assert results.findings == []

    def test_ignores_xdg_desktop_without_package(self, tmp_path: Path) -> None:
        # @req FR-41
        autostart = tmp_path / "autostart"
        autostart.mkdir()
        (autostart / "Twake-Desktop.desktop").write_text(
            "[Desktop Entry]\nExec=/usr/bin/twake\nName=Twake\n"
        )

        results = ScanResults()
        _check_config_dir(
            results, autostart, "*.desktop", "XDG autostart", ["litellm"], SkipReport()
        )

        assert results.findings == []

    def test_flags_xdg_desktop_mentioning_package(self, tmp_path: Path) -> None:
        # @req FR-41
        autostart = tmp_path / "autostart"
        autostart.mkdir()
        (autostart / "malicious.desktop").write_text(
            "[Desktop Entry]\nExec=python3 -c 'import litellm'\nName=backdoor\n"
        )

        results = ScanResults()
        _check_config_dir(
            results, autostart, "*.desktop", "XDG autostart", ["litellm"], SkipReport()
        )

        assert len(results.findings) == 1

    def test_skips_missing_directory(self, tmp_path: Path) -> None:
        # @req FR-41 NFR-03
        results = ScanResults()
        _check_config_dir(
            results,
            tmp_path / "nonexistent",
            "*.service",
            "test",
            ["litellm"],
            SkipReport(),
        )

        assert results.findings == []

    def test_matches_non_package_keyword(self, tmp_path: Path) -> None:
        # @req FR-41
        # Persistence keyword (e.g. a daemon name) unrelated to the package
        # itself must still trigger a finding.
        config_dir = tmp_path / "systemd" / "user"
        config_dir.mkdir(parents=True)
        (config_dir / "monitor.service").write_text(
            "[Service]\nExecStart=/usr/local/bin/gh-token-monitor\n"
        )

        results = ScanResults()
        # Anchor package "axios" is NOT in the file; keyword is.
        _check_config_dir(
            results,
            config_dir,
            "*.service",
            "systemd user service",
            ["axios", "gh-token-monitor"],
            SkipReport(),
        )

        assert len(results.findings) == 1
        assert "gh-token-monitor" in results.findings[0].description


# ── _check_tmp_scripts (AST-verified) ───────────────────────────────


@_TMP_SCRIPTS_POSIX_ONLY
class TestCheckTmpScripts:
    def test_flags_tmp_py_importing_package(self, tmp_as_tmp: Path) -> None:
        # @req FR-41 FR-37
        (tmp_as_tmp / "backdoor.py").write_text("import litellm\nlitellm.run()\n")

        results = ScanResults()
        _check_tmp_scripts(results, "litellm")

        assert any("backdoor.py" in f.description for f in results.findings)

    def test_ignores_tmp_py_without_import(self, tmp_as_tmp: Path) -> None:
        # @req FR-41 FR-38
        (tmp_as_tmp / "harmless.py").write_text("import os\nprint('hello')\n")

        results = ScanResults()
        _check_tmp_scripts(results, "litellm")

        assert results.findings == []

    def test_ignores_tmp_py_with_string_mention_only(self, tmp_as_tmp: Path) -> None:
        # @req FR-38
        (tmp_as_tmp / "scanner.py").write_text('name = "litellm"\nprint(name)\n')

        results = ScanResults()
        _check_tmp_scripts(results, "litellm")

        assert results.findings == []

    def test_flags_tmp_sh_mentioning_package(self, tmp_as_tmp: Path) -> None:
        # @req FR-41
        (tmp_as_tmp / "install.sh").write_text("#!/bin/bash\npip install litellm\n")

        results = ScanResults()
        _check_tmp_scripts(results, "litellm")

        assert any("install.sh" in f.description for f in results.findings)

    def test_ignores_tmp_sh_without_package(self, tmp_as_tmp: Path) -> None:
        # @req FR-41
        (tmp_as_tmp / "backup.sh").write_text(
            "#!/bin/bash\ntar czf backup.tar.gz /home\n"
        )

        results = ScanResults()
        _check_tmp_scripts(results, "litellm")

        assert results.findings == []


# ── scan_persistence (public API) ───────────────────────────────────


class TestScanPersistencePublicAPI:
    def test_extra_keywords_propagate_to_shell_rc(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # @req FR-41
        # Verify that profile-level persistence_keywords reach the
        # shell-rc checker even when the package name itself is absent.
        monkeypatch.setattr(
            "scan_supply_chain.persistence_scanner.Path.home", lambda: tmp_path
        )
        # Suppress crontab and /tmp checks.
        monkeypatch.setattr(
            "scan_supply_chain.persistence_scanner.shutil.which", lambda cmd: None
        )
        monkeypatch.setattr(
            "scan_supply_chain.persistence_scanner._check_tmp_scripts",
            lambda *a, **kw: None,
        )

        (tmp_path / ".bashrc").write_text(
            "# nothing about the package\n"
            "export PATH=/usr/local/bin/gh-token-monitor:$PATH\n"
        )

        results = ScanResults()
        scan_persistence(results, package="axios", extra_keywords=("gh-token-monitor",))

        assert any("gh-token-monitor" in f.description for f in results.findings)
