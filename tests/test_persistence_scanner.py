"""Tests for generic persistence location scanner.

Module under test: scan_supply_chain.persistence_scanner
"""

import subprocess

from scan_supply_chain.models import ScanResults
from scan_supply_chain.persistence_scanner import (
    _check_config_dir,
    _check_crontab,
    _check_shell_rc,
    _check_tmp_scripts,
)


# ── _check_crontab ──────────────────────────────────────────────────


class TestCheckCrontab:
    def test_detects_package_in_crontab(self, monkeypatch):
        # @req FR-41
        monkeypatch.setattr(
            "scan_supply_chain.persistence_scanner.shutil.which",
            lambda cmd: "/usr/bin/crontab",
        )
        monkeypatch.setattr(
            "scan_supply_chain.persistence_scanner.subprocess.run",
            lambda *a, **kw: subprocess.CompletedProcess(
                args=a[0],
                returncode=0,
                stdout="*/5 * * * * python3 -c 'import litellm'\n",
            ),
        )

        results = ScanResults()
        _check_crontab(results, "litellm")

        assert len(results.findings) == 1
        assert "crontab" in results.findings[0].description

    def test_clean_when_no_match(self, monkeypatch):
        # @req FR-41
        monkeypatch.setattr(
            "scan_supply_chain.persistence_scanner.shutil.which",
            lambda cmd: "/usr/bin/crontab",
        )
        monkeypatch.setattr(
            "scan_supply_chain.persistence_scanner.subprocess.run",
            lambda *a, **kw: subprocess.CompletedProcess(
                args=a[0], returncode=0, stdout="0 * * * * /usr/bin/backup\n"
            ),
        )

        results = ScanResults()
        _check_crontab(results, "litellm")

        assert results.findings == []

    def test_skips_when_crontab_unavailable(self, monkeypatch):
        # @req FR-41 NFR-03
        monkeypatch.setattr(
            "scan_supply_chain.persistence_scanner.shutil.which",
            lambda cmd: None,
        )

        results = ScanResults()
        _check_crontab(results, "litellm")

        assert results.findings == []

    def test_handles_timeout(self, monkeypatch):
        # @req FR-41 NFR-04
        monkeypatch.setattr(
            "scan_supply_chain.persistence_scanner.shutil.which",
            lambda cmd: "/usr/bin/crontab",
        )
        monkeypatch.setattr(
            "scan_supply_chain.persistence_scanner.subprocess.run",
            lambda *a, **kw: (_ for _ in ()).throw(
                subprocess.TimeoutExpired(cmd="crontab", timeout=5)
            ),
        )

        results = ScanResults()
        _check_crontab(results, "litellm")

        assert results.findings == []


# ── _check_shell_rc ─────────────────────────────────────────────────


class TestCheckShellRc:
    def test_detects_package_in_bashrc(self, tmp_path, monkeypatch):
        # @req FR-41
        monkeypatch.setattr(
            "scan_supply_chain.persistence_scanner.Path.home", lambda: tmp_path
        )
        (tmp_path / ".bashrc").write_text("alias ll='ls -la'\nexport LITELLM_KEY=abc\n")

        results = ScanResults()
        _check_shell_rc(results, "LITELLM")

        assert len(results.findings) == 1

    def test_ignores_normal_rc(self, tmp_path, monkeypatch):
        # @req FR-41
        monkeypatch.setattr(
            "scan_supply_chain.persistence_scanner.Path.home", lambda: tmp_path
        )
        (tmp_path / ".bashrc").write_text("alias ll='ls -la'\nexport PATH=$PATH\n")

        results = ScanResults()
        _check_shell_rc(results, "litellm")

        assert results.findings == []


# ── _check_config_dir (DRY helper) ──────────────────────────────────


class TestCheckConfigDir:
    def test_flags_file_mentioning_package(self, tmp_path):
        # @req FR-41
        config_dir = tmp_path / "systemd" / "user"
        config_dir.mkdir(parents=True)
        (config_dir / "sysmon.service").write_text(
            "[Service]\nExecStart=/usr/bin/python3 litellm_backdoor.py\n"
        )

        results = ScanResults()
        _check_config_dir(results, config_dir, "*.service", "systemd", "litellm")

        assert len(results.findings) == 1
        assert "systemd" in results.findings[0].description

    def test_ignores_file_without_package(self, tmp_path):
        # @req FR-41
        config_dir = tmp_path / "systemd" / "user"
        config_dir.mkdir(parents=True)
        (config_dir / "syncthing.service").write_text(
            "[Service]\nExecStart=/usr/bin/syncthing\n"
        )

        results = ScanResults()
        _check_config_dir(results, config_dir, "*.service", "systemd", "litellm")

        assert results.findings == []

    def test_ignores_xdg_desktop_without_package(self, tmp_path):
        # @req FR-41
        autostart = tmp_path / "autostart"
        autostart.mkdir()
        (autostart / "Twake-Desktop.desktop").write_text(
            "[Desktop Entry]\nExec=/usr/bin/twake\nName=Twake\n"
        )

        results = ScanResults()
        _check_config_dir(results, autostart, "*.desktop", "XDG autostart", "litellm")

        assert results.findings == []

    def test_flags_xdg_desktop_mentioning_package(self, tmp_path):
        # @req FR-41
        autostart = tmp_path / "autostart"
        autostart.mkdir()
        (autostart / "malicious.desktop").write_text(
            "[Desktop Entry]\nExec=python3 -c 'import litellm'\nName=backdoor\n"
        )

        results = ScanResults()
        _check_config_dir(results, autostart, "*.desktop", "XDG autostart", "litellm")

        assert len(results.findings) == 1

    def test_skips_missing_directory(self, tmp_path):
        # @req FR-41 NFR-03
        results = ScanResults()
        _check_config_dir(
            results, tmp_path / "nonexistent", "*.service", "test", "litellm"
        )

        assert results.findings == []


# ── _check_tmp_scripts (AST-verified) ───────────────────────────────


class TestCheckTmpScripts:
    def test_flags_tmp_py_importing_package(self, tmp_path, monkeypatch):
        # @req FR-41 FR-37
        monkeypatch.setattr(
            "scan_supply_chain.persistence_scanner.Path",
            lambda p: tmp_path if str(p) == "/tmp" else type(tmp_path)(p),
        )
        (tmp_path / "backdoor.py").write_text("import litellm\nlitellm.run()\n")

        results = ScanResults()
        import scan_supply_chain.persistence_scanner as ps

        original = ps.Path
        ps.Path = lambda p: tmp_path if str(p) == "/tmp" else original(p)
        try:
            _check_tmp_scripts(results, "litellm")
        finally:
            ps.Path = original

        assert any("backdoor.py" in f.description for f in results.findings)

    def test_ignores_tmp_py_without_import(self, tmp_path, monkeypatch):
        # @req FR-41 FR-38
        (tmp_path / "harmless.py").write_text("import os\nprint('hello')\n")

        results = ScanResults()
        import scan_supply_chain.persistence_scanner as ps

        original = ps.Path
        ps.Path = lambda p: tmp_path if str(p) == "/tmp" else original(p)
        try:
            _check_tmp_scripts(results, "litellm")
        finally:
            ps.Path = original

        assert results.findings == []

    def test_ignores_tmp_py_with_string_mention_only(self, tmp_path, monkeypatch):
        # @req FR-38
        (tmp_path / "scanner.py").write_text('name = "litellm"\nprint(name)\n')

        results = ScanResults()
        import scan_supply_chain.persistence_scanner as ps

        original = ps.Path
        ps.Path = lambda p: tmp_path if str(p) == "/tmp" else original(p)
        try:
            _check_tmp_scripts(results, "litellm")
        finally:
            ps.Path = original

        assert results.findings == []

    def test_flags_tmp_sh_mentioning_package(self, tmp_path, monkeypatch):
        # @req FR-41
        (tmp_path / "install.sh").write_text("#!/bin/bash\npip install litellm\n")

        results = ScanResults()
        import scan_supply_chain.persistence_scanner as ps

        original = ps.Path
        ps.Path = lambda p: tmp_path if str(p) == "/tmp" else original(p)
        try:
            _check_tmp_scripts(results, "litellm")
        finally:
            ps.Path = original

        assert any("install.sh" in f.description for f in results.findings)

    def test_ignores_tmp_sh_without_package(self, tmp_path, monkeypatch):
        # @req FR-41
        (tmp_path / "backup.sh").write_text(
            "#!/bin/bash\ntar czf backup.tar.gz /home\n"
        )

        results = ScanResults()
        import scan_supply_chain.persistence_scanner as ps

        original = ps.Path
        ps.Path = lambda p: tmp_path if str(p) == "/tmp" else original(p)
        try:
            _check_tmp_scripts(results, "litellm")
        finally:
            ps.Path = original

        assert results.findings == []
