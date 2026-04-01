"""Tests for generic persistence location scanner.

Module under test: scan_supply_chain.persistence_scanner
"""

import subprocess

from scan_supply_chain.models import ScanResults
from scan_supply_chain.persistence_scanner import (
    _check_crontab,
    _check_shell_rc,
    _check_systemd_user,
    _check_tmp_scripts,
)


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


class TestCheckSystemdUser:
    def test_detects_suspicious_service(self, tmp_path, monkeypatch):
        # @req FR-41
        monkeypatch.setattr(
            "scan_supply_chain.persistence_scanner.Path.home", lambda: tmp_path
        )
        service_dir = tmp_path / ".config" / "systemd" / "user"
        service_dir.mkdir(parents=True)
        (service_dir / "sysmon.service").write_text(
            "[Service]\nExecStart=/usr/bin/python3 litellm_backdoor.py\n"
        )

        results = ScanResults()
        _check_systemd_user(results, "litellm")

        assert len(results.findings) == 1
        assert "systemd" in results.findings[0].description

    def test_ignores_unrelated_services(self, tmp_path, monkeypatch):
        # @req FR-41
        monkeypatch.setattr(
            "scan_supply_chain.persistence_scanner.Path.home", lambda: tmp_path
        )
        service_dir = tmp_path / ".config" / "systemd" / "user"
        service_dir.mkdir(parents=True)
        (service_dir / "syncthing.service").write_text(
            "[Service]\nExecStart=/usr/bin/syncthing\n"
        )

        results = ScanResults()
        _check_systemd_user(results, "litellm")

        assert results.findings == []


class TestCheckTmpScripts:
    def test_lists_py_scripts_in_tmp(self, tmp_path, monkeypatch):
        # @req FR-41
        monkeypatch.setattr(
            "scan_supply_chain.persistence_scanner.Path",
            lambda p: tmp_path if p == "/tmp" else type(tmp_path)(p),
        )
        # Directly test the function with a real tmp dir
        from scan_supply_chain.persistence_scanner import Path as _  # noqa: F401

        (tmp_path / "backdoor.py").write_text("import os")
        (tmp_path / "normal.txt").write_text("hello")

        results = ScanResults()
        # Call with monkeypatched /tmp
        import scan_supply_chain.persistence_scanner as ps

        original = ps.Path
        ps.Path = lambda p: tmp_path if str(p) == "/tmp" else original(p)
        try:
            _check_tmp_scripts(results)
        finally:
            ps.Path = original

        assert any("backdoor.py" in f.description for f in results.findings)
