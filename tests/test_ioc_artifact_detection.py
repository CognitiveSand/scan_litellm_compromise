"""Tests for Phase 3: IOC artifact detection.

Module under test: scan_supply_chain.ioc_scanner
"""

import socket
import subprocess
from pathlib import Path


from scan_supply_chain.ioc_scanner import (
    _check_known_paths,
    _ip_matches_output,
    _resolve_c2_ips,
    _scan_for_c2_connections,
    _scan_for_malicious_pods,
    _scan_walk_files,
)
from scan_supply_chain.models import ScanResults
from tests.conftest import StubPolicy, make_litellm_threat, make_axios_threat


# ── _check_known_paths ────────────────────────────────────────────────


class TestCheckKnownPaths:
    def test_flags_existing_path_as_ioc(self, tmp_path, capsys):
        # @req FR-12
        ioc_file = tmp_path / "pglog"
        ioc_file.write_text("exfil data")

        results = ScanResults()
        _check_known_paths("test artifacts", [ioc_file], results)

        assert len(results.iocs) == 1
        assert str(ioc_file) in results.iocs[0]

    def test_reports_clean_when_no_paths_exist(self, tmp_path, capsys):
        # @req FR-12
        results = ScanResults()
        _check_known_paths("test artifacts", [tmp_path / "nope"], results)

        assert results.iocs == []
        captured = capsys.readouterr().out
        assert "None found" in captured

    def test_flags_multiple_existing_iocs(self, tmp_path, capsys):
        # @req FR-12
        (tmp_path / "pglog").write_text("a")
        (tmp_path / ".pg_state").write_text("b")

        results = ScanResults()
        _check_known_paths(
            "test",
            [tmp_path / "pglog", tmp_path / ".pg_state"],
            results,
        )

        assert len(results.iocs) == 2

    def test_handles_permission_error_on_path_check(self, monkeypatch, capsys):
        # @req FR-12 NFR-03
        def exists_raises(self):
            raise PermissionError("denied")

        monkeypatch.setattr(Path, "exists", exists_raises)

        results = ScanResults()
        _check_known_paths("test", [Path("/fake/path")], results)

        assert results.iocs == []


# ── _scan_walk_files ─────────────────────────────────────────────────


class TestScanWalkFiles:
    def test_finds_litellm_init_pth(self, tmp_path, capsys):
        # @req FR-11
        site_pkg = tmp_path / "lib" / "site-packages"
        site_pkg.mkdir(parents=True)
        (site_pkg / "litellm_init.pth").write_text("import os")

        # Use walk_files with no sha256 requirement so any matching filename is flagged
        from scan_supply_chain.threat_profile import WalkFileIOC

        threat = make_litellm_threat(
            walk_files=[
                WalkFileIOC(
                    description="litellm_init.pth (auto-exec backdoor)",
                    filenames=["litellm_init.pth"],
                    sha256=[],
                )
            ],
        )
        results = ScanResults()
        _scan_walk_files(results, threat, [str(tmp_path)])

        assert len(results.iocs) == 1
        assert "litellm_init.pth" in results.iocs[0]

    def test_reports_clean_when_no_files_found(self, tmp_path, capsys):
        # @req FR-11
        (tmp_path / "lib" / "site-packages").mkdir(parents=True)

        threat = make_litellm_threat()

        results = ScanResults()
        _scan_walk_files(results, threat, [str(tmp_path)])

        assert results.iocs == []
        captured = capsys.readouterr().out
        assert "None found" in captured

    def test_skips_nonexistent_search_roots(self, capsys):
        # @req FR-11
        threat = make_litellm_threat()

        results = ScanResults()
        _scan_walk_files(results, threat, ["/nonexistent/path/that/does/not/exist"])

        assert results.iocs == []

    def test_respects_explicit_roots(self, tmp_path, capsys):
        # @req FR-11 FR-13
        (tmp_path / "litellm_init.pth").write_text("import os")

        from scan_supply_chain.threat_profile import WalkFileIOC

        threat = make_litellm_threat(
            walk_files=[
                WalkFileIOC(
                    description="litellm_init.pth (auto-exec backdoor)",
                    filenames=["litellm_init.pth"],
                    sha256=[],
                )
            ],
        )

        results = ScanResults()
        _scan_walk_files(results, threat, [str(tmp_path)])

        assert len(results.iocs) == 1


# ── _resolve_c2_ips (pure helper) ────────────────────────────────────


class TestResolveC2Ips:
    def test_returns_known_ips_when_dns_disabled(self):
        # @req FR-14
        threat = make_litellm_threat()
        result = _resolve_c2_ips(threat, resolve_dns=False)

        for domain, known_ips in threat.c2.ips.items():
            assert domain in result
            for ip in known_ips:
                assert ip in result[domain]

    def test_does_not_call_dns_when_disabled(self, monkeypatch):
        # @req FR-14 NFR-05
        dns_called = []
        monkeypatch.setattr(
            "scan_supply_chain.ioc_scanner.socket.gethostbyname",
            lambda d: dns_called.append(d) or "1.2.3.4",
        )

        threat = make_litellm_threat()
        _resolve_c2_ips(threat, resolve_dns=False)

        assert dns_called == []

    def test_adds_live_ip_when_dns_enabled(self, monkeypatch):
        # @req FR-16
        monkeypatch.setattr(
            "scan_supply_chain.ioc_scanner.socket.gethostbyname",
            lambda d: "99.99.99.99",
        )

        threat = make_litellm_threat()
        result = _resolve_c2_ips(threat, resolve_dns=True)

        for domain in threat.c2.ips:
            assert "99.99.99.99" in result[domain]

    def test_deduplicates_live_ip_matching_known(self, monkeypatch):
        # @req FR-16
        threat = make_litellm_threat()
        first_domain = list(threat.c2.ips.keys())[0]
        known_ip = threat.c2.ips[first_domain][0]
        monkeypatch.setattr(
            "scan_supply_chain.ioc_scanner.socket.gethostbyname",
            lambda d: known_ip,
        )

        result = _resolve_c2_ips(threat, resolve_dns=True)

        assert result[first_domain].count(known_ip) == 1

    def test_handles_dns_failure_gracefully(self, monkeypatch):
        # @req FR-16 NFR-03
        monkeypatch.setattr(
            "scan_supply_chain.ioc_scanner.socket.gethostbyname",
            lambda d: (_ for _ in ()).throw(
                socket.gaierror("Name resolution failed"),
            ),
        )

        threat = make_litellm_threat()
        result = _resolve_c2_ips(threat, resolve_dns=True)

        for domain, known_ips in threat.c2.ips.items():
            assert domain in result
            for ip in known_ips:
                assert ip in result[domain]


# ── _scan_for_c2_connections ──────────────────────────────────────────


class TestScanForC2Connections:
    def _stub_ss(self, monkeypatch, stdout):
        stdout_bytes = stdout.encode() if isinstance(stdout, str) else stdout
        monkeypatch.setattr(
            "scan_supply_chain.ioc_scanner.shutil.which",
            lambda cmd: "/usr/bin/ss",
        )
        monkeypatch.setattr(
            "scan_supply_chain.ioc_scanner.subprocess.run",
            lambda *a, **kw: subprocess.CompletedProcess(
                args=a[0],
                returncode=0,
                stdout=stdout_bytes,
            ),
        )

    def test_flags_known_ip_without_dns(self, monkeypatch, capsys):
        # @req FR-14
        threat = make_litellm_threat()
        known_ip = threat.c2.ips["models.litellm.cloud"][0]
        self._stub_ss(monkeypatch, f"ESTAB  0  0  10.0.0.1:443  {known_ip}:80\n")

        policy = StubPolicy()
        policy.network_check_command = ["ss", "-tnp"]

        results = ScanResults()
        _scan_for_c2_connections(results, threat, policy)

        assert len(results.iocs) >= 1
        assert any("connection:" in ioc and known_ip in ioc for ioc in results.iocs)

    def test_reports_clean_when_no_c2_ips_in_output(self, monkeypatch, capsys):
        # @req FR-14
        self._stub_ss(monkeypatch, "ESTAB  0  0  10.0.0.1:443  1.2.3.4:80\n")

        threat = make_litellm_threat()
        policy = StubPolicy()
        policy.network_check_command = ["ss", "-tnp"]

        results = ScanResults()
        _scan_for_c2_connections(results, threat, policy)

        assert results.iocs == []
        captured = capsys.readouterr().out
        assert "No suspicious connections" in captured

    def test_skips_when_network_tool_unavailable(self, monkeypatch, capsys):
        # @req FR-14 NFR-03
        monkeypatch.setattr(
            "scan_supply_chain.ioc_scanner.shutil.which",
            lambda cmd: None,
        )

        threat = make_litellm_threat()
        policy = StubPolicy()
        policy.network_check_command = ["ss", "-tnp"]

        results = ScanResults()
        _scan_for_c2_connections(results, threat, policy)

        assert results.iocs == []

    def test_skips_when_no_network_command_configured(self, capsys):
        # @req FR-14
        threat = make_litellm_threat()
        policy = StubPolicy()
        policy.network_check_command = None

        results = ScanResults()
        _scan_for_c2_connections(results, threat, policy)

        assert results.iocs == []

    def test_handles_subprocess_timeout(self, monkeypatch, capsys):
        # @req FR-14 NFR-04
        monkeypatch.setattr(
            "scan_supply_chain.ioc_scanner.shutil.which",
            lambda cmd: "/usr/bin/ss",
        )
        monkeypatch.setattr(
            "scan_supply_chain.ioc_scanner.subprocess.run",
            lambda *a, **kw: (_ for _ in ()).throw(
                subprocess.TimeoutExpired(cmd="ss", timeout=5),
            ),
        )

        threat = make_litellm_threat()
        policy = StubPolicy()
        policy.network_check_command = ["ss", "-tnp"]

        results = ScanResults()
        _scan_for_c2_connections(results, threat, policy)

        assert results.iocs == []


# ── _scan_for_malicious_pods ─────────────────────────────────────────


class TestScanForMaliciousPods:
    def test_flags_node_setup_pods(self, monkeypatch, capsys):
        # @req FR-19
        monkeypatch.setattr(
            "scan_supply_chain.ioc_scanner.shutil.which",
            lambda cmd: "/usr/bin/kubectl" if cmd == "kubectl" else None,
        )
        monkeypatch.setattr(
            "scan_supply_chain.ioc_scanner.subprocess.run",
            lambda *a, **kw: subprocess.CompletedProcess(
                args=a[0],
                returncode=0,
                stdout="node-setup-abc123  1/1  Running  0  2h\nkube-proxy-xyz  1/1  Running  0  5d\n",
            ),
        )

        threat = make_litellm_threat()
        results = ScanResults()
        _scan_for_malicious_pods(results, threat)

        assert len(results.iocs) == 1
        assert "k8s-pods:1" in results.iocs[0]

    def test_reports_clean_when_no_suspicious_pods(self, monkeypatch, capsys):
        # @req FR-19
        monkeypatch.setattr(
            "scan_supply_chain.ioc_scanner.shutil.which",
            lambda cmd: "/usr/bin/kubectl" if cmd == "kubectl" else None,
        )
        monkeypatch.setattr(
            "scan_supply_chain.ioc_scanner.subprocess.run",
            lambda *a, **kw: subprocess.CompletedProcess(
                args=a[0],
                returncode=0,
                stdout="kube-proxy-xyz  1/1  Running  0  5d\n",
            ),
        )

        threat = make_litellm_threat()
        results = ScanResults()
        _scan_for_malicious_pods(results, threat)

        assert results.iocs == []
        captured = capsys.readouterr().out
        assert "No suspicious pods" in captured

    def test_skips_when_kubectl_not_installed(self, monkeypatch, capsys):
        # @req FR-19 NFR-03
        monkeypatch.setattr(
            "scan_supply_chain.ioc_scanner.shutil.which",
            lambda cmd: None,
        )

        threat = make_litellm_threat()
        results = ScanResults()
        _scan_for_malicious_pods(results, threat)

        assert results.iocs == []

    def test_skips_when_no_pod_patterns(self, monkeypatch, capsys):
        # @req FR-19
        threat = make_litellm_threat(
            kubernetes=__import__(
                "scan_supply_chain.threat_profile", fromlist=["KubernetesIOC"]
            ).KubernetesIOC(),
        )
        results = ScanResults()
        _scan_for_malicious_pods(results, threat)
        assert results.iocs == []


# ── _ip_matches_output (pure function) ───────────────────────────────


class TestIpMatchesOutput:
    def test_bare_ip_matches_when_no_ports(self):
        # @req FR-15
        assert _ip_matches_output("1.2.3.4", [], "ESTAB 1.2.3.4:443") is True

    def test_bare_ip_does_not_match_absent_ip(self):
        # @req FR-15
        assert _ip_matches_output("1.2.3.4", [], "ESTAB 5.6.7.8:443") is False

    def test_port_match_when_ip_and_port_present(self):
        # @req FR-15
        output = "ESTAB 10.0.0.1:54321 142.11.206.73:8000"
        assert _ip_matches_output("142.11.206.73", [8000], output) is True

    def test_port_mismatch_when_ip_on_wrong_port(self):
        # @req FR-15
        output = "ESTAB 10.0.0.1:54321 142.11.206.73:443"
        assert _ip_matches_output("142.11.206.73", [8000], output) is False

    def test_any_port_matches(self):
        # @req FR-15
        output = "ESTAB 10.0.0.1:54321 142.11.206.73:9090"
        assert _ip_matches_output("142.11.206.73", [8000, 9090], output) is True

    def test_c2_with_ports_in_full_scan(self, monkeypatch, capsys):
        # @req FR-15
        threat = make_axios_threat()
        known_ip = threat.c2.ips["sfrclak.com"][0]

        stdout_bytes = f"ESTAB 10.0.0.1:54321 {known_ip}:8000\n".encode()
        monkeypatch.setattr(
            "scan_supply_chain.ioc_scanner.shutil.which",
            lambda cmd: "/usr/bin/ss",
        )
        monkeypatch.setattr(
            "scan_supply_chain.ioc_scanner.subprocess.run",
            lambda *a, **kw: subprocess.CompletedProcess(
                args=a[0],
                returncode=0,
                stdout=stdout_bytes,
            ),
        )

        policy = StubPolicy()
        policy.network_check_command = ["ss", "-tnp"]

        results = ScanResults()
        _scan_for_c2_connections(results, threat, policy)

        assert len(results.iocs) >= 1
        assert any("connection:" in ioc for ioc in results.iocs)

    def test_c2_with_ports_rejects_wrong_port(self, monkeypatch, capsys):
        # @req FR-15
        threat = make_axios_threat()
        known_ip = threat.c2.ips["sfrclak.com"][0]

        stdout_bytes = f"ESTAB 10.0.0.1:54321 {known_ip}:443\n".encode()
        monkeypatch.setattr(
            "scan_supply_chain.ioc_scanner.shutil.which",
            lambda cmd: "/usr/bin/ss",
        )
        monkeypatch.setattr(
            "scan_supply_chain.ioc_scanner.subprocess.run",
            lambda *a, **kw: subprocess.CompletedProcess(
                args=a[0],
                returncode=0,
                stdout=stdout_bytes,
            ),
        )

        policy = StubPolicy()
        policy.network_check_command = ["ss", "-tnp"]

        results = ScanResults()
        _scan_for_c2_connections(results, threat, policy)

        assert results.iocs == []
