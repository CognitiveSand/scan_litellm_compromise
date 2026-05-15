"""Tests for structured network connection parsing.

Module under test: scan_supply_chain.network_scanner
"""

from unittest.mock import patch

from scan_supply_chain.network_scanner import (
    ConnectionRecord,
    enrich_from_proc,
    find_c2_connections,
    parse_lsof_output,
    parse_ss_output,
)


SS_SAMPLE = """\
State    Recv-Q Send-Q       Local Address:Port    Peer Address:Port Process
ESTAB    0      0          192.168.10.103:57954    172.66.0.227:443   users:(("firefox",pid=16377,fd=210))
ESTAB    0      0          192.168.10.103:49620   160.79.104.10:443   users:(("claude",pid=1913490,fd=58))
ESTAB    0      0          192.168.10.103:56006   142.11.206.73:8000  users:(("python3",pid=99999,fd=12))
"""

LSOF_SAMPLE = """\
COMMAND   PID USER   FD   TYPE DEVICE SIZE/OFF NODE NAME
firefox 16377 user  210u  IPv4 123456      0t0  TCP 192.168.10.103:57954->172.66.0.227:443 (ESTABLISHED)
python3 99999 user   12u  IPv4 789012      0t0  TCP 192.168.10.103:56006->142.11.206.73:8000 (ESTABLISHED)
"""

# IPv6 peers — ``ss -tnp`` and ``lsof -i -P -n`` wrap the address in
# square brackets to disambiguate the colon-separated port. The threat
# profile's c2.ips list holds bare IPs, so the parser must strip the
# brackets before emitting the peer_ip.
SS_IPV6_SAMPLE = """\
State    Recv-Q Send-Q       Local Address:Port    Peer Address:Port Process
ESTAB    0      0      [2001:db8::a]:57954    [2001:db8::1]:443   users:(("firefox",pid=16377,fd=210))
ESTAB    0      0      [2001:db8::a]:56006    [2001:db8::2]:8000  users:(("python3",pid=99999,fd=12))
"""

LSOF_IPV6_SAMPLE = """\
COMMAND   PID USER   FD   TYPE DEVICE SIZE/OFF NODE NAME
python3 99999 user   12u  IPv6 789012      0t0  TCP [2001:db8::a]:56006->[2001:db8::2]:8000 (ESTABLISHED)
"""


class TestParseSsOutput:
    def test_parses_connections(self) -> None:
        # @req FR-39
        records = parse_ss_output(SS_SAMPLE)
        assert len(records) == 3

    def test_extracts_peer_ip_and_port(self) -> None:
        # @req FR-39
        records = parse_ss_output(SS_SAMPLE)
        c2 = [r for r in records if r.peer_ip == "142.11.206.73"]
        assert len(c2) == 1
        assert c2[0].peer_port == 8000

    def test_extracts_pid_and_process(self) -> None:
        # @req FR-39
        records = parse_ss_output(SS_SAMPLE)
        c2 = [r for r in records if r.peer_ip == "142.11.206.73"][0]
        assert c2.pid == 99999
        assert c2.process_name == "python3"

    def test_handles_empty_output(self) -> None:
        # @req FR-39 NFR-03
        assert parse_ss_output("") == []

    def test_handles_header_only(self) -> None:
        # @req FR-39
        assert parse_ss_output("State Recv-Q Send-Q ...\n") == []

    def test_strips_brackets_from_ipv6_peer(self) -> None:
        # @req FR-39
        # Bare ``rpartition(":")`` would leave the closing bracket in
        # peer_ip, silently missing every IPv6 C2 address.
        records = parse_ss_output(SS_IPV6_SAMPLE)
        assert len(records) == 2
        c2 = [r for r in records if r.peer_port == 8000]
        assert len(c2) == 1
        assert c2[0].peer_ip == "2001:db8::2"


class TestParseLsofOutput:
    def test_parses_connections(self) -> None:
        # @req FR-39
        records = parse_lsof_output(LSOF_SAMPLE)
        assert len(records) == 2

    def test_extracts_peer_and_process(self) -> None:
        # @req FR-39
        records = parse_lsof_output(LSOF_SAMPLE)
        c2 = [r for r in records if r.peer_ip == "142.11.206.73"][0]
        assert c2.peer_port == 8000
        assert c2.process_name == "python3"
        assert c2.pid == 99999

    def test_strips_brackets_from_ipv6_peer(self) -> None:
        # @req FR-39
        records = parse_lsof_output(LSOF_IPV6_SAMPLE)
        assert len(records) == 1
        assert records[0].peer_ip == "2001:db8::2"
        assert records[0].peer_port == 8000


class TestFindC2Connections:
    def test_matches_by_ip(self) -> None:
        # @req FR-39
        records = [ConnectionRecord("142.11.206.73", 8000, 99, "python3")]
        domain_ips = {"sfrclak.com": ["142.11.206.73"]}

        matches = find_c2_connections(records, domain_ips, [])

        assert len(matches) == 1
        assert matches[0][1] == "sfrclak.com"

    def test_matches_by_ip_and_port(self) -> None:
        # @req FR-39 FR-15
        records = [ConnectionRecord("142.11.206.73", 8000, 99, "python3")]
        domain_ips = {"sfrclak.com": ["142.11.206.73"]}

        matches = find_c2_connections(records, domain_ips, [8000])

        assert len(matches) == 1

    def test_rejects_wrong_port(self) -> None:
        # @req FR-15
        records = [ConnectionRecord("142.11.206.73", 443, 99, "python3")]
        domain_ips = {"sfrclak.com": ["142.11.206.73"]}

        matches = find_c2_connections(records, domain_ips, [8000])

        assert matches == []

    def test_accepts_any_port_when_ports_empty(self) -> None:
        # @req FR-39
        records = [ConnectionRecord("142.11.206.73", 12345, 99, "python3")]
        domain_ips = {"sfrclak.com": ["142.11.206.73"]}

        matches = find_c2_connections(records, domain_ips, [])

        assert len(matches) == 1

    def test_no_match_for_unrelated_ip(self) -> None:
        # @req FR-39
        records = [ConnectionRecord("1.2.3.4", 443, 99, "curl")]
        domain_ips = {"sfrclak.com": ["142.11.206.73"]}

        matches = find_c2_connections(records, domain_ips, [])

        assert matches == []


class TestEnrichFromProc:
    def test_reads_exe_path(self) -> None:
        # @req FR-40
        record = ConnectionRecord("1.2.3.4", 443, 12345, "python3")

        with patch("scan_supply_chain.network_scanner.os.readlink") as mock_readlink:
            mock_readlink.return_value = "/usr/bin/python3.13"
            with patch("scan_supply_chain.network_scanner.sys.platform", "linux"):
                enriched = enrich_from_proc(record)

        assert enriched.exe_path == "/usr/bin/python3.13"

    def test_handles_permission_error(self) -> None:
        # @req FR-40 NFR-03
        record = ConnectionRecord("1.2.3.4", 443, 12345, "python3")

        with patch(
            "scan_supply_chain.network_scanner.os.readlink",
            side_effect=PermissionError,
        ):
            with patch("scan_supply_chain.network_scanner.sys.platform", "linux"):
                enriched = enrich_from_proc(record)

        assert enriched.exe_path == ""

    def test_skips_on_windows(self) -> None:
        # @req FR-40
        record = ConnectionRecord("1.2.3.4", 443, 12345, "python3")

        with patch("scan_supply_chain.network_scanner.sys.platform", "win32"):
            enriched = enrich_from_proc(record)

        assert enriched.exe_path == ""

    def test_skips_when_no_pid(self) -> None:
        # @req FR-40
        record = ConnectionRecord("1.2.3.4", 443, 0, "")
        enriched = enrich_from_proc(record)
        assert enriched.exe_path == ""
