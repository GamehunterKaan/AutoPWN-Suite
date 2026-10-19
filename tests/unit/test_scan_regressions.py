# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
"""Offline regressions for configuration, actual Nmap results and NVD failures."""
import io
from argparse import Namespace
from contextlib import nullcontext
from unittest.mock import ANY, MagicMock, patch

import pytest
from requests.exceptions import ConnectionError, HTTPError
from rich.console import Console

from autopwn_suite.api import AutoScanner
from autopwn_suite.cli import StartScanning, main
from autopwn_suite.nist_search import FindVars, Vulnerability, cache, searchCVE
from autopwn_suite.nmap_backend import PortScanner
from autopwn_suite.scanner import AnalyseScanResults, InitHostInfo, InitPortInfo, NoiseScan, ResolveScanHosts
from autopwn_suite.searchvuln import SearchSploits
from autopwn_suite.utils import GetHostsToScan, InitArgsConf, InitArgsTarget, ScanMode, ScanType


def nmap_result(hosts):
    scanner = MagicMock()
    scanner.__getitem__.side_effect = hosts.__getitem__
    scanner.all_hosts.return_value = list(hosts)
    return scanner


def port(product="DNS", version="1.0", state="open"):
    return {"state": state, "name": "domain", "product": product, "version": version}


@pytest.fixture(autouse=True)
def offline_state(monkeypatch):
    monkeypatch.setattr("autopwn_suite.scanner.is_root", lambda: True)
    monkeypatch.setattr("autopwn_suite.nist_search.sleep", lambda seconds: None)
    cache.clear()
    yield
    cache.clear()


def test_config_preserves_flags_credentials_paths_and_literal_percent(tmp_path):
    config = tmp_path / "settings.ini"
    config.write_text("""[AUTOPWN]
nmapflags = -sV -O --script ScriptName
apikey = AbCd%EF
hostfile = Hosts/Office.txt
auto = false
skip_exploit_download = false
scan_type = ping
skip_discovery = true
host_timeout = 30
noisetimeout = 5
output_folder = MyReports
output_type = TXT
[REPORT]
email_password = SecRet%123
email_port = 587
output = Reports/OfficeScan
""", encoding="utf-8")
    args = Namespace(config=str(config))
    InitArgsConf(args, MagicMock())
    assert args.nmap_flags == "-sV -O --script ScriptName"
    assert args.api == "AbCd%EF"
    assert args.host_file == "Hosts/Office.txt"
    assert args.report_email_password == "SecRet%123"
    assert args.output == "Reports/OfficeScan"
    assert args.output_folder == "MyReports"
    assert args.output_type == "txt"
    assert args.yes_please is False
    assert args.skip_exploit_download is False
    assert args.skip_discovery is True
    assert args.scan_type == "ping"
    assert args.host_timeout == 30
    assert args.noise_timeout == 5
    assert args.report_email_server_port == 587


@pytest.mark.parametrize("option", ["speed = 8", "auto = maybe", "noisetimeout = abc", "mode = invalid"])
def test_invalid_config_fails_before_scanning(tmp_path, option):
    config = tmp_path / "bad.ini"
    config.write_text(f"[AUTOPWN]\n{option}\n", encoding="utf-8")
    with pytest.raises(SystemExit):
        InitArgsConf(Namespace(config=str(config)), MagicMock())


def test_missing_config_is_not_silently_ignored(tmp_path):
    with pytest.raises(SystemExit):
        InitArgsConf(Namespace(config=str(tmp_path / "missing.ini")), MagicMock())


@pytest.mark.parametrize("failure", ["missing", "directory", "unreadable"])
def test_a_config_that_cannot_be_read_exits_with_a_failure_status(tmp_path, failure):
    """cron and CI treat exit status 0 as success, so a typo in -c must not look like one."""
    path = tmp_path / "missing.ini" if failure == "missing" else tmp_path
    reading = patch("autopwn_suite.utils.ConfigParser.read", side_effect=PermissionError) if failure == "unreadable" else nullcontext()
    with reading, pytest.raises(SystemExit) as exit_:
        InitArgsConf(Namespace(config=str(path)), MagicMock())
    assert exit_.value.code == 1


def test_config_can_select_web_mode_before_scan_initialization(tmp_path):
    config = tmp_path / "web.ini"
    config.write_text("[WEBUI]\nenabled = yes\nhost = 127.0.0.1\nport = 9090\n", encoding="utf-8")
    args = Namespace(version=False, no_color=True, daemon_install=False,
                     daemon_uninstall=False, create_config=False, config=str(config), web=False)
    with patch("autopwn_suite.cli.cli", return_value=args), patch("autopwn_suite.cli.start_server") as server, \
         patch("autopwn_suite.cli.FLASK_AVAILABLE", True), patch("autopwn_suite.cli.print_banner"), \
         patch("autopwn_suite.cli.CheckConnection") as check:
        with pytest.raises(SystemExit):
            main()
    server.assert_called_once_with(host="127.0.0.1", port=9090, version=ANY, offline=False, database=None)
    assert isinstance(server.call_args.kwargs["version"], str)
    assert server.call_args.kwargs["version"]
    check.assert_not_called()


def test_skip_discovery_scans_host_file_entries_individually():
    args = Namespace(skip_discovery=True, speed=3, host_timeout=30, nmap_flags="")
    hosts = ["192.0.2.1", "192.0.2.2"]
    with patch("autopwn_suite.cli.check_nmap"), patch("autopwn_suite.cli.UserConfirmation", return_value=(True, False, False)), \
         patch("autopwn_suite.cli.WebScan", return_value=False), patch("autopwn_suite.cli.PortScan") as scan, \
         patch("autopwn_suite.cli.AnalyseScanResults", return_value=[]):
        StartScanning(args, hosts, ScanType.Ping, ScanMode.Normal, None,
                      MagicMock(), MagicMock(), MagicMock())
    assert [call.args[0] for call in scan.call_args_list] == hosts


def test_cli_range_vuln_and_web_phases_use_each_actual_host():
    args = Namespace(skip_discovery=True, speed=3, host_timeout=30, nmap_flags="")
    scan = nmap_result({"192.0.2.1": {}, "192.0.2.2": {}})
    rows = [["192.0.2.1", 53, "domain", "DNS", "1", "udp"],
            ["192.0.2.2", 80, "http", "HTTP", "2"]]
    with patch("autopwn_suite.cli.check_nmap"), patch("autopwn_suite.cli.UserConfirmation", return_value=(True, True, True)), \
         patch("autopwn_suite.cli.WebScan", return_value=True), patch("autopwn_suite.cli.PortScan", return_value=scan), \
         patch("autopwn_suite.cli.AnalyseScanResults", return_value=rows), \
         patch("autopwn_suite.cli.SearchSploits", return_value=["vuln"]) as lookup, \
         patch("autopwn_suite.cli.GetExploitsFromArray") as downloads, patch("autopwn_suite.cli.webvuln") as web:
        StartScanning(args, "192.0.2.0/30", ScanType.Ping, ScanMode.Normal, None,
                      MagicMock(), MagicMock(), MagicMock())
    assert [call.args[0] for call in lookup.call_args_list] == [[rows[0]], [rows[1]]]
    assert [call.args[4] for call in downloads.call_args_list] == ["192.0.2.1", "192.0.2.2"]
    assert [call.args[0] for call in web.call_args_list] == ["192.0.2.1", "http://192.0.2.2:80/"]


def test_selecting_host_address_returns_without_another_prompt(monkeypatch):
    monkeypatch.setattr("autopwn_suite.utils.DontAskForConfirmation", False)
    with patch("builtins.input", side_effect=["192.0.2.1"]) as prompt:
        assert GetHostsToScan(["192.0.2.1", "192.0.2.2"], MagicMock()) == ["192.0.2.1"]
    prompt.assert_called_once()


def test_host_file_ignores_blank_and_comment_lines(tmp_path):
    host_file = tmp_path / "hosts.txt"
    host_file.write_text("# Office hosts\n 192.0.2.1 \n\n  # note\n192.0.2.2\n", encoding="utf-8")
    targets = InitArgsTarget(Namespace(target=None, host_file=str(host_file)), MagicMock())
    assert targets == ["192.0.2.1", "192.0.2.2"]


def test_empty_host_file_fails_without_detecting_a_different_network(tmp_path):
    host_file = tmp_path / "hosts.txt"
    host_file.write_text("\n# no hosts yet\n", encoding="utf-8")
    with patch("autopwn_suite.utils.DetectIPRange") as detect:
        with pytest.raises(SystemExit):
            InitArgsTarget(Namespace(target=None, host_file=str(host_file)), MagicMock())
    detect.assert_not_called()


def test_empty_scan_and_partial_port_fields_do_not_crash():
    assert AnalyseScanResults(nmap_result({}), MagicMock(), MagicMock()) == []
    assert InitPortInfo({"state": "open", "product": None}) == ("open", "Unknown", "Unknown", "Unknown")


def test_hostname_and_range_results_use_actual_hosts_and_keep_udp():
    scan = nmap_result({"192.0.2.1": {"udp": {53: port()}},
                        "192.0.2.2": {"tcp": {80: port("HTTP", "2")}}})
    assert ResolveScanHosts(scan, "office.example") == ["192.0.2.1", "192.0.2.2"]
    rows = AnalyseScanResults(scan, MagicMock(), MagicMock(), "192.0.2.0/30")
    assert rows == [["192.0.2.1", 53, "domain", "DNS", "1.0", "udp"],
                    ["192.0.2.2", 80, "domain", "HTTP", "2"]]


def test_vendor_is_read_from_nmap_mac_mapping():
    data = {"addresses": {"mac": "AA:BB"}, "vendor": {"AA:BB": "Example Vendor"}}
    assert InitHostInfo(data).vendor == "Example Vendor"
    assert AutoScanner().InitHostInfo(data)["vendor"] == "Example Vendor"


def test_api_handles_resolved_udp_hosts_offline_and_resets_previous_results():
    scanner = AutoScanner()
    first = nmap_result({"192.0.2.1": {"udp": {53: port()}}})
    offline = nmap_result({})
    with patch("autopwn_suite.api.PortScanner", side_effect=[first, offline]), \
         patch.object(scanner, "SearchVuln", return_value={"CVE-TEST": {}}) as lookup:
        results = scanner.scan("office.example")
        assert results["192.0.2.1"]["ports"] == {}
        assert results["192.0.2.1"]["udp_ports"][53]["product"] == "DNS"
        assert results["192.0.2.1"]["vulns"] == {"DNS": {"CVE-TEST": {}}}
        lookup.assert_called_once()
        assert scanner.scan("192.0.2.99") == {}


def test_api_only_searches_open_services_and_merges_same_product_cves():
    scanner = AutoScanner()
    scan = nmap_result({"192.0.2.1": {"tcp": {80: port("HTTP", "1"),
                                                    443: port("HTTP", "2"),
                                                    25: port("Mail", "1", "closed")}}})
    with patch("autopwn_suite.api.PortScanner", return_value=scan), \
         patch.object(scanner, "SearchVuln", side_effect=[{"CVE-A": {}}, {"CVE-B": {}}]) as lookup:
        result = scanner.scan("192.0.2.1")
    assert lookup.call_count == 2
    assert set(result["192.0.2.1"]["vulns"]["HTTP"]) == {"CVE-A", "CVE-B"}


def test_api_honors_slowest_scan_speed():
    assert "-T 0" in AutoScanner().CreateScanArgs(None, 0, False, None)


def test_noise_scan_stops_and_joins_children_after_unexpected_error():
    with patch("autopwn_suite.scanner.TestPing", return_value=["192.0.2.1"]), \
         patch("autopwn_suite.scanner.Process") as process, \
         patch("autopwn_suite.scanner.sleep", side_effect=OSError("timer failure")):
        with pytest.raises(OSError, match="timer failure"):
            NoiseScan("192.0.2.1", MagicMock(), MagicMock(), ScanType.Ping, 5)
    process.return_value.terminate.assert_called_once()
    process.return_value.join.assert_called_with(timeout=2)
    assert process.call_args.kwargs["args"][2].is_set()


def test_noise_scan_with_no_hosts_exits_before_waiting():
    with patch("autopwn_suite.scanner.TestPing", return_value=[]), patch("autopwn_suite.scanner.sleep") as sleep:
        with pytest.raises(SystemExit):
            NoiseScan("192.0.2.99", MagicMock(), MagicMock(), ScanType.Ping)
    sleep.assert_not_called()


def response(data):
    result = MagicMock()
    result.json.return_value = data
    return result


@pytest.mark.parametrize("failure", [ConnectionError("offline"), HTTPError("forbidden")])
def test_strict_lookup_raises_and_does_not_cache_failed_response(failure):
    with patch("autopwn_suite.nist_search.get", side_effect=failure) as fetch:
        with pytest.raises(RuntimeError, match="NVD lookup failed"):
            searchCVE("test", MagicMock(), strict=True)
    assert fetch.call_count == 3
    assert "test" not in cache


def test_api_lookup_failure_is_reported_to_the_caller():
    with patch("autopwn_suite.nist_search.get", side_effect=ConnectionError("offline")):
        with pytest.raises(RuntimeError, match="NVD lookup failed"):
            AutoScanner().SearchVuln(port())


@pytest.mark.parametrize("data", [{"message": "API error"}, {"vulnerabilities": None}, {"vulnerabilities": [{}]}])
def test_strict_lookup_rejects_malformed_data(data):
    with patch("autopwn_suite.nist_search.get", return_value=response(data)):
        with pytest.raises(RuntimeError):
            searchCVE("test", MagicMock(), strict=True)
    assert "test" not in cache


def test_lookup_collects_all_pages_and_only_caches_complete_success():
    first = response({"startIndex": 0, "totalResults": 2,
                      "vulnerabilities": [{"cve": {"id": "CVE-A"}}]})
    second = response({"startIndex": 1, "totalResults": 2,
                       "vulnerabilities": [{"cve": {"id": "CVE-B"}}]})
    with patch("autopwn_suite.nist_search.get", side_effect=[first, second]) as fetch:
        results = searchCVE("test", MagicMock(), strict=True)
    assert [v.CVEID for v in results] == ["CVE-A", "CVE-B"]
    assert fetch.call_args.kwargs["params"]["startIndex"] == 1
    assert fetch.call_args.kwargs["timeout"] == 20
    first.raise_for_status.assert_called_once()
    assert cache["test"] == results


def test_failed_later_page_does_not_cache_partial_results():
    first = response({"startIndex": 0, "totalResults": 2,
                      "vulnerabilities": [{"cve": {"id": "CVE-A"}}]})
    with patch("autopwn_suite.nist_search.get", side_effect=[first, ConnectionError("offline"),
                                                     ConnectionError("offline"), ConnectionError("offline")]):
        with pytest.raises(RuntimeError):
            searchCVE("test", MagicMock(), strict=True)
    assert "test" not in cache


def test_findvars_prefers_english_primary_metric_and_preserves_zero_score():
    data = {"cve": {"id": "CVE-A", "descriptions": [{"lang": "es", "value": "Spanish"},
                                                         {"lang": "en", "value": "English"}],
                    "metrics": {"cvssMetricV31": [
                        {"type": "Secondary", "cvssData": {"baseScore": 9, "baseSeverity": "CRITICAL"}},
                        {"type": "Primary", "cvssData": {"baseScore": 0, "baseSeverity": "NONE"}}],
                        "cvssMetricV2": [{"cvssData": {"baseScore": 7.5}}]}}}
    _, description, severity, score, _, _ = FindVars(data)
    assert (description, severity, score) == ("English", "NONE", 0)


def test_searchsploits_handles_empty_input_and_narrow_terminal():
    assert SearchSploits([], MagicMock(), MagicMock(), MagicMock()) == []
    vuln = Vulnerability("DNS", "CVE-A", "Long description", "HIGH", 7.5, "url", 2)
    with patch("autopwn_suite.searchvuln.CheckConnection", return_value=True), \
         patch("autopwn_suite.searchvuln.SearchKeyword", return_value=[vuln]), \
         patch("autopwn_suite.searchvuln.get_terminal_width", return_value=40):
        result = SearchSploits([["192.0.2.1", 53, "domain", "DNS", "1"]],
                              MagicMock(), MagicMock(), MagicMock())
    assert result[0].CVEs == ["CVE-A"]


def test_hostile_banner_text_is_printed_literally_instead_of_aborting_the_scan():
    # Banner text such as "[/bold]" is Rich markup; it must reach the screen verbatim.
    host = {"addresses": {"mac": "AA:BB"}, "vendor": {"AA:BB": "[/vendor]"},
            "osmatch": [{"name": "[/os]", "accuracy": "[/accuracy]", "osclass": [{"type": "[/type]"}]}],
            "tcp": {21: {"state": "open", "name": "[/service]", "product": "[/bold]", "version": "[/admin] 1.0"}}}
    console = Console(file=io.StringIO(), width=200, color_system=None)
    rows = AnalyseScanResults(nmap_result({"192.0.2.1": host}), MagicMock(), console, "192.0.2.1")
    output = console.file.getvalue()
    for text in ("[/vendor]", "[/os]", "[/accuracy]", "[/type]", "[/service]", "[/bold]", "[/admin] 1.0"):
        assert text in output
    assert rows == [["192.0.2.1", 21, "[/service]", "[/bold]", "[/admin] 1.0"]]


def timed_out_scan(timed_out=True, ports=""):
    scan = PortScanner(nmap_path="unused")
    scan.load_xml(f'<nmaprun><host timedout="{str(timed_out).lower()}"><status state="up" reason="syn-ack"/>'
                  f'<address addr="192.0.2.1" addrtype="ipv4"/>{ports}</host>'
                  '<runstats><finished exit="success"/><hosts up="1" down="0" total="1"/></runstats></nmaprun>')
    scan.scan = MagicMock()
    return scan


def test_cli_reports_a_host_timeout_instead_of_no_open_ports():
    log = MagicMock()
    assert AnalyseScanResults(timed_out_scan(), log, MagicMock(), "192.0.2.1") == []
    messages = [call.args[1] for call in log.logger.call_args_list]
    assert messages == ["Nmap timed out on 192.0.2.1; port coverage is incomplete."]
    assert log.logger.call_args.args[0] == "warning"


def test_cli_keeps_partial_ports_of_a_timed_out_host_and_still_warns():
    log = MagicMock()
    ports = '<ports><port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port></ports>'
    rows = AnalyseScanResults(timed_out_scan(ports=ports), log, Console(file=io.StringIO()), "192.0.2.1")
    assert rows == [["192.0.2.1", 22, "ssh", "Unknown", "Unknown"]]
    log.logger.assert_called_once_with("warning", "Nmap timed out on 192.0.2.1; port coverage is incomplete.")


def test_cli_still_reports_no_open_ports_for_a_host_that_finished():
    log = MagicMock()
    assert AnalyseScanResults(timed_out_scan(False), log, MagicMock(), "192.0.2.1") == []
    log.logger.assert_called_once_with("warning", "Target 192.0.2.1 seems to have no open ports.")


def test_api_flags_a_host_that_hit_the_host_timeout(caplog):
    with patch("autopwn_suite.api.PortScanner", return_value=timed_out_scan()), caplog.at_level("WARNING", logger="autopwn_suite.api"):
        result = AutoScanner().scan("192.0.2.1", host_timeout=3, scan_vulns=False)
    assert result == {"192.0.2.1": {"ports": {}, "timedout": True}}
    assert "Nmap timed out on 192.0.2.1; port coverage is incomplete" in caplog.text


def test_api_result_shape_is_unchanged_for_a_host_that_finished(caplog):
    with patch("autopwn_suite.api.PortScanner", return_value=timed_out_scan(False)), caplog.at_level("WARNING", logger="autopwn_suite.api"):
        result = AutoScanner().scan("192.0.2.1", host_timeout=3, scan_vulns=False)
    assert result == {"192.0.2.1": {"ports": {}}}
    assert caplog.text == ""
