# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
"""Recorded Nmap XML and simulated children; no network scans or third-party wrapper."""

from unittest.mock import MagicMock

import pytest

from autopwn_suite import nmap_backend as backend
from autopwn_suite import nmap_progress as runner
from tests.unit.test_nmap_progress import FakeProcess

XML = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sV -O -sU -p 53,9443 example.test" version="7.95">
  <scaninfo type="connect" protocol="tcp" numservices="2" services="53,9443"/>
  <scaninfo type="udp" protocol="udp" numservices="1" services="53"/>
  <host starttime="1" endtime="2">
    <status state="up" reason="syn-ack" reason_ttl="64"/>
    <address addr="192.0.2.10" addrtype="ipv4"/>
    <address addr="AA:BB:CC:DD:EE:FF" addrtype="mac" vendor="Example &amp; Co"/>
    <hostnames><hostname name="example.test" type="user"/></hostnames>
    <ports>
      <extraports state="closed" count="998"><extrareasons reason="reset" count="998"/></extraports>
      <port protocol="tcp" portid="53"><state state="closed" reason="reset"/></port>
      <port protocol="tcp" portid="9443">
        <state state="open" reason="syn-ack"/>
        <service name="http" product="nginx" version="1.24.0" extrainfo="Test" tunnel="ssl" method="probed" conf="10">
          <cpe>cpe:/a:nginx:nginx:1.24.0</cpe><cpe>cpe:/o:linux:linux_kernel</cpe>
        </service>
        <script id="http-title" output="Türkçe &amp; test">
          <table key="headers"><elem key="value">first</elem><elem key="value">second</elem>
            <table><elem>unkeyed</elem></table>
          </table>
        </script>
      </port>
      <port protocol="udp" portid="53">
        <state state="open|filtered" reason="no-response"/>
        <service name="domain" product="ISC BIND" version="9.18"/>
      </port>
    </ports>
    <os>
      <portused state="open" proto="tcp" portid="9443"/>
      <osmatch name="Linux 5.x" accuracy="98" line="123">
        <osclass vendor="Linux" osfamily="Linux" osgen="5.X" type="general purpose" accuracy="98">
          <cpe>cpe:/o:linux:linux_kernel:5</cpe>
        </osclass>
      </osmatch>
      <osfingerprint fingerprint="SCAN(...)"/>
    </os>
    <uptime seconds="123" lastboot="yesterday"/><distance value="1"/>
    <tcpsequence index="256" difficulty="Good luck!"/><ipidsequence class="All zeros"/>
    <tcptssequence class="100HZ"/><times srtt="300" rttvar="100" to="100000"/>
    <hostscript><script id="clock-skew" output="0s"/></hostscript>
    <trace proto="tcp" port="9443"><hop ttl="1" ipaddr="192.0.2.10" rtt="1.20" host="example.test"/></trace>
  </host>
  <host><status state="up" reason="echo-reply"/><address addr="192.0.2.2" addrtype="ipv4"/></host>
  <host timedout="true"><status state="down" reason="no-response"/><address addr="192.0.2.3" addrtype="ipv4"/></host>
  <host><status state="up" reason="echo-reply"/><address addr="2001:db8::1" addrtype="ipv6"/></host>
  <host><status state="up" reason="arp-response"/><address addr="AA:BB:00:00:00:00" addrtype="mac"/></host>
  <prescript><script id="pre" output="before"/></prescript>
  <postscript><script id="post" output="after"/></postscript>
  <runstats><finished time="2" timestr="done" elapsed="1.25" exit="success" summary="scan complete"/>
    <hosts up="4" down="1" total="5"/></runstats>
</nmaprun>'''.encode("utf-8")

EMPTY = b'''<nmaprun args="nmap -sn 192.0.2.99"><runstats>
<finished elapsed="1" exit="success"/><hosts up="0" down="1" total="1"/>
</runstats></nmaprun>'''


@pytest.fixture
def scanner():
    return backend.PortScanner(nmap_path="C:/Program Files/Nmap/nmap.exe")


def test_services_keep_protocol_state_tunnel_and_all_cpes(scanner):
    result = scanner.load_xml(XML)
    host = scanner["192.0.2.10"]
    assert result["scan"]["192.0.2.10"] is host
    assert host["tcp"][53]["state"] == "closed"
    assert host["tcp"][53]["product"] == ""
    assert host["udp"][53]["state"] == "open|filtered"
    assert host["udp"][53]["product"] == "ISC BIND"
    https = host["tcp"][9443]
    assert (https["name"], https["product"], https["version"], https["tunnel"]) == ("http", "nginx", "1.24.0", "ssl")
    assert https["cpe"] == "cpe:/a:nginx:nginx:1.24.0"
    assert https["cpes"] == [https["cpe"], "cpe:/o:linux:linux_kernel"]
    assert host["extraports"][0]["extrareasons"] == [{"reason": "reset", "count": "998"}]


def test_host_identity_os_and_discovery_metadata(scanner):
    from autopwn_suite.scanner import InitHostInfo
    scanner.load_xml(XML)
    host = scanner["192.0.2.10"]
    info = InitHostInfo(host)
    assert (info.mac, info.vendor, info.os, info.os_accuracy, info.os_type) == (
        "AA:BB:CC:DD:EE:FF", "Example & Co", "Linux 5.x", "98", "general purpose")
    assert host["hostnames"] == [{"name": "example.test", "type": "user"}]
    assert host["osmatch"][0]["osclass"][0]["cpe"] == ["cpe:/o:linux:linux_kernel:5"]
    assert host["portused"][0]["portid"] == "9443"
    assert host["osfingerprint"] == {"fingerprint": "SCAN(...)"}
    assert host["uptime"]["seconds"] == "123"
    assert host["distance"] == {"value": "1"}
    assert host["trace"]["hops"][0]["ipaddr"] == "192.0.2.10"
    assert host["times"]["srtt"] == "300"
    assert scanner["192.0.2.3"]["timedout"] == "true"
    assert scanner.all_hosts() == ["192.0.2.2", "192.0.2.3", "192.0.2.10", "2001:db8::1"]
    assert scanner.all_hosts(up_only=True) == ["192.0.2.2", "192.0.2.10", "2001:db8::1"]
    assert scanner.has_host("2001:db8::1") and not scanner.has_host("example.test")
    with pytest.raises(KeyError):
        scanner["example.test"]


def test_nse_outputs_preserve_nested_tables_duplicate_keys_and_unicode(scanner):
    result = scanner.load_xml(XML)
    https = scanner["192.0.2.10"]["tcp"][9443]
    assert https["script"] == {"http-title": "Türkçe & test"}
    table = https["script_details"][0]["elements"][0]
    assert table["key"] == "headers"
    assert [entry["text"] for entry in table["children"][:2]] == ["first", "second"]
    assert table["children"][2]["children"][0]["text"] == "unkeyed"
    assert scanner["192.0.2.10"]["hostscript"][0]["output"] == "0s"
    assert result["nmap"]["prescript"][0]["id"] == "pre"
    assert result["nmap"]["postscript"][0]["id"] == "post"
    assert scanner.get_nmap_last_output() == XML


def test_scan_statistics_and_stderr_diagnostics(scanner):
    result = scanner.load_xml(XML, stderr=" Warning: timed out\nHost diagnostic\n\n")
    assert scanner.command_line().endswith("example.test")
    assert scanner.scaninfo() == {"tcp": {"method": "connect", "services": "53,9443"},
                                  "udp": {"method": "udp", "services": "53"}}
    assert scanner.scanstats()["uphosts"] == "4"
    assert scanner.scanstats()["elapsed"] == "1.25"
    assert result["nmap"]["scanwarning"] == [" Warning: timed out"]
    assert result["nmap"]["scanerror"] == ["Host diagnostic"]


def test_old_osclass_location_and_other_transport_protocols(scanner):
    xml = XML.replace(b'<osmatch name=', b'<osclass type="router"/><osmatch name=')
    xml = xml.replace(b'<osclass vendor=', b'<unused vendor=').replace(b'</osclass>', b'</unused>')
    xml = xml.replace(b'protocol="udp" portid="53"', b'protocol="sctp" portid="53"')
    scanner.load_xml(xml)
    assert scanner["192.0.2.10"]["osmatch"][0]["osclass"][0]["type"] == "router"
    assert scanner["192.0.2.10"]["sctp"][53]["name"] == "domain"


@pytest.mark.parametrize("xml,message", [
    (b"", "Invalid or incomplete"), (XML[:-20], "Invalid or incomplete"),
    (b"<notnmap/>", "Expected nmaprun"), (b"<nmaprun/>", "missing run statistics"),
    (EMPTY.replace(b'exit="success"', b'exit="error" errormsg="probe failed"'), "probe failed"),
    (XML.replace(b'portid="9443"', b'portid="invalid"'), "Invalid port"),
    (XML.replace(b'protocol="tcp" portid="53"', b'portid="53"'), "Invalid port"),
])
def test_invalid_or_failed_xml_never_reuses_previous_results(scanner, xml, message):
    scanner.load_xml(XML)
    with pytest.raises(RuntimeError, match=message):
        scanner.load_xml(xml)
    assert scanner.all_hosts() == []


def test_empty_successful_scan_replaces_previous_hosts(scanner):
    scanner.load_xml(XML)
    result = scanner.load_xml(EMPTY)
    assert result["scan"] == {} and scanner.all_hosts() == []
    assert scanner.scanstats()["totalhosts"] == "1"


def test_missing_nmap_is_actionable_without_a_binary_probe(monkeypatch):
    monkeypatch.setattr(backend.shutil, "which", lambda _: None)
    spawn = MagicMock()
    monkeypatch.setattr(runner.subprocess, "Popen", spawn)
    with pytest.raises(RuntimeError, match="Install Nmap and add it to PATH"):
        backend.PortScanner()
    assert backend.parse_nmap_xml(EMPTY)["scan"] == {}
    spawn.assert_not_called()


def test_plain_scan_uses_the_same_parser_and_separate_argument_tokens(scanner, monkeypatch):
    spawn = MagicMock(return_value=FakeProcess(stdout=XML))
    monkeypatch.setattr(runner.subprocess, "Popen", spawn)
    result = scanner.scan(hosts=["example.test", "2001:db8::1"], ports="53,9443",
                          arguments='-sV --script "banner,ssl-cert" -n')
    command = spawn.call_args.args[0]
    assert command == [scanner._nmap_path, "-oX", "-", "example.test", "2001:db8::1",
                       "-sV", "--script", "banner,ssl-cert", "-n", "-p", "53,9443"]
    assert spawn.call_args.kwargs["shell"] is False
    assert result["scan"]["192.0.2.10"]["tcp"][9443]["tunnel"] == "ssl"
    spawn.return_value = FakeProcess(stdout=EMPTY)
    assert scanner.scan(hosts="192.0.2.99", arguments=["-sn", "-n"])["scan"] == {}


@pytest.mark.parametrize("arguments", ["-oX elsewhere.xml", "-oXelsewhere.xml", "-oA results",
                                       "--resume previous.log", "--append-output"])
def test_output_overrides_are_rejected_before_launch(scanner, monkeypatch, arguments):
    scanner.load_xml(XML)
    spawn = MagicMock()
    monkeypatch.setattr(runner.subprocess, "Popen", spawn)
    with pytest.raises(ValueError, match="redirected"):
        scanner.scan(arguments=arguments)
    spawn.assert_not_called()
    assert scanner.all_hosts() == []


@pytest.mark.parametrize("hosts,arguments,timeout,error", [
    ("--resume saved.xml", "-sV", None, ValueError),
    (123, "-sV", None, TypeError), ("127.0.0.1", [123], None, TypeError),
    ("127.0.0.1", "-sV", 0, ValueError), ("127.0.0.1", "-sV", float("inf"), ValueError),
])
def test_invalid_inputs_do_not_start_a_child(scanner, monkeypatch, hosts, arguments, timeout, error):
    spawn = MagicMock()
    monkeypatch.setattr(runner.subprocess, "Popen", spawn)
    with pytest.raises(error):
        scanner.scan(hosts=hosts, arguments=arguments, timeout=timeout)
    spawn.assert_not_called()


def test_overall_timeout_reaps_child_and_clears_old_results(scanner, monkeypatch):
    scanner.load_xml(XML)
    process = FakeProcess(stdout=XML, timeouts=10, stubborn=True)
    monkeypatch.setattr(runner.subprocess, "Popen", MagicMock(return_value=process))
    times = iter([0, 2])
    monkeypatch.setattr(runner.time, "monotonic", lambda: next(times))
    with pytest.raises(TimeoutError, match="exceeded timeout"):
        scanner.scan(timeout=1)
    assert process.terminated and process.killed
    assert process.stdout.closed and process.stderr.closed
    assert scanner.all_hosts() == []


def test_timeout_shorter_than_poll_interval_is_enforced(scanner, monkeypatch):
    class SlowProcess(FakeProcess):
        def wait(self, timeout=None):
            if self.returncode is not None:
                return self.returncode
            # This scan would complete in 100 ms if allowed to overrun its limit.
            if timeout >= 0.1:
                self.returncode = 0
                return 0
            raise runner.subprocess.TimeoutExpired("nmap", timeout)

    process = SlowProcess(stdout=XML)
    monkeypatch.setattr(runner.subprocess, "Popen", MagicMock(return_value=process))
    times = iter([0, 0.01, 0.06])
    monkeypatch.setattr(runner.time, "monotonic", lambda: next(times))
    with pytest.raises(TimeoutError, match="exceeded timeout"):
        scanner.scan(timeout=0.05)
    assert process.terminated and scanner.all_hosts() == []


def test_spawn_failure_does_not_leave_old_results(scanner, monkeypatch):
    scanner.load_xml(XML)
    monkeypatch.setattr(runner.subprocess, "Popen", MagicMock(side_effect=FileNotFoundError("nmap removed")))
    with pytest.raises(FileNotFoundError):
        scanner.scan()
    assert scanner.all_hosts() == []


@pytest.mark.parametrize("discovery", ["TestPing", "TestArp"])
@pytest.mark.parametrize("monitored", [False, True])
def test_discovery_filters_down_hosts_with_or_without_progress(scanner, monkeypatch, discovery, monitored):
    from autopwn_suite import scanner as scan_module
    monkeypatch.setattr(scan_module, "PortScanner", lambda: scanner)
    monkeypatch.setattr(runner.subprocess, "Popen", MagicMock(return_value=FakeProcess(stdout=XML)))
    kwargs = {"progress": MagicMock(), "should_stop": lambda: False} if monitored else {}
    assert getattr(scan_module, discovery)("example.test", offline=True, **kwargs) == [
        "192.0.2.2", "192.0.2.10", "2001:db8::1"]


def test_python_api_keeps_resolved_hosts_udp_os_and_offline_contract(scanner, monkeypatch):
    import autopwn_suite.api as api
    monkeypatch.setattr(api, "PortScanner", lambda: scanner)
    monkeypatch.setattr(api, "is_root", lambda: True)
    monkeypatch.setattr(api, "VulnerabilityLookup", lambda *a: pytest.fail("Port-only scan opened CVE database"))
    spawn = MagicMock(return_value=FakeProcess(stdout=XML))
    monkeypatch.setattr(runner.subprocess, "Popen", spawn)
    result = api.AutoScanner().scan("example.test", os_scan=True, scan_vulns=False, offline=True,
                                   nmap_args="-sT -sU -p 53,9443")
    assert "example.test" not in result
    assert result["192.0.2.10"]["ports"][53]["state"] == "closed"
    assert result["192.0.2.10"]["udp_ports"][53]["state"] == "open|filtered"
    assert result["192.0.2.10"]["os"]["os_name"] == "Linux 5.x"
    assert result["192.0.2.10"]["os"]["vendor"] == "Example & Co"
    assert "-n" in spawn.call_args.args[0] and "-O" in spawn.call_args.args[0]


def test_cli_analysis_and_web_targets_keep_tls_on_nonstandard_ports(scanner, monkeypatch):
    from autopwn_suite.scanner import AnalyseScanResults
    from autopwn_suite.web.webvuln import web_endpoints
    scanner.load_xml(XML)
    monkeypatch.setattr("autopwn_suite.scanner.is_root", lambda: True)
    rows = AnalyseScanResults(scanner, MagicMock(), MagicMock(), "192.0.2.10")
    assert rows == [["192.0.2.10", 9443, "http", "nginx", "1.24.0"]]
    assert web_endpoints("192.0.2.10", rows, scanner) == ["https://192.0.2.10:9443/"]
    assert web_endpoints("192.0.2.10", rows, scanner._scan_result) == ["https://192.0.2.10:9443/"]
    assert web_endpoints("192.0.2.99", [["192.0.2.99", 80, "http", "", ""]], scanner) == ["http://192.0.2.99:80/"]


def test_cancellation_without_progress_clears_old_results(scanner, monkeypatch):
    scanner.load_xml(XML)
    process = FakeProcess(stdout=XML, timeouts=1)
    monkeypatch.setattr(runner.subprocess, "Popen", MagicMock(return_value=process))
    stops = iter([False, False, True])
    with pytest.raises(runner.ScanCancelled):
        scanner.scan(should_stop=lambda: next(stops, True))
    assert process.terminated and scanner.all_hosts() == []
