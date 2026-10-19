# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
"""Nmap banners, hostnames and script output reach the port table, the API and the dashboard clean
(AUTOPWN-SA-2026-016)."""

import io
import json
from unittest.mock import MagicMock, patch

import pytest
from rich.console import Console

from autopwn_suite import nmap_progress as monitored
from autopwn_suite.nmap_backend import PortScanner
from autopwn_suite.scanner import AnalyseScanResults, PortScan
from tests.unit.test_hostile_text import FORBIDDEN_EXCEPT_NEWLINE, HOSTILE, assert_clean
from tests.unit.test_nmap_progress import FakeProcess

# Written as character references because XML has no way to carry ESC or BEL: NEL, LS, PS, LF, right-to-left override,
# zero-width space, left-to-right mark, the 8-bit CSI and a left-to-right isolate.
BANNER = "ssh&#133;&#8232;&#8233;[+] FORGED&#10;line&#8238;&#8203;&#8206;&#155;2J&#8294;"
BANNER_CLEAN = "ssh  [+] FORGED line2J"
HOSTILE_XML = f"""<nmaprun args="nmap -sV 192.0.2.1&#8232;"><host>
<status state="up" reason="syn-ack"/><address addr="192.0.2.1" addrtype="ipv4"/>
<address addr="AA:BB:CC:DD:EE:FF" addrtype="mac" vendor="Vend&#8238;or&#10;[+] V"/>
<hostnames><hostname name="h&#8232;ost.test" type="PTR"/></hostnames>
<ports><port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/>
<service name="{BANNER}" product="Open&#8238;SSH&#10;[+] P&lt;b&gt;" version="8.9&#8233;[*] V" extrainfo="x&#133;y"/>
<script id="banner" output="line one&#10;line two&#8238;&#155;&#9;end"><elem key="k">a&#10;b&#8203;c</elem></script>
</port></ports>
<os><osmatch name="Linux&#8232;5" accuracy="98"><osclass type="general&#10;purpose"/></osmatch></os></host>
<runstats><finished exit="success"/><hosts up="1" down="0" total="1"/></runstats></nmaprun>"""


def hostile_scan():
    scan = PortScanner(nmap_path="unused")
    scan.load_xml(HOSTILE_XML, stderr="Warning: host\U00002028name\x1b[2J resolves\nto two addresses\n")
    return scan


def test_nmap_text_is_cleaned_when_the_xml_is_read_and_scripts_keep_only_their_newlines():
    scan = hostile_scan()
    host = scan["192.0.2.1"]
    port = host["tcp"][22]
    assert port["name"] == BANNER_CLEAN
    assert port["product"] == "OpenSSH [+] P<b>" and port["version"] == "8.9 [*] V" and port["extrainfo"] == "xy"
    assert host["vendor"] == {"AA:BB:CC:DD:EE:FF": "Vendor [+] V"} and host["hostnames"][0]["name"] == "h ost.test"
    assert host["osmatch"][0]["name"] == "Linux 5" and host["osmatch"][0]["osclass"][0]["type"] == "general purpose"
    # NSE output is several lines by nature: the newline stays, nothing else that drives a terminal.
    assert port["script"] == {"banner": "line one\nline two end"}
    assert port["script_details"][0]["elements"][0]["text"] == "a\nbc"
    assert scan._scan_result["nmap"]["command_line"] == "nmap -sV 192.0.2.1 "
    assert scan._scan_result["nmap"]["scanwarning"] == ["Warning: host name[2J resolves"]
    assert scan._scan_result["nmap"]["scanerror"] == ["to two addresses"]
    assert_clean({key: value for key, value in host.items() if key != "tcp"})
    assert not FORBIDDEN_EXCEPT_NEWLINE.search(json.dumps(port["script"]).encode().decode("unicode_escape"))


def test_the_port_table_and_host_summary_show_one_clean_line_per_value():
    console = Console(file=io.StringIO(), width=200, color_system=None)
    rows = AnalyseScanResults(hostile_scan(), MagicMock(), console, "192.0.2.1")
    assert rows == [["192.0.2.1", 22, BANNER_CLEAN, "OpenSSH [+] P<b>", "8.9 [*] V"]]
    output = console.file.getvalue()
    assert not FORBIDDEN_EXCEPT_NEWLINE.search(output)
    assert "Vendor [+] V" in output and "Linux 5" in output and BANNER_CLEAN in output
    # Each cell stays on the row of its port: no line starts with the text a banner tried to add.
    assert not any(line.strip().startswith(("[+] ", "[*] ")) for line in output.splitlines())


def test_a_service_that_was_not_read_from_nmap_xml_is_cleaned_when_it_is_printed():
    host = {"addresses": {"mac": "AA:BB"}, "vendor": {"AA:BB": "Vend\x1b[2Jor"},
            "osmatch": [{"name": "Linux\x9b2J" + HOSTILE, "accuracy": "98", "osclass": [{"type": "gen\neral"}]}],
            "tcp": {22: {"state": "open", "name": "ssh\n[+] FORGED", "product": "Open\x1b]0;pwned\x07SSH" + HOSTILE,
                         "version": "8.9\U00002028[*] FORGED2"}}}
    scan = PortScanner(nmap_path="unused")
    scan._scan_result["scan"]["192.0.2.1"] = host
    console = Console(file=io.StringIO(), width=200, color_system=None)
    AnalyseScanResults(scan, MagicMock(), console, "192.0.2.1")
    output = console.file.getvalue()
    assert not FORBIDDEN_EXCEPT_NEWLINE.search(output)
    assert "ssh [+] FORGED" in output and "Vend[2Jor" in output and "gen eral" in output and "8.9 [*] FORGED2" in output
    assert not any(line.strip().startswith(("[+] ", "[*] ")) for line in output.splitlines())


def test_the_dashboard_keeps_and_logs_only_clean_host_text():
    pytest.importorskip("flask")
    import autopwn_suite.web_ui as wu
    wu._log_history.clear()
    job = wu.ScanJob("hostile-text-job", "192.0.2.1", {"target": "192.0.2.1"})
    failed = wu._collect_host_results(job, hostile_scan(), "192.0.2.1", wu.WebLogger(job.id),
                                      Console(file=io.StringIO()), False, None)
    assert failed is False
    host = job.hosts_list()[0]
    assert host["vendor"] == "Vendor [+] V" and host["os"] == "Linux 5"
    assert host["ports"][0]["service"] == BANNER_CLEAN and host["ports"][0]["product"] == "OpenSSH [+] P<b>"
    assert_clean(host, "host")
    assert_clean(job.to_full_dict(), "scan result")
    assert_clean(list(wu._log_history), "job log")
    assert any(BANNER_CLEAN in entry.get("msg", "") for entry in wu._log_history)


def test_the_os_fingerprint_keeps_its_lines_and_a_cpe_is_one_line():
    xml = """<nmaprun><host><status state="up"/><address addr="192.0.2.1" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="22"><state state="open"/>
<service name="ssh"><cpe>cpe:/a:x:y&#10;[+] FORGED&#8238;&#9;end</cpe></service></port></ports>
<os><osmatch name="Linux" accuracy="98"/><osfingerprint fingerprint="OS:SCAN(V=7.99%E=4)&#10;SEQ(SP=100&#8238;&#155;)&#9;x&#133;&#10;OPS(O1=M5B4)"/></os></host>
<runstats><finished exit="success"/><hosts up="1" down="0" total="1"/></runstats></nmaprun>"""
    scan = PortScanner(nmap_path="unused")
    host = scan.load_xml(xml)["scan"]["192.0.2.1"]
    # One probe result per line, as Nmap writes it; nothing else that drives a terminal.
    assert host["osfingerprint"]["fingerprint"] == "OS:SCAN(V=7.99%E=4)\nSEQ(SP=100) x\nOPS(O1=M5B4)"
    assert host["tcp"][22]["cpe"] == "cpe:/a:x:y [+] FORGED end" and host["tcp"][22]["cpes"] == ["cpe:/a:x:y [+] FORGED end"]
    assert not FORBIDDEN_EXCEPT_NEWLINE.search(host["osfingerprint"]["fingerprint"])


def test_the_error_nmap_prints_when_a_scan_fails_is_cleaned(monkeypatch):
    stderr = 'Failed to resolve "host\x1b[2J\u202e\u2028x".\nQUITTING!\n\x85'.encode()
    monkeypatch.setattr(monitored.subprocess, "Popen", MagicMock(return_value=FakeProcess(stderr=stderr, exit_code=1)))
    with pytest.raises(RuntimeError) as failed:
        monitored.scan_with_progress(MagicMock(_nmap_path="nmap"), "192.0.2.1", "-sV", MagicMock())
    assert str(failed.value) == 'Failed to resolve "host[2J x".\nQUITTING!'


def test_the_message_that_ends_a_scan_and_the_job_log_are_cleaned():
    with patch("autopwn_suite.scanner.PortScanner") as port_scanner, patch("autopwn_suite.scanner.is_root", return_value=False):
        port_scanner.return_value.scan.side_effect = RuntimeError("Failed\x1b[2J \u202eto\nresolve\u2028x")
        with pytest.raises(SystemExit) as stopped:
            PortScan("192.0.2.1", MagicMock())
    assert str(stopped.value) == "Error: Failed[2J to\nresolve x"
    pytest.importorskip("flask")
    import autopwn_suite.web_ui as wu
    wu._log_history.clear()
    job = wu.ScanJob("hostile-log-job", "192.0.2.1", {"target": "192.0.2.1"})
    wu._log(job, "[-] Port scan failed: bad\x1b[2J\u202e\u2028[+] FORGED\nsecond line", "error")
    wu.WebLogger(job.id).logger("error", ValueError("bad\x07\x85\u2029x"))
    assert [entry["msg"] for entry in wu._log_history] == ["[-] Port scan failed: bad[2J [+] FORGED\nsecond line", "bad x"]
