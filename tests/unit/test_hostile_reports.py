# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
"""Every export and saved report of a scan with hostile text from hosts and providers is free of line breaks,
control characters and layout characters, and the HTML report stays escaped (AUTOPWN-SA-2026-016)."""

import io
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from rich.console import Console

from autopwn_suite.getexploits import GetExploitAsFile
from autopwn_suite.logger import banner
from autopwn_suite.nist_search import Vulnerability
from autopwn_suite.report import InitializeWebhookReport
from autopwn_suite.scanner import AnalyseScanResults
from autopwn_suite.searchvuln import SearchSploits, VulnerableSoftware
from autopwn_suite.utils import SaveOutput
from autopwn_suite.web.findings import emit, finding
from tests.unit.test_hostile_nmap_text import hostile_scan
from tests.unit.test_hostile_provider_text import NVD_DESCRIPTION, hostile_exploit
from tests.unit.test_hostile_text import FORBIDDEN_EXCEPT_NEWLINE, HOSTILE


def print_everything_hostile(console, tmp_path):
    """Run each output path of a scan that takes text from a host and from providers, with hostile text in all of it."""
    banner("Testing web application on http://a.test/" + HOSTILE + " ...", "purple", console)
    AnalyseScanResults(hostile_scan(), MagicMock(), console, "192.0.2.1")
    vulnerability = Vulnerability("kw", "CVE-2024-0001\n[+] FORGED", NVD_DESCRIPTION, "HIGH\x1b[2J", 9.8,
                                  "https://nvd.test/\U0000202ex", 3.9)
    lookup = SimpleNamespace(search=lambda keyword, log, key: [vulnerability])
    with patch("autopwn_suite.searchvuln.CheckConnection", return_value=True), \
         patch("autopwn_suite.searchvuln.get_terminal_width", return_value=100):
        SearchSploits([["192.0.2.1", 22, "ssh", "OpenSSH\x1b[2J", "8.9\n[+] FORGED"]], MagicMock(), console,
                      Console(file=io.StringIO()), lookup=lookup)
    emit(console, finding("DIR", "http://127.0.0.1/admin", "redirect to /admin/\r\n [+] DIR - FORGED" + HOSTILE))
    with patch("autopwn_suite.getexploits.GetExploitInfo", return_value=[hostile_exploit()]), \
         patch("autopwn_suite.getexploits.GetExploitContents", return_value=(b"data", "poc.py")):
        GetExploitAsFile(VulnerableSoftware(title="Soft\U0000202eware 1.0", CVEs=["CVE-2024-0001"]),
                         MagicMock(), console, MagicMock())


def hostile_recording_console(tmp_path):
    console = Console(file=io.StringIO(), width=200, record=True, color_system="truecolor")
    print_everything_hostile(console, tmp_path)
    return console


@pytest.mark.parametrize("kind", ["txt", "html", "svg"])
def test_the_exports_and_saved_reports_hold_none_of_the_characters(kind, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    console = hostile_recording_console(tmp_path)
    exported = {"txt": console.export_text, "html": console.export_html, "svg": console.export_svg}[kind](clear=False)
    assert "FORGED" in exported and not FORBIDDEN_EXCEPT_NEWLINE.search(exported)
    SaveOutput(console, kind, str(tmp_path / f"report.{kind}"), None, "192.0.2.1")
    content = (tmp_path / f"report.{kind}").read_text(encoding="utf-8")
    assert "FORGED" in content and not FORBIDDEN_EXCEPT_NEWLINE.search(content)
    if kind == "html":  # the HTML report stays escaped
        assert "OpenSSH [+] P&lt;b&gt;" in content and "P<b>" not in content


def test_the_webhook_report_holds_none_of_the_characters(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    console = hostile_recording_console(tmp_path)
    sent = []
    with patch("autopwn_suite.report.SendWebhook", side_effect=lambda url, log, path: sent.append(Path(path).read_text(encoding="utf-8"))):
        InitializeWebhookReport("https://hooks.test/x", MagicMock(), console)
    assert len(sent) == 1 and "FORGED" in sent[0] and not FORBIDDEN_EXCEPT_NEWLINE.search(sent[0])
