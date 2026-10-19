# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
"""NVD records, a copied vulnerability database and Exploit-DB metadata reach the console, the API and the
dashboard clean (AUTOPWN-SA-2026-016)."""

import io
import json
import sqlite3
import zlib
from contextlib import closing
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from rich.console import Console

from autopwn_suite import nist_search
from autopwn_suite import vulnerability_db as db
from autopwn_suite.getexploits import ExploitInfo, GetExploitAsFile, _safe_path_component
from autopwn_suite.nist_search import Vulnerability, searchCVE
from autopwn_suite.searchvuln import SearchSploits, VulnerableSoftware
from tests.unit.test_hostile_text import FORBIDDEN, FORBIDDEN_EXCEPT_NEWLINE, HOSTILE

# ── NVD and a copied database ────────────────────────────────────────────────

NVD_DESCRIPTION = "Heap overflow\n[+] FORGED line\x1b[2J\U0000202e\U00002028end"
NVD_DESCRIPTION_CLEAN = "Heap overflow [+] FORGED line[2J end"


def nvd_page(description, cve_id="CVE-2024-0001", severity="CRI\x1bTICAL"):
    response = MagicMock()
    response.status_code = 200
    response.json.return_value = {"totalResults": 1, "startIndex": 0, "vulnerabilities": [{"cve": {
        "id": cve_id, "descriptions": [{"lang": "en", "value": description}],
        "metrics": {"cvssMetricV31": [{"type": "Primary", "cvssData": {"baseScore": 9.8, "baseSeverity": severity},
                                       "exploitabilityScore": 3.9}]}}}]}
    return response


def test_an_nvd_description_is_one_clean_line_in_every_result(monkeypatch):
    monkeypatch.setattr(nist_search, "cache", {})
    monkeypatch.setattr(nist_search, "_cache_stored_at", {})
    with patch("autopwn_suite.nist_search.get", return_value=nvd_page(NVD_DESCRIPTION, "CVE-2024-0001\U0000200b")), \
         patch("autopwn_suite.nist_search.sleep"):
        found = searchCVE("hostile keyword", MagicMock(), "key", strict=True, force_refresh=True)
    assert [(vuln.CVEID, vuln.description, vuln.severity, vuln.details_url) for vuln in found] == [
        ("CVE-2024-0001", NVD_DESCRIPTION_CLEAN, "CRITICAL", "https://nvd.nist.gov/vuln/detail/CVE-2024-0001")]


def test_the_cve_listing_prints_the_clean_text_and_never_starts_a_line_of_its_own():
    vulnerability = Vulnerability("keyword", "CVE-2024-0001\n[+] FORGED", NVD_DESCRIPTION + " " + "word " * 40,
                                  "HIGH\x1b[2J", 9.8, "https://nvd.test/\U0000202ex", 3.9)
    console = Console(file=io.StringIO(), width=200, color_system=None)
    lookup = SimpleNamespace(search=lambda keyword, log, key: [vulnerability])
    with patch("autopwn_suite.searchvuln.CheckConnection", return_value=True), \
         patch("autopwn_suite.searchvuln.get_terminal_width", return_value=100):
        result = SearchSploits([["192.0.2.1", 22, "ssh", "OpenSSH\x1b[2J", "8.9\n[+] FORGED"]], MagicMock(), console,
                               Console(file=io.StringIO()), lookup=lookup)
    output = console.file.getvalue()
    assert not FORBIDDEN_EXCEPT_NEWLINE.search(output)
    assert NVD_DESCRIPTION_CLEAN.split()[0] in output and "CVE-2024-0001 [+] FORGED" in output
    assert not any(line.strip().startswith(("[+] ", "[*] ")) for line in output.splitlines())
    assert result[0].CVEs == ["CVE-2024-0001 [+] FORGED"]


def build_database(path, description, updated_at):
    record = {"cve": {"id": "CVE-2025-1234", "descriptions": [{"lang": "en", "value": description}],
                      "metrics": {"cvssMetricV31": [{"type": "Primary", "cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH"},
                                                     "exploitabilityScore": 3.9}]}}}
    with closing(sqlite3.connect(path)) as connection:
        connection.executescript("""CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE cves (id TEXT PRIMARY KEY, year INTEGER NOT NULL, description TEXT NOT NULL, record BLOB NOT NULL);""")
        connection.execute(f"PRAGMA user_version = {db.SCHEMA_VERSION}")
        connection.execute("INSERT INTO cves VALUES (?, ?, ?, ?)", ("CVE-2025-1234", 2025, description.casefold(),
                                                                       zlib.compress(json.dumps(record).encode())))
        connection.executemany("INSERT INTO metadata VALUES (?, ?)",
                               [("ready", "true"), ("count", "1"), ("updated_at", updated_at)])
        connection.commit()


def test_a_copied_database_cannot_put_hostile_text_into_results_or_its_own_status(tmp_path):
    path = tmp_path / "copied.sqlite3"
    build_database(path, "OpenSSH 8.2p1 flaw" + NVD_DESCRIPTION, "2026-10-19\U0000202e\n[+] FORGED")
    database = db.OfflineDatabase(path)
    try:
        found = database.search("OpenSSH 8.2p1")
        assert database.metadata["updated_at"] == "2026-10-19 [+] FORGED"
    finally:
        database.close()
    assert [vuln.description for vuln in found] == ["OpenSSH 8.2p1 flaw" + NVD_DESCRIPTION_CLEAN]
    assert db.database_status(path)["updated_at"] == "2026-10-19 [+] FORGED"


# ── Exploit-DB ───────────────────────────────────────────────────────────────

def hostile_exploit():
    return ExploitInfo(Platform="linux\n[+] FORGED" + HOSTILE, PublishDate="2026\x1b[2J", Type="remote\U0000202e",
                       ExploitDBID=1, Author="a\U00002028b", Metasploit=False, Verified=True,
                       Link="https://www.exploit-db.com/download/1\n[+] FORGED")


def test_exploit_details_are_printed_clean_and_the_file_name_on_disk_is_the_printed_one(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    console = Console(file=io.StringIO(), width=300, color_system=None)
    with patch("autopwn_suite.getexploits.GetExploitInfo", return_value=[hostile_exploit()]), \
         patch("autopwn_suite.getexploits.GetExploitContents", return_value=(b"data", "poc\U0000202egpj.py\x7f\U0000200b")):
        GetExploitAsFile(VulnerableSoftware(title="Soft\U0000202eware\n[+] X 1.0", CVEs=["CVE-2024-0001\U0000200b"]),
                         MagicMock(), console, MagicMock())
    output = console.file.getvalue()
    assert not FORBIDDEN_EXCEPT_NEWLINE.search(output)
    assert "linux [+] FORGED" in output and "Author:  a b" in output
    assert not any(line.strip().startswith(("[+] ", "[*] ")) for line in output.splitlines())
    names = [path.relative_to(tmp_path).as_posix() for path in (tmp_path / "exploits").rglob("*")]
    assert names and all(not FORBIDDEN.search(name) for name in names)
    assert (tmp_path / "exploits" / "Software_[+] X 1.0" / "CVE-2024-0001" / "pocgpj.py").read_bytes() == b"data"
    assert "exploits/Software_[+] X 1.0/CVE-2024-0001/pocgpj.py" in output


@pytest.mark.parametrize("hostile, expected", [
    ("poc\U0000202egpj.py", "pocgpj.py"),
    ("a\x7fb\x9bc\U0000200bd\U000e0041", "abcd"),
    (".\U0000200b.", "unknown"),
    ("x\U00002028y", "x y"),
    ("name\x00.txt", "name_.txt"),
])
def test_remote_names_lose_control_and_layout_characters(hostile, expected):
    assert _safe_path_component(hostile) == expected
