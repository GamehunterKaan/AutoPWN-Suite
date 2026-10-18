# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
"""Run the system Nmap executable and parse its documented XML format.

This adapter implements the scan/result interface used by AutoPWN. Nmap remains
responsible for packet handling, discovery, service probes, OS detection and NSE.
The parser is independent of the executable, so recorded results work offline.
"""

import ipaddress
import shlex
import shutil
from xml.etree import ElementTree

from autopwn_suite.nmap_progress import scan_with_progress


def _script_elements(parent):
    """Keep ordered NSE tables/elements, including repeated or absent keys."""
    return [{"tag": child.tag, **child.attrib, "text": child.text or "",
             "children": _script_elements(child)} for child in parent]


def _scripts(parent):
    return [{**script.attrib, "elements": _script_elements(script)}
            for script in parent.findall("script")]


def _os_classes(parent):
    return [{**entry.attrib, "cpe": [cpe.text or "" for cpe in entry.findall("cpe")]}
            for entry in parent.findall("osclass")]


def _host(element):
    addresses = {entry.get("addrtype"): entry.get("addr", "")
                 for entry in element.findall("address") if entry.get("addrtype")}
    # A MAC address is metadata, never a target for subsequent port/web scans.
    address = addresses.get("ipv4") or addresses.get("ipv6")
    if not address:
        return None, None
    status = element.find("status")
    host = {**element.attrib, "addresses": addresses,
            "vendor": {entry.get("addr", ""): entry.get("vendor")
                       for entry in element.findall("address") if entry.get("vendor")},
            "hostnames": [dict(entry.attrib) for entry in element.findall("hostnames/hostname")],
            "status": {"state": "unknown", "reason": "",
                       **(status.attrib if status is not None else {})}}

    for port in element.findall("ports/port"):
        protocol = port.get("protocol")
        try:
            number = int(port.attrib["portid"])
            if not protocol or number < 0:
                raise ValueError("invalid port")
        except (KeyError, ValueError) as exc:
            raise RuntimeError("Invalid port in Nmap XML") from exc
        state = port.find("state")
        service = port.find("service")
        data = {"state": "unknown", "reason": "", "name": "", "product": "",
                "version": "", "extrainfo": "", "conf": "", "cpe": ""}
        if state is not None:
            data.update(state.attrib)
        if service is not None:
            data.update(service.attrib)
            cpes = [entry.text or "" for entry in service.findall("cpe")]
            if cpes:
                data.update(cpe=cpes[0], cpes=cpes)
        scripts = _scripts(port)
        if scripts:
            data["script"] = {entry.get("id", ""): entry.get("output", "") for entry in scripts}
            data["script_details"] = scripts
        host.setdefault(protocol, {})[number] = data

    extraports = element.findall("ports/extraports")
    if extraports:
        host["extraports"] = [{**entry.attrib,
                               "extrareasons": [dict(reason.attrib) for reason in entry]}
                              for entry in extraports]
    os = element.find("os")
    if os is not None:
        classes = _os_classes(os)  # Older XML can place osclass directly under os.
        host["osmatch"] = [{**match.attrib, "osclass": _os_classes(match) or classes}
                           for match in os.findall("osmatch")]
        host["portused"] = [dict(entry.attrib) for entry in os.findall("portused")]
        fingerprint = os.find("osfingerprint")
        if fingerprint is not None:
            host["osfingerprint"] = dict(fingerprint.attrib)
    scripts = element.find("hostscript")
    if scripts is not None:
        host["hostscript"] = _scripts(scripts)
    for tag in ("uptime", "distance", "tcpsequence", "ipidsequence", "tcptssequence", "times"):
        entry = element.find(tag)
        if entry is not None:
            host[tag] = dict(entry.attrib)
    trace = element.find("trace")
    if trace is not None:
        host["trace"] = {**trace.attrib, "hops": [dict(hop.attrib) for hop in trace.findall("hop")]}
    return address, host


def parse_nmap_xml(xml, stderr=""):
    """Return the project's host/service mapping; reject failed/incomplete runs."""
    try:
        root = ElementTree.fromstring(xml)
    except (ElementTree.ParseError, ValueError) as exc:
        raise RuntimeError("Invalid or incomplete Nmap XML output") from exc
    if root.tag != "nmaprun":
        raise RuntimeError("Expected nmaprun XML output")
    finished = root.find("runstats/finished")
    hosts = root.find("runstats/hosts")
    if finished is None or hosts is None:
        raise RuntimeError("Incomplete Nmap XML: missing run statistics")
    if finished.get("exit") == "error":
        raise RuntimeError(finished.get("errormsg") or stderr.strip() or "Nmap scan failed")

    scaninfo = root.findall("scaninfo")
    metadata = {**root.attrib, "command_line": root.get("args", ""),
                "scaninfo": {entry.get("protocol", ""): {"method": entry.get("type", ""),
                                                           "services": entry.get("services", "")}
                             for entry in scaninfo},
                "scaninfo_details": [dict(entry.attrib) for entry in scaninfo],
                "scanstats": {**finished.attrib, "uphosts": hosts.get("up", "0"),
                              "downhosts": hosts.get("down", "0"), "totalhosts": hosts.get("total", "0")},
                "scanwarning": [], "scanerror": []}
    for line in stderr.splitlines():
        if line.strip():
            key = "scanwarning" if line.lstrip().lower().startswith("warning:") else "scanerror"
            metadata[key].append(line)
    for tag in ("prescript", "postscript"):
        entry = root.find(tag)
        if entry is not None:
            metadata[tag] = _scripts(entry)
    result = {"nmap": metadata, "scan": {}}
    for element in root.findall("host"):
        address, host = _host(element)
        if address:
            result["scan"][address] = host
    return result


class PortScanner:
    """Small Nmap adapter shared by the CLI, Python API and dashboard workers."""

    def __init__(self, nmap_path=None):
        self._nmap_path = nmap_path or shutil.which("nmap")
        if not self._nmap_path:
            raise RuntimeError("Nmap executable not found. Install Nmap and add it to PATH.")
        self.clear()

    def clear(self):
        self._scan_result = {"nmap": {}, "scan": {}}
        self._nmap_last_output = b""

    def scan(self, hosts="127.0.0.1", ports=None, arguments="-sV", *,
             progress=None, should_stop=None, timeout=None):
        """Scan using an argument list (no shell); timeout applies to the whole run."""
        self.clear()
        if ports is not None:
            # Keep port selections separate from executable/target arguments.
            flags = shlex.split(arguments) if isinstance(arguments, str) else list(arguments)
            arguments = [*flags, "-p", str(ports)]
        return scan_with_progress(self, hosts, arguments, progress, should_stop, timeout=timeout)

    def load_xml(self, xml, stderr=""):
        """Load a recorded scan without running Nmap or retaining old host results."""
        self.clear()
        self._nmap_last_output = xml
        self._scan_result = parse_nmap_xml(xml, stderr)
        return self._scan_result

    def __getitem__(self, host):
        return self._scan_result["scan"][host]

    def all_hosts(self, *, up_only=False):
        def address_key(address):
            value = ipaddress.ip_address(address)
            return value.version, int(value)
        hosts = self._scan_result["scan"]
        return sorted((address for address, data in hosts.items()
                       if not up_only or data["status"]["state"] == "up"), key=address_key)

    def has_host(self, host):
        return host in self._scan_result["scan"]

    def command_line(self):
        return self._scan_result["nmap"].get("command_line", "")

    def scaninfo(self):
        return self._scan_result["nmap"].get("scaninfo", {})

    def scanstats(self):
        return self._scan_result["nmap"].get("scanstats", {})

    def get_nmap_last_output(self):
        return self._nmap_last_output
