# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
"""Nmap progress and child-process cleanup without executing Nmap."""
import io
import subprocess
from unittest.mock import MagicMock

import pytest

from modules import nmap_progress as monitored

XML = b'''<?xml version="1.0"?>
<nmaprun>
<taskbegin task="SYN Stealth Scan" time="1"/>
<taskprogress task="SYN Stealth Scan" percent="42.50" time="2"/>
<taskend task="SYN Stealth Scan" time="3"/>
<taskbegin task="Service scan" time="3"/>
<taskprogress task="Service scan" percent="12.00" time="4"/>
</nmaprun>
'''


class FakeProcess:
    def __init__(self, stdout=XML, stderr=b"", exit_code=0, timeouts=0, stubborn=False):
        self.stdout = io.BytesIO(stdout)
        self.stderr = io.BytesIO(stderr)
        self.returncode = None
        self.exit_code = exit_code
        self.timeouts = timeouts
        self.stubborn = stubborn
        self.terminated = False
        self.killed = False

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        if self.returncode is not None:
            return self.returncode
        if self.timeouts or (self.terminated and self.stubborn):
            self.timeouts = max(0, self.timeouts - 1)
            raise subprocess.TimeoutExpired("nmap", timeout)
        self.returncode = self.exit_code
        return self.returncode

    def terminate(self):
        self.terminated = True
        if not self.stubborn:
            self.returncode = -15

    def kill(self):
        self.killed = True
        self.returncode = -9


@pytest.fixture
def fake_spawn(monkeypatch):
    process = FakeProcess()
    spawn = MagicMock(return_value=process)
    monkeypatch.setattr(monitored.subprocess, "Popen", spawn)
    return spawn, process


def scanner():
    value = MagicMock()
    value._nmap_path = "C:/Program Files/Nmap/nmap.exe"
    return value


def test_streams_task_progress_and_preserves_complete_xml(fake_spawn):
    spawn, process = fake_spawn
    nm = scanner()
    updates = []
    monitored.scan_with_progress(nm, "192.0.2.1 192.0.2.2", "-sV -p 22,80 -n", lambda *args: updates.append(args))
    assert updates == [("SYN Stealth Scan", None), ("SYN Stealth Scan", 42.5),
                       ("SYN Stealth Scan", 100.0), ("Service scan", None), ("Service scan", 12.0)]
    args = spawn.call_args.args[0]
    assert args[:3] == [nm._nmap_path, "-oX", "-"]
    assert "--stats-every" in args and "-v" in args and "-n" in args
    assert "192.0.2.1" in args and "192.0.2.2" in args
    assert spawn.call_args.kwargs.get("shell", False) is False
    nm.load_xml.assert_called_once_with(XML, stderr="")
    assert process.stdout.closed and process.stderr.closed
    assert not process.terminated


def test_unknown_or_invalid_statistics_are_ignored():
    callback = MagicMock()
    for line in (b'<taskprogress task="Scan" percent="NaN"/>', b'<taskprogress task="Scan" percent="101"/>',
                 b'<taskprogress task="Scan" percent="-1"/>', b'<taskprogress percent="50"/>',
                 b'<taskprogress task="Scan"/>', b'<taskbegin task="broken &"/>', b'<host/>'):
        monitored.report_progress(line, callback)
    callback.assert_not_called()


@pytest.mark.parametrize("stubborn", [False, True])
def test_cancel_stops_only_this_child_process_and_closes_pipes(fake_spawn, stubborn):
    spawn, _ = fake_spawn
    process = FakeProcess(timeouts=1, stubborn=stubborn)
    spawn.return_value = process
    stops = iter([False, False, True])
    nm = scanner()
    with pytest.raises(monitored.ScanCancelled):
        monitored.scan_with_progress(nm, "192.0.2.1", "-sV", MagicMock(), lambda: next(stops, True))
    assert process.terminated and process.killed is stubborn
    assert process.stdout.closed and process.stderr.closed
    nm.load_xml.assert_not_called()


def test_cancel_before_launch_does_not_spawn(fake_spawn):
    spawn, _ = fake_spawn
    with pytest.raises(monitored.ScanCancelled):
        monitored.scan_with_progress(scanner(), "192.0.2.1", "-sV", MagicMock(), lambda: True)
    spawn.assert_not_called()


def test_child_failure_is_not_parsed_as_success(fake_spawn):
    spawn, _ = fake_spawn
    process = FakeProcess(stderr=b"nmap: permission denied", exit_code=1)
    spawn.return_value = process
    nm = scanner()
    with pytest.raises(RuntimeError, match="permission denied"):
        monitored.scan_with_progress(nm, "192.0.2.1", "-sV", MagicMock())
    nm.load_xml.assert_not_called()
    assert process.stderr.closed


def test_xml_redirection_cannot_replace_the_managed_output(fake_spawn):
    spawn, _ = fake_spawn
    with pytest.raises(ValueError, match="redirected"):
        monitored.scan_with_progress(scanner(), "192.0.2.1", "-oA unrelated", MagicMock())
    spawn.assert_not_called()


def test_reader_error_still_drains_and_reaps_child(fake_spawn):
    _, process = fake_spawn
    callback = MagicMock(side_effect=RuntimeError("callback failed"))
    with pytest.raises(RuntimeError, match="read Nmap"):
        monitored.scan_with_progress(scanner(), "192.0.2.1", "-sV", callback)
    assert process.poll() is not None and process.stdout.closed and process.stderr.closed


def test_reader_start_failure_reaps_child(fake_spawn, monkeypatch):
    _, process = fake_spawn
    monkeypatch.setattr(monitored.threading.Thread, "start", MagicMock(side_effect=RuntimeError("no thread")))
    with pytest.raises(RuntimeError, match="no thread"):
        monitored.scan_with_progress(scanner(), "192.0.2.1", "-sV", MagicMock())
    assert process.terminated and process.stdout.closed and process.stderr.closed


@pytest.mark.parametrize("fail_on", [1, 2])
def test_reader_construction_failure_reaps_child(fake_spawn, monkeypatch, fail_on):
    _, process = fake_spawn
    thread_type = monitored.threading.Thread
    calls = 0

    def create_reader(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == fail_on:
            raise RuntimeError("cannot construct reader")
        return thread_type(*args, **kwargs)

    monkeypatch.setattr(monitored.threading, "Thread", create_reader)
    with pytest.raises(RuntimeError, match="cannot construct reader"):
        monitored.scan_with_progress(scanner(), "192.0.2.1", "-sV", MagicMock())
    assert process.terminated and process.stdout.closed and process.stderr.closed


def test_stderr_is_preserved_for_the_xml_parser(fake_spawn):
    spawn, _ = fake_spawn
    spawn.return_value = FakeProcess(stderr=b"Warning: host timeout\nUnreachable host\n")
    nm = scanner()
    monitored.scan_with_progress(nm, "192.0.2.1", "-sV", MagicMock())
    nm.load_xml.assert_called_once_with(XML, stderr="Warning: host timeout\nUnreachable host\n")


def test_streaming_preserves_host_and_service_results(fake_spawn):
    from modules.nmap_backend import PortScanner
    xml = b'''<nmaprun args="nmap -sV 192.0.2.1">
      <scaninfo type="syn" protocol="tcp" numservices="1" services="22"/>
      <taskprogress task="Service scan" time="2" percent="75.00"/>
      <host><status state="up" reason="syn-ack"/><address addr="192.0.2.1" addrtype="ipv4"/>
        <ports><port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/>
          <service name="ssh" product="OpenSSH" version="8.2p1" method="probed" conf="10"/>
        </port></ports></host>
      <runstats><finished time="3" timestr="done" elapsed="2.0"/><hosts up="1" down="0" total="1"/></runstats>
    </nmaprun>'''
    fake_spawn[0].return_value = FakeProcess(stdout=xml)
    nm = PortScanner(nmap_path="nmap")
    monitored.scan_with_progress(nm, "192.0.2.1", "-sV", MagicMock())
    assert nm.all_hosts() == ["192.0.2.1"]
    assert nm["192.0.2.1"]["tcp"][22]["product"] == "OpenSSH"
    assert nm["192.0.2.1"]["tcp"][22]["version"] == "8.2p1"
    assert nm.get_nmap_last_output() == xml


def test_pipe_read_error_aborts_nmap_instead_of_waiting_forever(fake_spawn, monkeypatch):
    class BrokenPipe(io.BytesIO):
        def readline(self):
            raise OSError("pipe read failed")
    class StalledProcess(FakeProcess):
        def wait(self, timeout=None):
            if self.returncode is not None:
                return self.returncode
            raise subprocess.TimeoutExpired("nmap", timeout)
    class InlineReader:
        def __init__(self, target, args, daemon):
            self.target, self.args = target, args
        def start(self):
            self.target(*self.args)
        def join(self):
            pass
    monkeypatch.setattr(monitored.threading, "Thread", InlineReader)
    process = StalledProcess()
    process.stdout = BrokenPipe()
    fake_spawn[0].return_value = process
    calls = 0
    def stop_guard():
        nonlocal calls
        calls += 1
        return calls > 4  # Bound an unfixed implementation without leaving a child.
    with pytest.raises(RuntimeError, match="read Nmap"):
        monitored.scan_with_progress(scanner(), "192.0.2.1", "-sV", MagicMock(), stop_guard)
    assert process.terminated and process.stdout.closed and process.stderr.closed
