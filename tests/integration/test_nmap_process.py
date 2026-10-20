# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
"""Exercise real OS pipes and child cleanup using local Python children as Nmap."""

import subprocess
import sys
import threading

import pytest

from autopwn_suite import nmap_progress as runner
from autopwn_suite.nmap_backend import PortScanner

pytestmark = pytest.mark.integration


@pytest.fixture
def child_scan(monkeypatch):
    popen = subprocess.Popen
    children = []

    def launch(script):
        def spawn(command, **kwargs):
            child = popen([sys.executable, "-u", "-c", script], **kwargs)
            children.append(child)
            return child
        monkeypatch.setattr(runner.subprocess, "Popen", spawn)
        return PortScanner(nmap_path="simulated-nmap"), children

    yield launch, popen
    for child in children:
        if child.poll() is None:
            child.kill()
        child.wait(timeout=5)
        child.stdout.close()
        child.stderr.close()


def test_large_stdout_and_stderr_do_not_deadlock_or_truncate(child_scan):
    launch, _ = child_scan
    scanner, children = launch('''
import sys, threading
size = 2 * 1024 * 1024
xml = (b'<nmaprun><output type="interactive">' + b'X' * size +
       b'</output><runstats><finished exit="success" elapsed="0.1"/>' +
       b'<hosts up="0" down="0" total="0"/></runstats></nmaprun>')
def emit(stream, value):
    stream.write(value)
    stream.flush()
threads = [threading.Thread(target=emit, args=(sys.stdout.buffer, xml)),
           threading.Thread(target=emit, args=(sys.stderr.buffer, b'Warning: ' + b'Y' * size))]
for thread in threads: thread.start()
for thread in threads: thread.join()
''')
    result = scanner.scan("127.0.0.1", arguments="-n", timeout=10)
    assert result["scan"] == {}
    assert scanner.get_nmap_last_output().count(b"X") == 2 * 1024 * 1024
    assert result["nmap"]["scanwarning"][0].count("Y") == 2 * 1024 * 1024
    assert children[0].poll() == 0
    assert children[0].stdout.closed and children[0].stderr.closed


def test_cancellation_reaps_only_the_owned_child(child_scan):
    launch, popen = child_scan
    scanner, children = launch('''
import sys, time
sys.stdout.write('<nmaprun>\\n<taskbegin task="Service scan"/>\\n')
sys.stdout.flush()
time.sleep(60)
''')
    unrelated = popen([sys.executable, "-c", "import time; time.sleep(60)"],
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                      creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    stopped = threading.Event()
    try:
        with pytest.raises(runner.ScanCancelled):
            scanner.scan("127.0.0.1", progress=lambda *args: stopped.set(),
                         should_stop=stopped.is_set, timeout=5)
        assert children[0].poll() is not None
        assert children[0].stdout.closed and children[0].stderr.closed
        assert unrelated.poll() is None
        assert scanner.all_hosts() == []
    finally:
        unrelated.terminate()
        unrelated.wait(timeout=5)


def test_real_child_timeout_closes_pipes_and_reaps(child_scan):
    launch, _ = child_scan
    scanner, children = launch("import time; time.sleep(60)")
    with pytest.raises(TimeoutError, match="exceeded timeout"):
        scanner.scan("127.0.0.1", timeout=0.05)
    assert children[0].poll() is not None
    assert children[0].stdout.closed and children[0].stderr.closed
    assert scanner.all_hosts() == []


def test_progress_callback_failure_reaps_real_child(child_scan):
    launch, _ = child_scan
    scanner, children = launch('''
import sys, time
sys.stdout.write('<taskbegin task="Service scan"/>\\n')
sys.stdout.flush()
time.sleep(60)
''')

    def broken_callback(*args):
        raise RuntimeError("consumer failed")

    with pytest.raises(RuntimeError, match="Could not read Nmap"):
        scanner.scan("127.0.0.1", progress=broken_callback, timeout=5)
    assert children[0].poll() is not None
    assert children[0].stdout.closed and children[0].stderr.closed


def test_keyboard_interrupt_reaps_real_child(child_scan):
    launch, _ = child_scan
    scanner, children = launch("import time; time.sleep(60)")
    calls = 0

    def interrupted():
        nonlocal calls
        calls += 1
        if calls > 1:
            raise KeyboardInterrupt
        return False

    with pytest.raises(KeyboardInterrupt):
        scanner.scan("127.0.0.1", should_stop=interrupted, timeout=5)
    assert children[0].poll() is not None
    assert children[0].stdout.closed and children[0].stderr.closed
