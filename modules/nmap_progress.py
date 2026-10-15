"""Own Nmap subprocesses, drain XML output and optionally stream task progress."""

import math
import re
import shlex
import subprocess
import tempfile
import threading
import time
from xml.etree import ElementTree


class ScanCancelled(RuntimeError):
    pass


_TASK = re.compile(rb"<(taskbegin|taskprogress|taskend)\b[^>]*?/>")


def report_progress(line, callback):
    for match in _TASK.finditer(line):
        try:
            element = ElementTree.fromstring(match.group())
            percent = None
            if element.tag == "taskend":
                percent = 100.0
            elif element.tag == "taskprogress":
                percent = float(element.attrib["percent"])
                if not math.isfinite(percent) or not 0 <= percent <= 100:
                    continue
            callback(element.attrib["task"], percent)
        except (ElementTree.ParseError, ValueError, KeyError):
            # Progress is optional; malformed statistics must not damage results.
            continue


def _tokens(value):
    if isinstance(value, str):
        return shlex.split(value)
    if isinstance(value, (list, tuple)) and all(isinstance(token, str) for token in value):
        return list(value)
    raise TypeError("Nmap targets and arguments must be strings or lists of strings")


def scan_with_progress(scanner, hosts, arguments, progress=None, should_stop=None, *, timeout=None):
    """Run only this job's Nmap process; drain both pipes and stop it on request."""
    scanner.clear()
    flags = _tokens(arguments)
    targets = _tokens(hosts)
    if any(flag.startswith(("-oX", "-oA", "--resume", "--append-output")) for flag in flags):
        raise ValueError("XML scan output cannot be redirected")
    if any(target.startswith("-") for target in targets):
        raise ValueError("Targets cannot contain Nmap options")
    if progress is not None and not callable(progress):
        raise TypeError("Nmap progress must be a callback")
    if timeout is not None and (not math.isfinite(timeout) or timeout <= 0):
        raise ValueError("Nmap timeout must be a positive finite number")
    # Verbosity exposes task begin/end; statistics expose each task's percentage.
    command = [scanner._nmap_path, "-oX", "-"]
    if progress is not None:
        command += ["-v", "--stats-every", "1s"]
    command += targets + flags
    should_stop = should_stop or (lambda: False)
    if should_stop():
        raise ScanCancelled("Scan stopped by user")
    deadline = time.monotonic() + timeout if timeout is not None else None

    errors = []
    with tempfile.SpooledTemporaryFile(max_size=1024 * 1024) as output, tempfile.SpooledTemporaryFile(max_size=1024 * 1024) as error_output:
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, bufsize=65536,
                                   creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0), shell=False)

        def drain(stream, destination, report=False):
            failed = False
            try:
                for line in iter(stream.readline, b""):
                    if failed:
                        continue
                    try:
                        destination.write(line)
                        if report and progress is not None:
                            report_progress(line, progress)
                    except Exception as exc:
                        errors.append(exc)
                        failed = True  # Continue draining so Nmap cannot deadlock.
            except Exception as exc:
                errors.append(exc)

        started_readers = []
        cancelled = False
        timed_out = False
        try:
            # Reader construction can fail too; the child already belongs to us.
            for stream, destination, report in ((process.stdout, output, True),
                                                (process.stderr, error_output, False)):
                reader = threading.Thread(target=drain, args=(stream, destination, report), daemon=True)
                reader.start()
                started_readers.append(reader)
            while True:
                if errors:
                    break
                if should_stop():
                    cancelled = True
                    break
                wait_timeout = 0.25
                if deadline is not None:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        timed_out = True
                        break
                    wait_timeout = min(wait_timeout, remaining)
                try:
                    process.wait(timeout=wait_timeout)
                    break
                except subprocess.TimeoutExpired:
                    continue
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
            for reader in started_readers:
                reader.join()
            process.stdout.close()
            process.stderr.close()
        if cancelled or should_stop():
            raise ScanCancelled("Scan stopped by user")
        if timed_out:
            raise TimeoutError(f"Nmap scan exceeded timeout of {timeout} seconds")
        if errors:
            raise RuntimeError("Could not read Nmap scan output") from errors[0]
        output.seek(0)
        error_output.seek(0)
        xml = output.read()
        stderr = error_output.read().decode("utf-8", errors="replace")
        if process.returncode:
            raise RuntimeError(stderr.strip() or "Nmap scan failed")
        return scanner.load_xml(xml, stderr=stderr)
