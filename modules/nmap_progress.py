"""Stream Nmap's XML task progress while preserving python-nmap result parsing."""

import math
import re
import shlex
import subprocess
import tempfile
import threading
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


def scan_with_progress(scanner, hosts, arguments, progress, should_stop=None):
    """Run only this job's Nmap process; drain both pipes and stop it on request."""
    flags = shlex.split(arguments)
    if any(flag.startswith(("-oX", "-oA")) for flag in flags):
        raise ValueError("XML scan output cannot be redirected")
    # Verbosity exposes task begin/end; statistics expose each task's percentage.
    command = [scanner._nmap_path, "-oX", "-", "-v", "--stats-every", "1s"]
    command += shlex.split(hosts) + flags
    should_stop = should_stop or (lambda: False)
    if should_stop():
        raise ScanCancelled("Scan stopped by user")

    errors = []
    with tempfile.SpooledTemporaryFile(max_size=1024 * 1024) as output, tempfile.SpooledTemporaryFile(max_size=1024 * 1024) as error_output:
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, bufsize=65536,
                                   creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))

        def drain(stream, destination, report=False):
            failed = False
            try:
                for line in iter(stream.readline, b""):
                    if failed:
                        continue
                    try:
                        destination.write(line)
                        if report:
                            report_progress(line, progress)
                    except Exception as exc:
                        errors.append(exc)
                        failed = True  # Continue draining so Nmap cannot deadlock.
            except Exception as exc:
                errors.append(exc)

        readers = [threading.Thread(target=drain, args=(process.stdout, output, True), daemon=True),
                   threading.Thread(target=drain, args=(process.stderr, error_output), daemon=True)]
        started_readers = []
        cancelled = False
        try:
            for reader in readers:
                reader.start()
                started_readers.append(reader)
            while True:
                if errors:
                    break
                if should_stop():
                    cancelled = True
                    break
                try:
                    process.wait(timeout=0.25)
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
        if errors:
            raise RuntimeError("Could not read Nmap scan output") from errors[0]
        output.seek(0)
        error_output.seek(0)
        xml = output.read()
        stderr = error_output.read().decode("utf-8", errors="replace")
        if process.returncode:
            raise RuntimeError(stderr.strip() or "Nmap scan failed")
        warnings = [line for line in stderr.splitlines() if line.lower().startswith("warning:")]
        failures = [line for line in stderr.splitlines() if not line.lower().startswith("warning:")]
        scanner._nmap_last_output = xml
        scanner.analyse_nmap_xml_scan(nmap_xml_output=xml, nmap_err=stderr,
                                     nmap_err_keep_trace=failures, nmap_warn_keep_trace=warnings)
