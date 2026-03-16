"""
AutoPWN Suite - Embedded Web UI
================================
Usage:
    autopwn-suite --web [--web-host 0.0.0.0] [--web-port 8080]

Features:
  - Multiple concurrent scans (browser-launched)
  - Scan profiles (saved configurations)
  - Scheduled scans (cron-style)
  - Email + webhook notifications on scan completion
  - Persistent settings (stored in web_ui_settings.json)

API:
  GET  /                        -> dashboard

  Scans:
  GET  /api/scans               -> list all scan jobs
  POST /api/scan/start          -> start a new scan
  POST /api/scan/stop           -> stop a scan {"scan_id": "..."}

  Hosts / log / events:
  GET  /api/hosts               -> all hosts (merged)
  GET  /api/log                 -> log history
  GET  /api/events              -> SSE stream

  Settings:
  GET  /api/settings            -> all settings
  PUT  /api/settings            -> save settings (full replace)

  Profiles:
  GET  /api/profiles            -> list scan profiles
  POST /api/profiles            -> create profile
  PUT  /api/profiles/<id>       -> update profile
  DELETE /api/profiles/<id>     -> delete profile

  Schedules:
  GET  /api/schedules           -> list scheduled scans
  POST /api/schedules           -> create schedule
  PUT  /api/schedules/<id>      -> update schedule
  DELETE /api/schedules/<id>    -> delete schedule
"""

from __future__ import annotations

import io
import json
import queue
import shutil
import smtplib
import threading
import time
import uuid
from datetime import datetime, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from typing import Optional

try:
    import requests as _requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    from flask import Flask, Response, jsonify, request, send_from_directory
    from flask_cors import CORS
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False


# ── Paths ─────────────────────────────────────────────────────────────────────

_MODULE_DIR  = Path(__file__).parent
_STATIC_DIR  = _MODULE_DIR / "web_ui_static"
_SETTINGS_FILE = _MODULE_DIR / "web_ui_settings.json"


# ── Settings persistence ──────────────────────────────────────────────────────

_DEFAULT_SETTINGS = {
    "nist_api_key": "",
    "email": {
        "enabled":  False,
        "smtp_host": "",
        "smtp_port": 587,
        "username":  "",
        "password":  "",
        "from_addr": "",
        "to_addr":   "",
        "on_complete": True,
        "on_error":    True,
        "on_vuln_found": True,
    },
    "webhook": {
        "enabled":       False,
        "url":           "",
        "on_complete":   True,
        "on_error":      True,
        "on_vuln_found": True,
    },
}

_settings: dict = {}
_settings_lock  = threading.Lock()


def _load_settings() -> None:
    global _settings
    if _SETTINGS_FILE.exists():
        try:
            data = json.loads(_SETTINGS_FILE.read_text(encoding="utf-8"))
            # Deep merge with defaults so new keys are always present
            merged = _deep_merge(_DEFAULT_SETTINGS, data)
            with _settings_lock:
                _settings = merged
            return
        except Exception:
            pass
    with _settings_lock:
        _settings = _deep_merge(_DEFAULT_SETTINGS, {})
    _save_settings()


def _save_settings() -> None:
    with _settings_lock:
        data = dict(_settings)
    _SETTINGS_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")


def _deep_merge(base: dict, override: dict) -> dict:
    result = dict(base)
    for k, v in override.items():
        if k in result and isinstance(result[k], dict) and isinstance(v, dict):
            result[k] = _deep_merge(result[k], v)
        else:
            result[k] = v
    return result


def _get_setting(*keys):
    with _settings_lock:
        d = _settings
    for k in keys:
        d = d.get(k, {}) if isinstance(d, dict) else None
        if d is None:
            return None
    return d


# ── Profiles persistence ──────────────────────────────────────────────────────

_PROFILES_FILE = _MODULE_DIR / "web_ui_profiles.json"
_profiles: dict = {}   # id -> profile dict
_profiles_lock  = threading.Lock()


def _load_profiles() -> None:
    global _profiles
    if _PROFILES_FILE.exists():
        try:
            data = json.loads(_PROFILES_FILE.read_text(encoding="utf-8"))
            with _profiles_lock:
                _profiles = data
            return
        except Exception:
            pass
    with _profiles_lock:
        _profiles = {}


def _save_profiles() -> None:
    with _profiles_lock:
        data = dict(_profiles)
    _PROFILES_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")


# ── Schedules persistence ─────────────────────────────────────────────────────

_SCHEDULES_FILE = _MODULE_DIR / "web_ui_schedules.json"
_schedules: dict = {}   # id -> schedule dict
_schedules_lock  = threading.Lock()

# Track last-run time per schedule so we don't double-fire
_schedule_last_run: dict = {}
_schedule_last_run_lock = threading.Lock()


def _load_schedules() -> None:
    global _schedules
    if _SCHEDULES_FILE.exists():
        try:
            data = json.loads(_SCHEDULES_FILE.read_text(encoding="utf-8"))
            with _schedules_lock:
                _schedules = data
            return
        except Exception:
            pass
    with _schedules_lock:
        _schedules = {}


def _save_schedules() -> None:
    with _schedules_lock:
        data = dict(_schedules)
    _SCHEDULES_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")


# ── Per-scan job ──────────────────────────────────────────────────────────────

class ScanJob:
    def __init__(self, scan_id: str, target: str, config: dict):
        self.id          = scan_id
        self.target      = target
        self.config      = config
        self.status      = "running"
        self.started_at  = datetime.utcnow().isoformat()
        self.finished_at = ""
        self.error       = ""
        self._lock       = threading.Lock()
        self._stop_flag  = threading.Event()
        self._hosts: dict[str, dict] = {}

    def should_stop(self) -> bool:
        return self._stop_flag.is_set()

    def request_stop(self) -> None:
        self._stop_flag.set()
        with self._lock:
            if self.status == "running":
                self.status = "stopping"

    def mark_done(self) -> None:
        with self._lock:
            self.status      = "completed"
            self.finished_at = datetime.utcnow().isoformat()

    def mark_error(self, msg: str) -> None:
        with self._lock:
            self.status      = "error"
            self.error       = msg
            self.finished_at = datetime.utcnow().isoformat()

    def get_or_create_host(self, ip: str) -> dict:
        with self._lock:
            if ip not in self._hosts:
                self._hosts[ip] = {
                    "ip": ip, "mac": "", "vendor": "", "os": "",
                    "ports": [], "vulns": [],
                    "scan_status": "scanning",
                    "scan_id":     self.id,
                }
            return self._hosts[ip]

    def mark_host_done(self, ip: str) -> None:
        with self._lock:
            if ip in self._hosts:
                self._hosts[ip]["scan_status"] = "completed"

    def hosts_list(self) -> list:
        with self._lock:
            return list(self._hosts.values())

    def to_dict(self) -> dict:
        with self._lock:
            hosts = list(self._hosts.values())
        return {
            "id":          self.id,
            "target":      self.target,
            "config":      self.config,
            "status":      self.status,
            "started_at":  self.started_at,
            "finished_at": self.finished_at,
            "error":       self.error,
            "host_count":  len(hosts),
            "port_count":  sum(len(h["ports"]) for h in hosts),
            "vuln_count":  sum(len(h["vulns"])  for h in hosts),
        }


# ── Global scan registry + SSE ────────────────────────────────────────────────

_scans: dict[str, ScanJob] = {}
_scans_lock   = threading.Lock()
_broadcast_q: queue.Queue = queue.Queue()
_log_history: list = []
_log_history_lock = threading.Lock()


def _broadcast(event: dict) -> None:
    with _log_history_lock:
        _log_history.append(event)
    _broadcast_q.put(event)


def _register_scan(job: ScanJob) -> None:
    with _scans_lock:
        _scans[job.id] = job


def _get_scan(scan_id: str) -> Optional[ScanJob]:
    with _scans_lock:
        return _scans.get(scan_id)


def _all_scans() -> list[ScanJob]:
    with _scans_lock:
        return list(_scans.values())


# ── WebLogger ─────────────────────────────────────────────────────────────────

class WebLogger:
    _LEVEL_MAP = {"info": "info", "error": "error", "warning": "warning", "success": "success"}

    def __init__(self, scan_id: str):
        self.scan_id = scan_id

    def logger(self, exception_: str, message: str) -> None:
        level = self._LEVEL_MAP.get(exception_, "info")
        _broadcast({
            "scan_id": self.scan_id,
            "ts":      datetime.utcnow().strftime("%H:%M:%S"),
            "level":   level,
            "msg":     str(message),
        })


# ── NullConsole ───────────────────────────────────────────────────────────────

class _NullStatus:
    def __enter__(self): return self
    def __exit__(self, *_): pass
    def start(self): pass
    def stop(self): pass
    def update(self, *_, **__): pass


class NullConsole:
    def status(self, *_, **__): return _NullStatus()
    def print(self, *_, **__): pass


# ── Notifications ─────────────────────────────────────────────────────────────

def _send_webhook(job: ScanJob) -> None:
    cfg = _get_setting("webhook")
    if not cfg or not cfg.get("enabled") or not cfg.get("url"):
        return
    if not REQUESTS_AVAILABLE:
        return

    hosts = job.hosts_list()
    vuln_count = sum(len(h["vulns"]) for h in hosts)

    if job.status == "completed" and not cfg.get("on_complete"):
        return
    if job.status == "error" and not cfg.get("on_error"):
        return
    if vuln_count and not cfg.get("on_vuln_found"):
        return

    payload = {
        "event":      "scan_" + job.status,
        "scan_id":    job.id,
        "target":     job.target,
        "host_count": len(hosts),
        "vuln_count": vuln_count,
        "started_at": job.started_at,
        "finished_at":job.finished_at,
        "error":      job.error,
        "timestamp":  datetime.utcnow().isoformat(),
    }
    try:
        _requests.post(cfg["url"], json=payload, timeout=10)
    except Exception as e:
        _broadcast({
            "scan_id": job.id, "level": "warning",
            "ts": datetime.utcnow().strftime("%H:%M:%S"),
            "msg": f"[*] Webhook delivery failed: {e}",
        })


def _send_email(job: ScanJob) -> None:
    cfg = _get_setting("email")
    if not cfg or not cfg.get("enabled"):
        return
    if not cfg.get("smtp_host") or not cfg.get("to_addr"):
        return

    hosts     = job.hosts_list()
    vuln_count = sum(len(h["vulns"]) for h in hosts)

    if job.status == "completed" and not cfg.get("on_complete"):
        return
    if job.status == "error" and not cfg.get("on_error"):
        return
    if vuln_count and not cfg.get("on_vuln_found"):
        return

    subject = f"[AutoPWN] Scan {job.status.upper()} — {job.target}"
    lines   = [
        f"Target:     {job.target}",
        f"Status:     {job.status}",
        f"Hosts:      {len(hosts)}",
        f"Open ports: {sum(len(h['ports']) for h in hosts)}",
        f"CVEs found: {vuln_count}",
        f"Started:    {job.started_at}",
        f"Finished:   {job.finished_at}",
    ]
    if job.error:
        lines.append(f"Error:      {job.error}")

    # Add top CVEs
    all_vulns = sorted(
        [v for h in hosts for v in h["vulns"]],
        key=lambda v: v.get("cvss", 0), reverse=True
    )[:10]
    if all_vulns:
        lines.append("\nTop vulnerabilities:")
        for v in all_vulns:
            lines.append(f"  {v['cve']}  [{v['severity'].upper()}]  CVSS:{v.get('cvss','?')}  {v['description'][:80]}")

    body = "\n".join(lines)

    try:
        msg = MIMEMultipart()
        msg["From"]    = cfg.get("from_addr") or cfg.get("username", "")
        msg["To"]      = cfg["to_addr"]
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "plain"))

        with smtplib.SMTP(cfg["smtp_host"], int(cfg.get("smtp_port", 587))) as srv:
            srv.ehlo()
            srv.starttls()
            if cfg.get("username") and cfg.get("password"):
                srv.login(cfg["username"], cfg["password"])
            srv.sendmail(msg["From"], [cfg["to_addr"]], msg.as_string())
    except Exception as e:
        _broadcast({
            "scan_id": job.id, "level": "warning",
            "ts": datetime.utcnow().strftime("%H:%M:%S"),
            "msg": f"[*] Email notification failed: {e}",
        })


def _notify(job: ScanJob) -> None:
    threading.Thread(target=_send_webhook, args=(job,), daemon=True).start()
    threading.Thread(target=_send_email,   args=(job,), daemon=True).start()


# ── Scan engine ───────────────────────────────────────────────────────────────

def _log(job: ScanJob, msg: str, level: str = "info") -> None:
    _broadcast({
        "scan_id": job.id,
        "ts":      datetime.utcnow().strftime("%H:%M:%S"),
        "level":   level,
        "msg":     msg,
    })


def _run_scan(job: ScanJob) -> None:
    config         = job.config
    target         = config["target"]
    mode           = config.get("mode", "normal")
    speed          = int(config.get("speed", 3))
    scan_type      = config.get("scan_type") or None
    nmap_flags     = config.get("nmap_flags", "")
    api_key        = config.get("api_key") or _get_setting("nist_api_key") or None
    host_timeout   = int(config.get("host_timeout", 240))
    scan_ports     = config.get("scan_ports", True)
    scan_vulns     = config.get("scan_vulns", True)
    skip_discovery = config.get("skip_discovery", False)

    log  = WebLogger(job.id)
    null = NullConsole()

    try:
        from rich.console import Console
        silent = Console(file=io.StringIO(), color_system=None)

        _log(job, f"[*] Starting scan on {target}")

        if not shutil.which("nmap"):
            _log(job, "[-] nmap not found. Please install nmap.", "error")
            job.mark_error("nmap not found")
            _notify(job)
            return

        from modules.utils import ScanMode, ScanType, is_root
        from modules.scanner import DiscoverHosts, PortScan, AnalyseScanResults

        # Scan mode
        scanmode = ScanMode.Normal
        if mode == "evade":
            if is_root():
                scanmode = ScanMode.Evade
                _log(job, "[*] Evasion mode enabled", "warning")
            else:
                _log(job, "[*] Root required for evasion mode, using normal", "warning")
        elif mode == "noise":
            scanmode = ScanMode.Noise
            _log(job, "[*] Noise mode enabled", "warning")

        # Scan type
        scantype = ScanType.ARP if is_root() else ScanType.Ping
        if scan_type == "arp":
            scantype = ScanType.ARP if is_root() else ScanType.Ping
        elif scan_type == "ping":
            scantype = ScanType.Ping

        # Host discovery
        if not skip_discovery:
            _log(job, f"[*] Discovering hosts on {target}")
            if job.should_stop():
                job.mark_done()
                _notify(job)
                return
            try:
                hosts_found = DiscoverHosts(target, silent, scantype, scanmode)
            except Exception as e:
                _log(job, f"[-] Host discovery failed: {e}", "error")
                hosts_found = [target] if isinstance(target, str) else list(target)

            if not hosts_found:
                _log(job, "[-] No hosts found.", "warning")
                job.mark_done()
                _notify(job)
                return

            _log(job, f"[+] {len(hosts_found)} host(s) discovered", "success")
            targets = hosts_found
        else:
            targets = [target] if isinstance(target, str) else list(target)

        # Per-host
        for host_ip in targets:
            if job.should_stop():
                _log(job, "[*] Scan stopped by user.", "warning")
                break

            _log(job, f"[*] Scanning {host_ip}")
            h = job.get_or_create_host(host_ip)

            if not scan_ports:
                job.mark_host_done(host_ip)
                continue

            try:
                nm = PortScan(host_ip, log, speed, host_timeout, scanmode, nmap_flags)
            except Exception as e:
                _log(job, f"[-] Port scan failed for {host_ip}: {e}", "error")
                job.mark_host_done(host_ip)
                continue

            # Metadata
            try:
                if host_ip in nm.all_hosts():
                    nm_host   = nm[host_ip]
                    addresses = nm_host.get("addresses", {})
                    with job._lock:
                        h["mac"]    = addresses.get("mac", "")
                        vendor_map  = nm_host.get("vendor") or {}
                        h["vendor"] = vendor_map.get(addresses.get("mac", ""), "")
                        os_matches  = nm_host.get("osmatch", [])
                        if os_matches:
                            h["os"] = os_matches[0].get("name", "")
            except Exception:
                pass

            port_array = AnalyseScanResults(nm, log, silent, host_ip)
            ports = []
            for row in port_array:
                if len(row) >= 5:
                    ports.append({
                        "port": row[1], "service": row[2],
                        "product": row[3], "version": row[4],
                    })
                    _log(job, f"    ├─ {row[1]}/tcp  {row[2]}  {row[3]} {row[4]}".rstrip())
            with job._lock:
                h["ports"] = ports

            if not ports:
                _log(job, f"[*] No open ports on {host_ip}", "warning")
                job.mark_host_done(host_ip)
                continue

            _log(job, f"[+] {host_ip} — {len(ports)} open port(s)", "success")

            if not scan_vulns or job.should_stop():
                job.mark_host_done(host_ip)
                continue

            _log(job, f"[*] Searching vulnerabilities for {host_ip}")

            from modules.searchvuln import GenerateKeywords
            from modules.nist_search import searchCVE

            keywords = GenerateKeywords(port_array)
            if not keywords:
                _log(job, f"[*] Insufficient version info for {host_ip}, skipping", "warning")
                job.mark_host_done(host_ip)
                continue

            vulns_out = []
            for kw in keywords:
                if job.should_stop():
                    break
                _log(job, f"[*] Querying NIST: {kw}")
                try:
                    cve_list = searchCVE(kw, log, api_key)
                except Exception as e:
                    _log(job, f"[-] CVE search error ({kw}): {e}", "error")
                    continue

                for cve in cve_list:
                    sev = (cve.severity or "unknown").lower()
                    vulns_out.append({
                        "cve": cve.CVEID, "description": cve.description,
                        "severity": sev, "cvss": cve.severity_score or 0,
                        "keyword": kw,
                    })
                    _log(job, f"    └─ {cve.CVEID} [{sev.upper()}] CVSS:{cve.severity_score}", "warning")

            with job._lock:
                h["vulns"] = vulns_out

            count = len(vulns_out)
            _log(job, f"[{'!' if count else '+'}] {host_ip} — {count} vulnerability(ies) found",
                 "warning" if count else "success")
            job.mark_host_done(host_ip)

        _log(job, f"[+] Scan {job.id[:8]} completed.", "success")
        job.mark_done()

    except Exception as exc:
        _log(job, f"[-] Unexpected error: {exc}", "error")
        job.mark_error(str(exc))

    finally:
        _broadcast({"scan_id": job.id, "level": "__scan_done__", "msg": "", "ts": ""})
        _notify(job)


def _launch_scan(config: dict) -> ScanJob:
    """Create, register, and start a scan job. Returns the job."""
    scan_id = str(uuid.uuid4())
    job     = ScanJob(scan_id, config["target"], config)
    _register_scan(job)
    threading.Thread(target=_run_scan, args=(job,), daemon=True).start()
    return job


# ── Scheduler ─────────────────────────────────────────────────────────────────

def _parse_interval_minutes(schedule: dict) -> Optional[int]:
    """
    Returns the interval in minutes based on schedule type.
    schedule types: 'interval', 'daily', 'weekly'
    """
    stype = schedule.get("type", "interval")
    if stype == "interval":
        unit  = schedule.get("interval_unit", "hours")
        value = int(schedule.get("interval_value", 1))
        if unit == "minutes": return value
        if unit == "hours":   return value * 60
        if unit == "days":    return value * 1440
    elif stype == "daily":
        return 1440   # checked daily; time matching done separately
    elif stype == "weekly":
        return 10080
    return None


def _should_fire(schedule: dict) -> bool:
    """Check whether a schedule should fire right now."""
    if not schedule.get("enabled", True):
        return False

    now = datetime.utcnow()
    sid = schedule["id"]

    with _schedule_last_run_lock:
        last = _schedule_last_run.get(sid)

    stype = schedule.get("type", "interval")

    if stype == "interval":
        minutes = _parse_interval_minutes(schedule)
        if minutes is None:
            return False
        if last is None:
            return True
        return (now - last).total_seconds() >= minutes * 60

    elif stype == "daily":
        # Fire once per day at the specified UTC time
        fire_time = schedule.get("time_utc", "00:00")  # "HH:MM"
        try:
            fh, fm = (int(x) for x in fire_time.split(":"))
        except Exception:
            return False
        if last is not None and last.date() == now.date():
            return False
        return now.hour == fh and now.minute == fm

    elif stype == "weekly":
        # Fire once per week on the specified weekday (0=Mon) and UTC time
        fire_day  = int(schedule.get("weekday", 0))
        fire_time = schedule.get("time_utc", "00:00")
        try:
            fh, fm = (int(x) for x in fire_time.split(":"))
        except Exception:
            return False
        if last is not None and (now - last).total_seconds() < 7 * 86400 - 3600:
            return False
        return now.weekday() == fire_day and now.hour == fh and now.minute == fm

    return False


def _scheduler_loop() -> None:
    """Background thread: checks schedules every 60 seconds."""
    while True:
        time.sleep(60)
        try:
            with _schedules_lock:
                all_schedules = list(_schedules.values())

            for schedule in all_schedules:
                if not _should_fire(schedule):
                    continue

                # Build config from schedule + linked profile (if any)
                profile_id = schedule.get("profile_id")
                config: dict = {}

                if profile_id:
                    with _profiles_lock:
                        profile = _profiles.get(profile_id, {})
                    config = dict(profile.get("config", {}))

                config["target"] = schedule.get("target", config.get("target", ""))
                if not config["target"]:
                    continue

                job = _launch_scan(config)
                _broadcast({
                    "scan_id": job.id, "level": "info",
                    "ts": datetime.utcnow().strftime("%H:%M:%S"),
                    "msg": f"[*] Scheduled scan fired: {schedule.get('name', schedule['id'][:8])} → {config['target']}",
                })

                with _schedule_last_run_lock:
                    _schedule_last_run[schedule["id"]] = datetime.utcnow()

                # Update next_run in schedule dict
                with _schedules_lock:
                    if schedule["id"] in _schedules:
                        _schedules[schedule["id"]]["last_run"] = datetime.utcnow().isoformat()
                _save_schedules()

        except Exception:
            pass


# ── Flask application ─────────────────────────────────────────────────────────

def _build_app(static_dir: Path) -> "Flask":
    app = Flask(__name__, static_folder=str(static_dir))
    CORS(app)

    # ── Static ──

    @app.route("/")
    def index():
        return send_from_directory(str(static_dir), "index.html")

    # ── Scans ──

    @app.route("/api/scans")
    def api_scans():
        return jsonify([j.to_dict() for j in _all_scans()])

    @app.route("/api/scans/<scan_id>")
    def api_scan_detail(scan_id):
        job = _get_scan(scan_id)
        if not job:
            return jsonify({"error": "Scan not found"}), 404
        return jsonify(job.to_dict())

    @app.route("/api/scan/start", methods=["POST"])
    def api_scan_start():
        body   = request.get_json(force=True, silent=True) or {}
        target = (body.get("target") or "").strip()
        if not target:
            return jsonify({"error": "'target' is required"}), 400

        config = {
            "target":         target,
            "mode":           body.get("mode", "normal"),
            "speed":          int(body.get("speed", 3)),
            "scan_type":      body.get("scan_type") or None,
            "nmap_flags":     body.get("nmap_flags", ""),
            "api_key":        body.get("api_key", ""),
            "host_timeout":   int(body.get("host_timeout", 240)),
            "scan_ports":     bool(body.get("scan_ports", True)),
            "scan_vulns":     bool(body.get("scan_vulns", True)),
            "skip_discovery": bool(body.get("skip_discovery", False)),
        }
        job = _launch_scan(config)
        return jsonify({"ok": True, "scan_id": job.id, "message": f"Scan started for {target}"})

    @app.route("/api/scan/stop", methods=["POST"])
    def api_scan_stop():
        body    = request.get_json(force=True, silent=True) or {}
        scan_id = (body.get("scan_id") or "").strip()
        job     = _get_scan(scan_id)
        if not job:
            return jsonify({"error": "Scan not found"}), 404
        if job.status not in ("running", "stopping"):
            return jsonify({"ok": False, "message": "Scan is not running"}), 400
        job.request_stop()
        return jsonify({"ok": True})

    # ── Hosts / log / events ──

    @app.route("/api/hosts")
    def api_hosts():
        all_hosts = []
        for job in _all_scans():
            all_hosts.extend(job.hosts_list())
        return jsonify(all_hosts)

    @app.route("/api/log")
    def api_log():
        with _log_history_lock:
            return jsonify(list(_log_history))

    @app.route("/api/events")
    def api_events():
        def generate():
            with _log_history_lock:
                snapshot = list(_log_history)
            for entry in snapshot:
                yield f"data: {json.dumps(entry)}\n\n"
            while True:
                try:
                    entry = _broadcast_q.get(timeout=25)
                    yield f"data: {json.dumps(entry)}\n\n"
                except queue.Empty:
                    yield ": ping\n\n"
        return Response(generate(), mimetype="text/event-stream",
                        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

    # ── Settings ──

    @app.route("/api/settings", methods=["GET"])
    def api_settings_get():
        with _settings_lock:
            # Return a copy with password masked for display
            data = json.loads(json.dumps(_settings))
        if data.get("email", {}).get("password"):
            data["email"]["password"] = "••••••••"
        return jsonify(data)

    @app.route("/api/settings", methods=["PUT"])
    def api_settings_put():
        body = request.get_json(force=True, silent=True) or {}
        with _settings_lock:
            # If the client sends back the masked password placeholder, keep the real one
            if body.get("email", {}).get("password") == "••••••••":
                body["email"]["password"] = _settings.get("email", {}).get("password", "")
            _settings.update(_deep_merge(_settings, body))
        _save_settings()
        return jsonify({"ok": True})

    @app.route("/api/settings/test_email", methods=["POST"])
    def api_test_email():
        """Send a test email using current settings."""
        cfg = _get_setting("email")
        if not cfg or not cfg.get("enabled"):
            return jsonify({"error": "Email notifications are disabled"}), 400
        try:
            msg = MIMEMultipart()
            msg["From"]    = cfg.get("from_addr") or cfg.get("username", "")
            msg["To"]      = cfg["to_addr"]
            msg["Subject"] = "[AutoPWN] Test notification"
            msg.attach(MIMEText("AutoPWN Suite email notifications are working.", "plain"))
            with smtplib.SMTP(cfg["smtp_host"], int(cfg.get("smtp_port", 587))) as srv:
                srv.ehlo(); srv.starttls()
                if cfg.get("username") and cfg.get("password"):
                    srv.login(cfg["username"], cfg["password"])
                srv.sendmail(msg["From"], [cfg["to_addr"]], msg.as_string())
            return jsonify({"ok": True})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/settings/test_webhook", methods=["POST"])
    def api_test_webhook():
        """Send a test webhook ping."""
        cfg = _get_setting("webhook")
        if not cfg or not cfg.get("enabled") or not cfg.get("url"):
            return jsonify({"error": "Webhook is disabled or URL not set"}), 400
        if not REQUESTS_AVAILABLE:
            return jsonify({"error": "requests library not installed"}), 500
        try:
            r = _requests.post(cfg["url"], json={
                "event": "test", "message": "AutoPWN Suite webhook test",
                "timestamp": datetime.utcnow().isoformat(),
            }, timeout=10)
            return jsonify({"ok": True, "status_code": r.status_code})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    # ── Profiles ──

    @app.route("/api/profiles", methods=["GET"])
    def api_profiles_get():
        with _profiles_lock:
            return jsonify(list(_profiles.values()))

    @app.route("/api/profiles", methods=["POST"])
    def api_profiles_post():
        body = request.get_json(force=True, silent=True) or {}
        name = (body.get("name") or "").strip()
        if not name:
            return jsonify({"error": "'name' is required"}), 400
        pid = str(uuid.uuid4())
        profile = {
            "id":         pid,
            "name":       name,
            "description":body.get("description", ""),
            "created_at": datetime.utcnow().isoformat(),
            "config": {
                "mode":           body.get("mode", "normal"),
                "speed":          int(body.get("speed", 3)),
                "scan_type":      body.get("scan_type") or None,
                "nmap_flags":     body.get("nmap_flags", ""),
                "host_timeout":   int(body.get("host_timeout", 240)),
                "scan_ports":     bool(body.get("scan_ports", True)),
                "scan_vulns":     bool(body.get("scan_vulns", True)),
                "skip_discovery": bool(body.get("skip_discovery", False)),
            },
        }
        with _profiles_lock:
            _profiles[pid] = profile
        _save_profiles()
        return jsonify(profile), 201

    @app.route("/api/profiles/<pid>", methods=["PUT"])
    def api_profiles_put(pid):
        with _profiles_lock:
            if pid not in _profiles:
                return jsonify({"error": "Profile not found"}), 404
        body = request.get_json(force=True, silent=True) or {}
        with _profiles_lock:
            p = _profiles[pid]
            if "name"        in body: p["name"]        = body["name"]
            if "description" in body: p["description"] = body["description"]
            if "config"      in body: p["config"]       = _deep_merge(p.get("config", {}), body["config"])
        _save_profiles()
        with _profiles_lock:
            return jsonify(_profiles[pid])

    @app.route("/api/profiles/<pid>", methods=["DELETE"])
    def api_profiles_delete(pid):
        with _profiles_lock:
            if pid not in _profiles:
                return jsonify({"error": "Profile not found"}), 404
            del _profiles[pid]
        _save_profiles()
        return jsonify({"ok": True})

    # ── Schedules ──

    @app.route("/api/schedules", methods=["GET"])
    def api_schedules_get():
        with _schedules_lock:
            return jsonify(list(_schedules.values()))

    @app.route("/api/schedules", methods=["POST"])
    def api_schedules_post():
        body = request.get_json(force=True, silent=True) or {}
        target = (body.get("target") or "").strip()
        if not target:
            return jsonify({"error": "'target' is required"}), 400
        sid = str(uuid.uuid4())
        schedule = {
            "id":             sid,
            "name":           body.get("name", f"Schedule {sid[:8]}"),
            "target":         target,
            "profile_id":     body.get("profile_id") or None,
            "enabled":        bool(body.get("enabled", True)),
            "type":           body.get("type", "interval"),       # interval | daily | weekly
            "interval_value": int(body.get("interval_value", 24)),
            "interval_unit":  body.get("interval_unit", "hours"), # minutes | hours | days
            "time_utc":       body.get("time_utc", "00:00"),      # for daily/weekly
            "weekday":        int(body.get("weekday", 0)),        # 0=Mon, for weekly
            "created_at":     datetime.utcnow().isoformat(),
            "last_run":       "",
        }
        with _schedules_lock:
            _schedules[sid] = schedule
        _save_schedules()
        return jsonify(schedule), 201

    @app.route("/api/schedules/<sid>", methods=["PUT"])
    def api_schedules_put(sid):
        with _schedules_lock:
            if sid not in _schedules:
                return jsonify({"error": "Schedule not found"}), 404
        body = request.get_json(force=True, silent=True) or {}
        updatable = ["name","target","profile_id","enabled","type",
                     "interval_value","interval_unit","time_utc","weekday"]
        with _schedules_lock:
            s = _schedules[sid]
            for k in updatable:
                if k in body:
                    s[k] = body[k]
        _save_schedules()
        with _schedules_lock:
            return jsonify(_schedules[sid])

    @app.route("/api/schedules/<sid>", methods=["DELETE"])
    def api_schedules_delete(sid):
        with _schedules_lock:
            if sid not in _schedules:
                return jsonify({"error": "Schedule not found"}), 404
            del _schedules[sid]
        _save_schedules()
        return jsonify({"ok": True})

    return app


# ── Public entry point ────────────────────────────────────────────────────────

def start_server(host: str = "0.0.0.0", port: int = 8080) -> None:
    """Start the web UI server and block until Ctrl+C."""
    if not FLASK_AVAILABLE:
        raise RuntimeError("Flask is not installed. Run:  pip install flask flask-cors")

    _STATIC_DIR.mkdir(exist_ok=True)

    if not (_STATIC_DIR / "index.html").exists():
        raise FileNotFoundError(
            f"index.html not found at: {_STATIC_DIR / 'index.html'}\n"
            "Make sure modules/web_ui_static/index.html exists."
        )

    # Load persisted data
    _load_settings()
    _load_profiles()
    _load_schedules()

    # Start scheduler background thread
    threading.Thread(target=_scheduler_loop, daemon=True).start()

    app = _build_app(_STATIC_DIR)

    import logging as _logging
    _logging.getLogger("werkzeug").setLevel(_logging.ERROR)

    display_host = "localhost" if host == "0.0.0.0" else host
    print(f"\n  AutoPWN Suite — Web UI")
    print(f"  http://{display_host}:{port}\n")

    app.run(host=host, port=port, threaded=True, use_reloader=False)