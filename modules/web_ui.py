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

import html as _html
import io
import json
import os
import queue
import shutil
import smtplib
import threading
import time
import uuid
import base64
from copy import deepcopy
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from typing import Optional
import logging

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


# ── Input validation ──────────────────────────────────────────────────────────

import re as _re

# Characters allowed in nmap targets: IPs, CIDR, hostnames, ranges
_TARGET_RE = _re.compile(r'^[a-zA-Z0-9\.\-\:\/\, ]+$')
# Allowed nmap flag patterns: dash-prefixed flags, numbers, commas, equals, colons, slashes
_NMAP_FLAG_RE = _re.compile(r'^[\sa-zA-Z0-9\.\-\_\=\,\:\/\*\?]+$')
# Shell metacharacters that must never appear in nmap arguments
_SHELL_DANGEROUS = set(';|&`$(){}[]<>!\n\r\\\'\"~')


def _validate_target(target: str) -> Optional[str]:
    """Return an error string if the target is invalid, else None."""
    if not isinstance(target, str):
        return "target must be a string"
    if not target.strip():
        return "'target' is required"
    if any(c in _SHELL_DANGEROUS for c in target):
        return "target contains invalid characters"
    if not _TARGET_RE.match(target):
        return "target contains invalid characters"
    return None


def _validate_nmap_flags(flags: str) -> Optional[str]:
    """Return an error string if nmap flags are invalid, else None."""
    if not isinstance(flags, str):
        return "nmap_flags must be a string"
    if not flags:
        return None
    if any(c in _SHELL_DANGEROUS for c in flags):
        return "nmap_flags contains invalid characters"
    if not _NMAP_FLAG_RE.match(flags):
        return "nmap_flags contains invalid characters"
    return None


# ── Paths ─────────────────────────────────────────────────────────────────────

_MODULE_DIR  = Path(__file__).parent
_STATIC_DIR  = _MODULE_DIR / "web_ui_static"
_DATA_DIR    = Path(os.environ.get("AUTOPWN_DATA_DIR", str(_MODULE_DIR)))
_DATA_DIR.mkdir(parents=True, exist_ok=True)
_SETTINGS_FILE = _DATA_DIR / "web_ui_settings.json"


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
            if not isinstance(data, dict) or any(k in data and not isinstance(data[k], dict) for k in ("email", "webhook")):
                raise ValueError("Settings must contain objects")
            # Deep merge with defaults so new keys are always present
            merged = _deep_merge(_DEFAULT_SETTINGS, data)
            with _settings_lock:
                _settings = merged
            return
        except (OSError, ValueError, TypeError):
            logging.exception("Could not load settings; preserving the existing file")
    with _settings_lock:
        _settings = _deep_merge(_DEFAULT_SETTINGS, {})
    if not _SETTINGS_FILE.exists():
        _save_settings()


def _write_json(path: Path, data: dict) -> None:
    """Replace a complete JSON document; an interrupted save keeps the old one."""
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        with temporary.open("x", encoding="utf-8") as output:
            json.dump(data, output, indent=2)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _save_settings() -> None:
    with _settings_lock:
        _write_json(_SETTINGS_FILE, _settings)


def _deep_merge(base: dict, override: dict) -> dict:
    result = deepcopy(base)
    for k, v in override.items():
        if k in result and isinstance(result[k], dict) and isinstance(v, dict):
            result[k] = _deep_merge(result[k], v)
        else:
            result[k] = deepcopy(v)
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

_PROFILES_FILE = _DATA_DIR / "web_ui_profiles.json"
_profiles: dict = {}   # id -> profile dict
_profiles_lock  = threading.Lock()


def _load_profiles() -> None:
    global _profiles
    if _PROFILES_FILE.exists():
        try:
            data = json.loads(_PROFILES_FILE.read_text(encoding="utf-8"))
            if not isinstance(data, dict) or any(not isinstance(p, dict) for p in data.values()):
                raise ValueError("Profiles must be an object of profile objects")
            with _profiles_lock:
                _profiles = data
            return
        except Exception:
            pass
    with _profiles_lock:
        _profiles = {}


def _save_profiles() -> None:
    with _profiles_lock:
        _write_json(_PROFILES_FILE, _profiles)


# ── Schedules persistence ─────────────────────────────────────────────────────

_SCHEDULES_FILE = _DATA_DIR / "web_ui_schedules.json"
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
            if not isinstance(data, dict):
                raise ValueError("Schedules must be an object")
            data = {sid: sched for sid, sched in data.items()
                    if isinstance(sid, str) and isinstance(sched, dict)}
            with _schedules_lock:
                _schedules = data
            # Restore last_run times so schedules don't fire immediately on restart
            with _schedule_last_run_lock:
                _schedule_last_run.clear()
                for sid, sched in data.items():
                    lr = sched.get("last_run")
                    if isinstance(lr, str) and lr:
                        try:
                            restored = datetime.fromisoformat(lr.replace("Z", "+00:00"))
                            if restored.tzinfo is None:
                                restored = restored.replace(tzinfo=timezone.utc)
                            _schedule_last_run[sid] = restored.astimezone(timezone.utc)
                        except (ValueError, TypeError):
                            pass
            return
        except Exception:
            pass
    with _schedules_lock:
        _schedules = {}
    with _schedule_last_run_lock:
        _schedule_last_run.clear()


def _save_schedules() -> None:
    with _schedules_lock:
        _write_json(_SCHEDULES_FILE, _schedules)


# ── Per-scan job ──────────────────────────────────────────────────────────────

class ScanJob:
    def __init__(self, scan_id: str, target: str, config: dict):
        self.id          = scan_id
        self.target      = target
        self.config      = config
        self.status      = "running"
        self.started_at  = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        self.finished_at = ""
        self.error       = ""
        self._lock       = threading.RLock()
        self._stop_flag  = threading.Event()
        self._hosts: dict[str, dict] = {}

    def should_stop(self) -> bool:
        return self._stop_flag.is_set()

    def request_stop(self) -> None:
        self._stop_flag.set()
        with self._lock:
            if self.status == "running":
                self.status = "stopping"

    def mark_done(self, status: str = "completed") -> None:
        with self._lock:
            self.status      = status
            self.finished_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    def mark_error(self, msg: str) -> None:
        with self._lock:
            self.status      = "error"
            self.error       = msg
            self.finished_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

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

    def mark_host_done(self, ip: str, status: str = "completed") -> None:
        with self._lock:
            if ip in self._hosts:
                self._hosts[ip]["scan_status"] = status

    def hosts_list(self) -> list:
        with self._lock:
            return deepcopy(list(self._hosts.values()))

    def to_dict(self) -> dict:
        with self._lock:
            hosts = deepcopy(list(self._hosts.values()))
            status = self.status
            finished_at = self.finished_at
            error = self.error
        return {
            "id":          self.id,
            "target":      self.target,
            "config":      {k: deepcopy(v) for k, v in self.config.items() if k != "api_key"},
            "status":      status,
            "started_at":  self.started_at,
            "finished_at": finished_at,
            "error":       error,
            "host_count":  len(hosts),
            "port_count":  sum(len(h["ports"]) for h in hosts),
            "vuln_count":  sum(len(h["vulns"])  for h in hosts),
        }

    def to_full_dict(self) -> dict:
        with self._lock:
            hosts = deepcopy(list(self._hosts.values()))
            base_dict = self.to_dict()
        
        structured_hosts = []
        for h in hosts:
            sh = {
                "ip": h.get("ip", ""),
                "mac": h.get("mac", ""),
                "vendor": h.get("vendor", ""),
                "os": h.get("os", ""),
                "ports": [],
                "scan_status": h.get("scan_status", ""),
                "lookup_status": h.get("lookup_status", "not_run"),
            }
            mapped_vulns = []
            for p in h.get("ports", []):
                port_num = p.get("port")
                port_vulns = []
                for v in h.get("vulns", []):
                    if v.get("port") == port_num and v.get("protocol", "tcp") == p.get("protocol", "tcp"):
                        port_vulns.append(v)
                        if v not in mapped_vulns:
                            mapped_vulns.append(v)
                sh["ports"].append({
                    "port": p.get("port"),
                    "service": p.get("service"),
                    "product": p.get("product"),
                    "version": p.get("version"),
                    "protocol": p.get("protocol", "tcp"),
                    "vulnerabilities": port_vulns
                })
            
            unmapped = [v for v in h.get("vulns", []) if v not in mapped_vulns]
            if unmapped:
                sh["unmapped_vulnerabilities"] = unmapped
            structured_hosts.append(sh)
            
        base_dict["hosts"] = structured_hosts
        return base_dict

# ── Global scan registry + SSE ────────────────────────────────────────────────

_scans: dict[str, ScanJob] = {}
_scans_lock   = threading.Lock()
_sse_subscribers: list = []
_sse_subscribers_lock = threading.Lock()
_log_history: list = []
_log_history_lock = threading.Lock()
_MAX_LOG_HISTORY = 5000
_MAX_COMPLETED_SCANS = 100


def _broadcast(event: dict) -> None:
    with _log_history_lock:
        _log_history.append(event)
        if len(_log_history) > _MAX_LOG_HISTORY:
            del _log_history[:len(_log_history) - _MAX_LOG_HISTORY]
        with _sse_subscribers_lock:
            for q in _sse_subscribers:
                try:
                    q.put_nowait(event)
                except queue.Full:
                    # A slow dashboard must not block scans or grow memory forever.
                    try:
                        q.get_nowait()
                    except queue.Empty:
                        pass
                    q.put_nowait(event)


def _register_scan(job: ScanJob) -> None:
    with _scans_lock:
        _scans[job.id] = job
        # Prune oldest completed/error scans if over limit
        done = [(k, v) for k, v in _scans.items()
                if v.status in ("completed", "error", "partial", "stopped")]
        if len(done) > _MAX_COMPLETED_SCANS:
            done.sort(key=lambda x: x[1].finished_at)
            for k, _ in done[:len(done) - _MAX_COMPLETED_SCANS]:
                del _scans[k]


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
            "ts":      datetime.now(timezone.utc).strftime("%H:%M:%S"),
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

    # Send if ANY matching condition is enabled
    should_send = False
    if job.status == "completed" and cfg.get("on_complete"):
        should_send = True
    if job.status in ("error", "partial") and cfg.get("on_error"):
        should_send = True
    if vuln_count and cfg.get("on_vuln_found"):
        should_send = True
    if not should_send:
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
        "timestamp":  datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    try:
        response = _requests.post(cfg["url"], json=payload, timeout=10)
        response.raise_for_status()
    except Exception as e:
        _broadcast({
            "scan_id": job.id, "level": "warning",
            "ts": datetime.now(timezone.utc).strftime("%H:%M:%S"),
            "msg": f"[*] Webhook delivery failed: {e}",
        })


@contextmanager
def _smtp_connection(cfg):
    port = int(cfg.get("smtp_port", 587))
    factory = smtplib.SMTP_SSL if port == 465 else smtplib.SMTP
    with factory(cfg["smtp_host"], port, timeout=30) as srv:
        srv.ehlo()
        if port != 465:
            srv.starttls()
            srv.ehlo()
        if cfg.get("username") and cfg.get("password"):
            srv.login(cfg["username"], cfg["password"])
        yield srv


def _send_email(job: ScanJob) -> None:
    cfg = _get_setting("email")
    if not cfg or not cfg.get("enabled"):
        return
    if not cfg.get("smtp_host") or not cfg.get("to_addr"):
        return

    hosts     = job.hosts_list()
    vuln_count = sum(len(h["vulns"]) for h in hosts)

    # Send if ANY matching condition is enabled
    should_send = False
    if job.status == "completed" and cfg.get("on_complete"):
        should_send = True
    if job.status in ("error", "partial") and cfg.get("on_error"):
        should_send = True
    if vuln_count and cfg.get("on_vuln_found"):
        should_send = True
    if not should_send:
        return

    _e = _html.escape
    subject = f"[AutoPWN] Scan {job.status.upper()} — {job.target}"

    c = job.config or {}
    cmd_base = f"nmap {job.target} -sS -sV -O -Pn -T 2 -f -g 53 --data-length 10" if c.get("mode") == "evade" else f"nmap {job.target} -sS -sV --host-timeout {c.get('host_timeout', 240)} -Pn -O -T {c.get('speed', 3)}"
    flags = c.get("nmap_flags", "")
    if flags:
        if "-O" in cmd_base and "-O" in flags:
            flags = flags.replace("-O", "").strip()
        if flags:
            cmd_base += " " + flags

    favicon_path = _STATIC_DIR / "favicon.ico"
    _icon_data = None
    logo_html = ""
    if favicon_path.exists():
        try:
            _icon_data = favicon_path.read_bytes()
            logo_html = '<img src="cid:autopwn_icon" style="width: 40px; height: 40px; display: block;" alt="Logo">'
        except Exception:
            pass

    html = f"""<!DOCTYPE html><html><head><title>Scan Report - {_e(job.target)}</title>
    <style>
      body{{font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; padding: 20px; color: #333; line-height: 1.5;}}
      h1, h2, h3, h4{{color: #111; margin-bottom: 8px;}}
      table{{width: 100%; border-collapse: collapse; margin-bottom: 20px; font-size: 13px;}}
      th, td{{border: 1px solid #ddd; padding: 10px; text-align: left;}}
      th{{background-color: #f5f5f5;}}
      .meta{{background: #f9f9f9; padding: 15px; border-radius: 6px; margin-bottom: 20px; border: 1px solid #eee;}}
      .meta p{{margin: 5px 0;}}
      .sev-critical{{color: #d32f2f; font-weight: bold;}}
      .sev-high{{color: #f57c00; font-weight: bold;}}
      .sev-medium{{color: #fbc02d; font-weight: bold;}}
      .sev-low{{color: #388e3c; font-weight: bold;}}
      .sev-unknown{{color: #777;}}
    </style>
    </head><body>
    <table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom: 20px; border-bottom: 2px solid #eee; padding-bottom: 10px;">
      <tr>
        <td width="50" valign="middle">
          {logo_html}
        </td>
        <td valign="middle">
          <h1 style="margin: 0; color: #111; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;">AutoPWN Suite <span style="color: #777; font-weight: normal;">— Scan Report</span></h1>
        </td>
      </tr>
    </table>
    <div class="meta">
      <p><strong>Target:</strong> {_e(job.target)}</p>
      <p><strong>Scan ID:</strong> {_e(job.id)}</p>
      <p><strong>Status:</strong> {_e(job.status)}</p>
      <p><strong>Command:</strong> {_e(cmd_base.strip())}</p>
      <p><strong>Started:</strong> {_e(job.started_at)}</p>
      <p><strong>Finished:</strong> {_e(job.finished_at or 'N/A')}</p>
    </div>
    """
    if job.error:
        html += f'<div class="meta" style="border-color:#ff3f4f;"><p style="color:#ff3f4f;"><strong>Error:</strong> {_e(job.error)}</p></div>'

    html += f"<h2>Hosts Discovered ({len(hosts)})</h2>\n"

    if hosts:
        for h in hosts:
            html += f"<h3>Host: {_e(h.get('ip', ''))}</h3>\n"
            html += f'<div class="meta"><p><strong>MAC:</strong> {_e(h.get("mac") or "—")} &nbsp;|&nbsp; <strong>OS:</strong> {_e(h.get("os") or "—")} &nbsp;|&nbsp; <strong>Vendor:</strong> {_e(h.get("vendor") or "—")}</p></div>\n'
            if h.get("ports"):
                html += "<h4>Open Ports</h4><table><tr><th>Port</th><th>Service</th><th>Product</th><th>Version</th></tr>\n"
                for p in h.get("ports", []):
                    html += f"<tr><td>{_e(str(p.get('port','')))}</td><td>{_e(p.get('service',''))}</td><td>{_e(p.get('product',''))}</td><td>{_e(p.get('version',''))}</td></tr>\n"
                html += "</table>\n"
            else:
                html += "<p>No open ports found.</p>\n"

            vulns = h.get("vulns", [])
            if vulns:
                html += "<h4>Vulnerabilities</h4><table><tr><th>CVE</th><th>Severity</th><th>CVSS</th><th>Description</th></tr>\n"
                for v in vulns:
                    sev = _e(v.get("severity", "unknown").lower())
                    html += f"<tr><td>{_e(v.get('cve',''))}</td><td class=\"sev-{sev}\">{_e(v.get('severity', '').upper())}</td><td>{_e(str(v.get('cvss', '—')))}</td><td>{_e(v.get('description',''))}</td></tr>\n"
                html += "</table>\n"
            html += '<hr style="border:0; border-top:2px dashed #eee; margin:30px 0;">\n'
    else:
        html += "<p>No hosts were found during this scan.</p>\n"

    html += "</body></html>"

    try:
        from email.mime.image import MIMEImage
        msg = MIMEMultipart("related")
        msg["From"]    = cfg.get("from_addr") or cfg.get("username", "")
        msg["To"]      = cfg["to_addr"]
        msg["Subject"] = subject
        msg.attach(MIMEText(html, "html"))
        if _icon_data:
            icon_part = MIMEImage(_icon_data, _subtype="x-icon")
            icon_part.add_header("Content-ID", "<autopwn_icon>")
            icon_part.add_header("Content-Disposition", "inline", filename="favicon.ico")
            msg.attach(icon_part)

        with _smtp_connection(cfg) as srv:
            srv.sendmail(msg["From"], [cfg["to_addr"]], msg.as_string())
    except Exception as e:
        _broadcast({
            "scan_id": job.id, "level": "warning",
            "ts": datetime.now(timezone.utc).strftime("%H:%M:%S"),
            "msg": f"[*] Email notification failed: {e}",
        })


def _notify(job: ScanJob) -> None:
    threading.Thread(target=_send_webhook, args=(job,), daemon=True).start()
    threading.Thread(target=_send_email,   args=(job,), daemon=True).start()


# ── Scan engine ───────────────────────────────────────────────────────────────

def _log(job: ScanJob, msg: str, level: str = "info") -> None:
    _broadcast({
        "scan_id": job.id,
        "ts":      datetime.now(timezone.utc).strftime("%H:%M:%S"),
        "level":   level,
        "msg":     msg,
    })


def _build_nmap_flags(config: dict) -> str:
    """Build the full nmap_flags string from both the free-text field and
    the structured profile fields (scan_technique, ports, version_intensity,
    os_detection).  This ensures scheduled scans from profiles work correctly."""
    parts = []
    if config.get("scan_technique"):
        parts.append(config["scan_technique"])
    if config.get("ports"):
        parts.append(f"-p {config['ports']}")
    vi = config.get("version_intensity")
    if vi is not None and vi != "":
        parts.append(f"--version-intensity {vi}")
    if config.get("os_detection"):
        parts.append("-O")
    if config.get("nmap_flags"):
        parts.append(config["nmap_flags"])
    return " ".join(parts)


def _run_scan(job: ScanJob) -> None:
    log  = WebLogger(job.id)
    had_failures = False

    try:
        config = job.config
        target = config["target"]
        mode = config.get("mode", "normal")
        speed = int(config.get("speed", 3))
        scan_type = config.get("scan_type") or None
        nmap_flags = config.get("nmap_flags", "")
        api_key = config.get("api_key") or _get_setting("nist_api_key") or None
        host_timeout = int(config.get("host_timeout", 240))
        scan_ports = config.get("scan_ports", True)
        scan_vulns = config.get("scan_vulns", True)
        skip_discovery = config.get("skip_discovery", False)
        from rich.console import Console
        silent = Console(file=io.StringIO(), color_system=None)

        _log(job, f"[*] Starting scan on {target}")

        if not shutil.which("nmap"):
            _log(job, "[-] nmap not found. Please install nmap.", "error")
            job.mark_error("nmap not found")
            return

        from modules.utils import ScanMode, ScanType, is_root
        from modules.scanner import DiscoverHosts, PortScan, AnalyseScanResults, ResolveScanHosts

        # Scan mode
        scanmode = ScanMode.Normal
        if mode == "evade":
            if is_root():
                scanmode = ScanMode.Evade
                _log(job, "[*] Evasion mode enabled", "warning")
            else:
                _log(job, "[*] Root required for evasion mode, using normal", "warning")
        elif mode == "noise":
            # NoiseScan requires a dedicated long-running process and is not
            # supported from the web UI.  Fall back to normal mode.
            _log(job, "[*] Noise mode is not supported in web UI, using normal mode", "warning")

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
                job.mark_done("stopped")
                return
            try:
                hosts_found = DiscoverHosts(target, silent, scantype, scanmode)
            except Exception as e:
                _log(job, f"[-] Host discovery failed: {e}", "error")
                had_failures = True
                hosts_found = [target] if isinstance(target, str) else list(target)

            if not hosts_found:
                _log(job, "[-] No hosts found.", "warning")
                job.mark_done()
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
            if not scan_ports:
                job.get_or_create_host(host_ip)
                job.mark_host_done(host_ip)
                continue

            try:
                nm = PortScan(host_ip, log, speed, host_timeout, scanmode, nmap_flags)
            except SystemExit as e:
                _log(job, f"[-] Port scan failed for {host_ip}: {e}", "error")
                had_failures = True
                job.get_or_create_host(host_ip)
                job.mark_host_done(host_ip, "error")
                continue
            except Exception as e:
                _log(job, f"[-] Port scan failed for {host_ip}: {e}", "error")
                had_failures = True
                job.get_or_create_host(host_ip)
                job.mark_host_done(host_ip, "error")
                continue
            # Nmap returns IP keys even when the request is a hostname or range.
            resolved = ResolveScanHosts(nm, host_ip)
            if not resolved:
                had_failures = True
                job.get_or_create_host(host_ip)
                job.mark_host_done(host_ip, "not_observed")
                _log(job, f"[-] No scan observation returned for {host_ip}", "warning")
                continue
            for observed_ip in resolved:
                if job.should_stop():
                    break
                if _collect_host_results(job, nm, observed_ip, log, silent, scan_vulns, api_key):
                    had_failures = True

        outcome = "stopped" if job.should_stop() else "partial" if had_failures else "completed"
        _log(job, f"[+] Scan {job.id[:8]} {outcome}.", "success" if outcome == "completed" else "warning")
        job.mark_done(outcome)

    except SystemExit as exc:
        _log(job, f"[-] Scan aborted: {exc}", "error")
        job.mark_error(str(exc))
    except Exception as exc:
        _log(job, f"[-] Unexpected error: {exc}", "error")
        job.mark_error(str(exc))

    finally:
        _broadcast({"scan_id": job.id, "level": "__scan_done__", "msg": "", "ts": ""})
        _notify(job)


def _collect_host_results(job, nm, ip, log, silent, scan_vulns, api_key) -> bool:
    """Record one actual host. Return whether its vulnerability lookup failed."""
    from modules.scanner import AnalyseScanResults
    from modules.searchvuln import GenerateKeyword
    from modules.nist_search import searchCVE

    h = job.get_or_create_host(ip)
    nm_host = nm[ip]
    addresses = nm_host.get("addresses", {})
    os_matches = nm_host.get("osmatch", [])
    rows = AnalyseScanResults(nm, log, silent, ip)
    ports = [{"port": row[1], "service": row[2], "product": row[3],
              "version": row[4], "protocol": row[5] if len(row) > 5 else "tcp"}
             for row in rows if len(row) >= 5]
    with job._lock:
        h["mac"] = addresses.get("mac", "")
        h["vendor"] = (nm_host.get("vendor") or {}).get(h["mac"], "")
        h["os"] = os_matches[0].get("name", "") if os_matches else ""
        h["ports"] = ports
        h["lookup_status"] = "not_run" if scan_vulns else "skipped"
        h["observed_at"] = datetime.now(timezone.utc).isoformat()
    for port in ports:
        _log(job, f"    ├─ {port['port']}/{port['protocol']}  {port['service']}  {port['product']} {port['version']}".rstrip())
    if not scan_vulns or not ports or job.should_stop():
        job.mark_host_done(ip, "stopped" if job.should_stop() else "completed")
        return False

    findings = []
    failed = False
    for port in ports:
        if job.should_stop():
            break
        keyword = GenerateKeyword(str(port["product"]), str(port["version"]))
        if not keyword:
            continue
        _log(job, f"[*] Querying NIST for {port['port']}/{port['protocol']}: {keyword}")
        try:
            cves = searchCVE(keyword, log, api_key, strict=True)
        except Exception as exc:
            failed = True
            _log(job, f"[-] CVE search error ({keyword}): {exc}", "error")
            continue
        for cve in cves:
            severity = (cve.severity or "unknown").lower()
            findings.append({"cve": cve.CVEID, "description": cve.description,
                             "severity": severity, "cvss": cve.severity_score or 0,
                             "keyword": keyword, "port": port["port"], "protocol": port["protocol"]})
            _log(job, f"    └─ {cve.CVEID} [{severity.upper()}] CVSS:{cve.severity_score}", "warning")
    with job._lock:
        h["vulns"] = findings
        h["lookup_status"] = "partial" if failed or job.should_stop() else "completed"
    job.mark_host_done(ip, "stopped" if job.should_stop() else "completed")
    return failed


def _launch_scan(config: dict) -> ScanJob:
    """Create, register, and start a scan job. Returns the job."""
    scan_id = str(uuid.uuid4())
    job     = ScanJob(scan_id, config["target"], config)
    _register_scan(job)
    threading.Thread(target=_run_scan, args=(job,), daemon=True).start()
    return job


# ── Scheduler ─────────────────────────────────────────────────────────────────

def _integer_option(value, field, minimum, maximum=None):
    """Accept JSON integers or integer form values without silently truncating."""
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise ValueError(f"'{field}' must be an integer")
    if isinstance(value, str) and not _re.fullmatch(r"[+-]?\d+", value.strip()):
        raise ValueError(f"'{field}' must be an integer")
    number = int(value)
    if number < minimum or (maximum is not None and number > maximum):
        bounds = f"{minimum}-{maximum}" if maximum is not None else f"at least {minimum}"
        raise ValueError(f"'{field}' must be {bounds}")
    return number


def _profile_config(body, existing=None):
    """Apply the same profile rules when creating, editing, or scheduling."""
    defaults = {"mode": "normal", "speed": 3, "scan_type": None,
                "scan_technique": "", "ports": "", "version_intensity": None,
                "os_detection": False, "nmap_flags": "", "host_timeout": 240,
                "scan_ports": True, "scan_vulns": True, "skip_discovery": False}
    if not isinstance(body, dict) or (existing is not None and not isinstance(existing, dict)):
        raise ValueError("Profile configuration must be an object")
    config = dict(defaults)
    for source in (existing or {}, body):
        config.update({key: source[key] for key in defaults if key in source})
    if config["mode"] not in ("normal", "evade", "noise"):
        raise ValueError("'mode' must be 'normal', 'evade', or 'noise'")
    config["speed"] = _integer_option(config["speed"], "speed", 0, 5)
    config["host_timeout"] = _integer_option(config["host_timeout"], "host_timeout", 1)
    if config["scan_type"] is not None and not isinstance(config["scan_type"], str):
        raise ValueError("'scan_type' must be 'arp', 'ping', or null")
    config["scan_type"] = config["scan_type"] or None
    if config["scan_type"] not in (None, "arp", "ping"):
        raise ValueError("'scan_type' must be 'arp', 'ping', or null")
    for key in ("scan_ports", "scan_vulns", "skip_discovery", "os_detection"):
        if not isinstance(config[key], bool):
            raise ValueError(f"'{key}' must be a boolean")
    for key in ("scan_technique", "ports", "nmap_flags"):
        if not isinstance(config[key], str):
            raise ValueError(f"'{key}' must be a string")
    intensity = config["version_intensity"]
    config["version_intensity"] = None if intensity is None or intensity == "" else _integer_option(intensity, "version_intensity", 0, 9)
    flags_error = _validate_nmap_flags(_build_nmap_flags(config))
    if flags_error:
        raise ValueError(flags_error)
    return config


def _schedule_data(body, existing=None):
    """Validate the full merged record before changing a saved schedule."""
    if not isinstance(body, dict):
        raise ValueError("Schedule must be an object")
    fields = ("name", "target", "profile_id", "enabled", "type", "interval_value",
              "interval_unit", "time_utc", "weekday")
    result = {"name": "", "target": "", "profile_id": None, "enabled": True,
              "type": "interval", "interval_value": 24, "interval_unit": "hours",
              "time_utc": "00:00", "weekday": 0, **(existing or {})}
    result.update({key: body[key] for key in fields if key in body})
    if not isinstance(result["name"], str):
        raise ValueError("'name' must be a string")
    if not isinstance(result["target"], str):
        raise ValueError("'target' must be a string")
    result["target"] = result["target"].strip()
    target_error = _validate_target(result["target"])
    if target_error:
        raise ValueError(target_error)
    if not isinstance(result["profile_id"], str) or not result["profile_id"]:
        raise ValueError("A profile is required for scheduled scans")
    if not isinstance(result["enabled"], bool):
        raise ValueError("'enabled' must be a boolean")
    if result["type"] not in ("interval", "daily", "weekly"):
        raise ValueError("'type' must be 'interval', 'daily', or 'weekly'")
    if result["interval_unit"] not in ("minutes", "hours", "days"):
        raise ValueError("'interval_unit' must be 'minutes', 'hours', or 'days'")
    result["interval_value"] = _integer_option(result["interval_value"], "interval_value", 1)
    result["weekday"] = _integer_option(result["weekday"], "weekday", 0, 6)
    if not isinstance(result["time_utc"], str) or not _re.fullmatch(r"(?:[01]\d|2[0-3]):[0-5]\d", result["time_utc"]):
        raise ValueError("'time_utc' must be a valid HH:MM UTC time")
    return result


def _parse_interval_minutes(schedule: dict) -> Optional[int]:
    """
    Returns the interval in minutes based on schedule type.
    schedule types: 'interval', 'daily', 'weekly'
    """
    if not isinstance(schedule, dict):
        return None
    stype = schedule.get("type", "interval")
    if stype == "interval":
        unit  = schedule.get("interval_unit", "hours")
        try:
            value = _integer_option(schedule.get("interval_value", 1), "interval_value", 1)
        except ValueError:
            return None
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
    if not isinstance(schedule, dict) or schedule.get("enabled", True) is not True:
        return False

    now = datetime.now(timezone.utc)
    sid = schedule.get("id")
    if not isinstance(sid, str) or not sid:
        return False

    with _schedule_last_run_lock:
        last = _schedule_last_run.get(sid)
    if last is not None:
        if not isinstance(last, datetime):
            return False
        if last.tzinfo is None:
            last = last.replace(tzinfo=timezone.utc)

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
        try:
            fire_day = _integer_option(schedule.get("weekday", 0), "weekday", 0, 6)
        except ValueError:
            return False
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
                all_schedules = [dict(value) if isinstance(value, dict) else value
                                 for value in _schedules.values()]
        except Exception:
            logging.exception("Could not read scheduled scans")
            continue

        for schedule in all_schedules:
            try:
                if not _should_fire(schedule):
                    continue
                checked = _schedule_data(schedule)
                # Keep the profile and schedule stable until launch. Deleting,
                # disabling, or editing either cannot start the stale snapshot.
                with _profiles_lock:
                    profile = _profiles.get(checked["profile_id"])
                    if not isinstance(profile, dict):
                        raise ValueError("Linked profile no longer exists")
                    config = _profile_config({}, profile.get("config", {}))
                    config["target"] = checked["target"]
                    config["nmap_flags"] = _build_nmap_flags(config)
                    with _schedules_lock:
                        if _schedules.get(schedule["id"]) != schedule:
                            continue
                        job = _launch_scan(config)
                        now = datetime.now(timezone.utc)
                        with _schedule_last_run_lock:
                            _schedule_last_run[schedule["id"]] = now
                        _schedules[schedule["id"]]["last_run"] = now.strftime("%Y-%m-%dT%H:%M:%SZ")

                _broadcast({
                    "scan_id": job.id, "level": "info",
                    "ts": datetime.now(timezone.utc).strftime("%H:%M:%S"),
                    "msg": f"[*] Scheduled scan fired: {schedule.get('name', schedule['id'][:8])} → {config['target']}",
                })
                _save_schedules()
            except Exception as exc:
                logging.exception("Scheduled scan failed")
                label = schedule.get("name") or schedule.get("id", "unknown") if isinstance(schedule, dict) else "unknown"
                _broadcast({
                    "scan_id": "", "level": "error",
                    "ts": datetime.now(timezone.utc).strftime("%H:%M:%S"),
                    "msg": f"[!] Scheduled scan skipped ({label}): {exc}",
                })


# ── Flask application ─────────────────────────────────────────────────────────

def _build_app(static_dir: Path) -> "Flask":
    app = Flask(__name__, static_folder=str(static_dir), static_url_path="")
    CORS(app)

    @app.before_request
    def require_json_object():
        if request.method in ("POST", "PUT"):
            body = request.get_json(silent=True)
            if body is not None and not isinstance(body, dict):
                return jsonify({"error": "JSON body must be an object"}), 400

    # ── Static ──

    @app.route("/")
    def index():
        return send_from_directory(str(static_dir), "index.html")

    @app.route("/favicon.ico")
    def favicon():
        return send_from_directory(str(static_dir), "favicon.ico", mimetype="image/vnd.microsoft.icon")

    @app.route("/api/version")
    def api_version():
        return jsonify({"version": __version__})

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

    @app.route("/api/scans/<scan_id>/download")
    def api_scan_download(scan_id):
        job = _get_scan(scan_id)
        if not job:
            return jsonify({"error": "Scan not found"}), 404
        return Response(
            json.dumps(job.to_full_dict(), indent=2),
            mimetype="application/json",
            headers={"Content-Disposition": f"attachment; filename=autopwn_scan_{scan_id[:8]}.json"}
        )

    @app.route("/api/scan/start", methods=["POST"])
    def api_scan_start():
        body   = request.get_json(force=True, silent=True) or {}
        target = body.get("target", "")

        target_err = _validate_target(target)
        if target_err:
            return jsonify({"error": target_err}), 400
        target = target.strip()

        try:
            config = _profile_config(body)
        except ValueError:
            return jsonify({"error": "Invalid scan configuration"}), 400
        api_key = body.get("api_key", "")
        if api_key is not None and not isinstance(api_key, str):
            return jsonify({"error": "api_key must be a string"}), 400
        config.update(target=target, api_key=api_key,
                      nmap_flags=_build_nmap_flags(config))
        job = _launch_scan(config)
        return jsonify({"ok": True, "scan_id": job.id, "message": f"Scan started for {target}"})

    @app.route("/api/scan/stop", methods=["POST"])
    def api_scan_stop():
        body    = request.get_json(force=True, silent=True) or {}
        scan_id = body.get("scan_id", "")
        if not isinstance(scan_id, str):
            return jsonify({"error": "scan_id must be a string"}), 400
        scan_id = scan_id.strip()
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
        observations = {}
        attempts = {}
        for job in _all_scans():
            for host in job.hosts_list():
                actual = bool(host.get("observed_at")) or bool(host.get("ports"))
                timestamp = host.get("observed_at") or job.finished_at or job.started_at
                when = datetime.fromisoformat(timestamp.replace("Z", "+00:00")).timestamp()
                previous = attempts.get(host["ip"])
                if previous is None or when >= previous[0]:
                    attempts[host["ip"]] = (when, host)
                if actual:
                    previous = observations.get(host["ip"])
                    if previous is None or when >= previous[0]:
                        observations[host["ip"]] = (when, host)
        latest = []
        for ip, attempt in attempts.items():
            observed = observations.get(ip)
            host = observed[1] if observed else attempt[1]
            if observed and attempt[0] >= observed[0] and attempt[1]["scan_id"] != host["scan_id"]:
                host["latest_attempt"] = {key: attempt[1].get(key) for key in ("scan_id", "scan_status", "lookup_status")}
            latest.append(host)
        return jsonify(latest)

    @app.route("/api/log")
    def api_log():
        with _log_history_lock:
            return jsonify(list(_log_history))

    @app.route("/api/events")
    def api_events():
        client_q = queue.Queue(maxsize=_MAX_LOG_HISTORY)
        with _log_history_lock:
            snapshot = list(_log_history)
            with _sse_subscribers_lock:
                _sse_subscribers.append(client_q)
        def generate():
            try:
                for entry in snapshot:
                    yield f"data: {json.dumps(entry)}\n\n"
                while True:
                    try:
                        entry = client_q.get(timeout=25)
                        yield f"data: {json.dumps(entry)}\n\n"
                    except queue.Empty:
                        yield ": ping\n\n"
            finally:
                with _sse_subscribers_lock:
                    _sse_subscribers.remove(client_q)
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
        if any(k in body and not isinstance(body[k], dict) for k in ("email", "webhook")):
            return jsonify({"error": "email and webhook must be objects"}), 400
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
            with _smtp_connection(cfg) as srv:
                srv.sendmail(msg["From"], [cfg["to_addr"]], msg.as_string())
            return jsonify({"ok": True})
        except Exception:
            logging.exception("Failed to send test email")
            return jsonify({"error": "Failed to send test email"}), 500

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
                "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            }, timeout=10)
            r.raise_for_status()
            return jsonify({"ok": True, "status_code": r.status_code})
        except Exception:
            logging.exception("Failed to send test webhook")
            return jsonify({"error": "Failed to send test webhook"}), 500

    # ── Profiles ──

    @app.route("/api/profiles", methods=["GET"])
    def api_profiles_get():
        with _profiles_lock:
            return jsonify(list(_profiles.values()))

    @app.route("/api/profiles", methods=["POST"])
    def api_profiles_post():
        body = request.get_json(force=True, silent=True)
        if not isinstance(body, dict):
            return jsonify({"error": "Profile must be an object"}), 400
        name = body.get("name", "")
        if not isinstance(name, str) or not name.strip():
            return jsonify({"error": "'name' is required"}), 400
        description = body.get("description", "")
        if not isinstance(description, str):
            return jsonify({"error": "'description' must be a string"}), 400
        try:
            config = _profile_config(body)
        except ValueError:
            return jsonify({"error": "Invalid scan configuration"}), 400
        pid = str(uuid.uuid4())
        profile = {
            "id":         pid,
            "name":       name.strip(),
            "description":description,
            "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "config": config,
        }
        with _profiles_lock:
            _profiles[pid] = profile
        _save_profiles()
        return jsonify(profile), 201

    @app.route("/api/profiles/<pid>", methods=["PUT"])
    def api_profiles_put(pid):
        body = request.get_json(force=True, silent=True)
        with _profiles_lock:
            if pid not in _profiles:
                return jsonify({"error": "Profile not found"}), 404
            if not isinstance(body, dict):
                return jsonify({"error": "Profile must be an object"}), 400
            p = dict(_profiles[pid])
            if "name" in body:
                if not isinstance(body["name"], str) or not body["name"].strip():
                    return jsonify({"error": "'name' is required"}), 400
                p["name"] = body["name"].strip()
            if "description" in body:
                if not isinstance(body["description"], str):
                    return jsonify({"error": "'description' must be a string"}), 400
                p["description"] = body["description"]
            try:
                p["config"] = _profile_config(body, p.get("config", {}))
            except ValueError:
                return jsonify({"error": "Invalid scan configuration"}), 400
            _profiles[pid] = p
        _save_profiles()
        return jsonify(p)

    @app.route("/api/profiles/<pid>", methods=["DELETE"])
    def api_profiles_delete(pid):
        disabled = False
        with _profiles_lock:
            if pid not in _profiles:
                return jsonify({"error": "Profile not found"}), 404
            del _profiles[pid]
            with _schedules_lock:
                for schedule in _schedules.values():
                    if isinstance(schedule, dict) and schedule.get("profile_id") == pid:
                        schedule["enabled"] = False
                        disabled = True
        _save_profiles()
        if disabled:
            _save_schedules()
        return jsonify({"ok": True})

    # ── Schedules ──

    @app.route("/api/schedules", methods=["GET"])
    def api_schedules_get():
        with _schedules_lock:
            return jsonify(list(_schedules.values()))

    @app.route("/api/schedules", methods=["POST"])
    def api_schedules_post():
        body = request.get_json(force=True, silent=True)
        try:
            schedule = _schedule_data(body)
        except ValueError:
            return jsonify({"error": "Invalid schedule configuration"}), 400
        sid = str(uuid.uuid4())
        schedule.update({
            "id": sid, "name": body.get("name", f"Schedule {sid[:8]}"),
            "created_at":     datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "last_run":       "",
        })
        with _profiles_lock:
            if schedule["profile_id"] not in _profiles:
                return jsonify({"error": "Profile not found"}), 400
            with _schedules_lock:
                _schedules[sid] = schedule
        _save_schedules()
        return jsonify(schedule), 201

    @app.route("/api/schedules/<sid>", methods=["PUT"])
    def api_schedules_put(sid):
        body = request.get_json(force=True, silent=True)
        with _profiles_lock:
            with _schedules_lock:
                if sid not in _schedules:
                    return jsonify({"error": "Schedule not found"}), 404
                try:
                    s = _schedule_data(body, _schedules[sid])
                except ValueError:
                    return jsonify({"error": "Invalid schedule configuration"}), 400
                if s["profile_id"] not in _profiles:
                    return jsonify({"error": "Profile not found"}), 400
                _schedules[sid] = s
        _save_schedules()
        return jsonify(s)

    @app.route("/api/schedules/<sid>", methods=["DELETE"])
    def api_schedules_delete(sid):
        with _schedules_lock:
            if sid not in _schedules:
                return jsonify({"error": "Schedule not found"}), 404
            del _schedules[sid]
        with _schedule_last_run_lock:
            _schedule_last_run.pop(sid, None)
        _save_schedules()
        return jsonify({"ok": True})

    return app


# ── Public entry point ────────────────────────────────────────────────────────

def start_server(host: str = "0.0.0.0", port: int = 8080, version: str = "Unkown") -> None:
    """Start the web UI server and block until Ctrl+C."""
    global __version__
    __version__ = version
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
