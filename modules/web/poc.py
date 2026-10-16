# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
"""Generate runnable PoCs from stored scanner evidence, never arbitrary code."""

import json
import shlex
from pathlib import Path

from modules.web.poc_runtime import validate_plan as validate_plan
from modules.web.poc_runtime import verify_plan as verify_plan


def build_plan(finding):
    reproduction = finding.get("reproduction", {})
    plan = {"strategy": reproduction.get("strategy", "response"), "target": reproduction.get("target", finding["endpoint"]),
            "requests": reproduction.get("requests", [{"url": finding["url"], "method": "GET"}]),
            "kind": finding["type"], "evidence": finding["evidence"], "parameter": finding.get("parameter"),
            "verify_tls": reproduction.get("verify_tls", True) is not False}
    for field in ("marker", "payload", "header"):
        if field in reproduction:
            plan[field] = reproduction[field]
    if finding["type"].startswith("TLS_"):
        plan.update(strategy="tls", requests=[])
    return plan


def python_poc(finding):
    plan = build_plan(finding)
    runtime = Path(__file__).with_name("poc_runtime.py").read_text(encoding="utf-8")
    transport = Path(__file__).with_name("transport.py").read_text(encoding="utf-8")
    # Keep downloads standalone while sharing the scanner's exact transport.
    runtime = runtime.replace("from modules.web.transport import read_response\n", "")
    serialized = repr(json.dumps(plan, ensure_ascii=True))
    return ("#!/usr/bin/env python3\n# Reproduce recorded evidence on the same origin.\n"
            "# Install: python -m pip install requests cryptography\n"
            "# Replace REDACTED query values locally if present.\n" + transport + "\n" + runtime +
            f"\n\nif __name__ == '__main__':\n    import json\n    PLAN = json.loads({serialized})\n"
            "    try:\n        result = verify_plan(PLAN)\n    except ValueError as error:\n        result = {'status': 'needs_input', 'summary': str(error)}\n"
            "    print(json.dumps(result, indent=2))\n")


def curl_poc(finding):
    plan = build_plan(finding)
    if plan["strategy"] == "tls":
        return "# Use the Python PoC for certificate and exact-version TLS verification.\n"
    rows = ["# Inspect headers without following redirects. Response bodies are discarded."]
    for request in plan["requests"]:
        command = ["curl", "--max-time", "10", "--max-redirs", "0", "--request", request.get("method", "GET"), "--dump-header", "-", "--output", "/dev/null"]
        if not plan["verify_tls"]:
            # Recorded from a scan the operator explicitly ran with --insecure-tls.
            command.insert(3, "--insecure")
        for name, value in request.get("headers", {}).items():
            command += ["--header", f"{name}: {value}"]
        command += ["--url", request["url"]]
        rows.append(" ".join(shlex.quote(part) for part in command))
    return "\n".join(rows) + "\n"


def browser_poc(finding):
    if finding["type"] not in ("CORS", "XSS"):
        return None
    plan = build_plan(finding)
    target = finding["url"]
    data = json.dumps({"target": target, "kind": finding["type"], "marker": plan.get("marker", "")}).replace("<", "\\u003c")
    return f'''<!doctype html><html lang="en"><meta charset="utf-8"><title>Browser evidence test</title>
<style>body{{font:16px system-ui;max-width:760px;margin:48px auto;padding:24px;background:#101722;color:#e5edf7}}input{{box-sizing:border-box;width:100%;padding:12px;margin:12px 0}}button{{padding:12px 20px;cursor:pointer}}pre{{white-space:pre-wrap}}</style>
<h1>Browser evidence test</h1><p>This page sends a request only when you click Run test.</p>
<p>For CORS, serve this file from a separate controlled origin and open it while logged into the target.
Browser cookie policy may prevent credentials. For a null-origin finding, also test opening this file locally.
For XSS, the test opens the recorded payload URL; check whether the marker appears in an executed alert.</p>
<label>Target URL<input id="target"></label><button id="run">Run test</button><pre id="result"></pre>
<script>const DATA={data};const field=document.getElementById('target');field.value=DATA.target;
document.getElementById('run').onclick=async()=>{{const target=field.value;const output=document.getElementById('result');
if(new URL(target).origin!==new URL(DATA.target).origin){{output.textContent='Use the recorded target origin.';return;}}
if(target.includes('REDACTED')){{output.textContent='Replace redacted values first.';return;}}
if(DATA.kind==='XSS'){{window.open(target,'_blank','noopener,noreferrer');output.textContent='Expected executed marker: '+DATA.marker;return;}}
try{{const response=await fetch(target,{{credentials:'include',redirect:'error'}});output.textContent='Browser could read the response. Status: '+response.status+'; type: '+response.headers.get('content-type')+'; authenticated sensitive-data impact still requires application review.';}}
catch(error){{output.textContent='Browser could not read the response: '+error.message;}}}};</script></html>'''
