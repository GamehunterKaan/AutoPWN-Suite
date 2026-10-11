"""Consistent, reviewable web findings without treating probes as proof."""

from rich.text import Text


def finding(kind, url, evidence, *, parameter=None, severity="low", confidence="candidate"):
    return {"type": kind, "url": url, "parameter": parameter,
            "severity": severity, "confidence": confidence, "evidence": evidence}


def emit(console, result):
    # Target-controlled URLs and evidence must not be parsed as Rich markup.
    console.print(Text(f"[+] {result['type']} ({result['confidence']}, {result['severity']}): "
                       f"{result['url']} — {result['evidence']}"))
