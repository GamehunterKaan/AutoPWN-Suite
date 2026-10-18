# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
import ast
import ipaddress
import ssl
from unittest.mock import MagicMock, call, patch

import pytest

from autopwn_suite.web.poc import browser_poc, build_plan, curl_poc, python_poc
from autopwn_suite.web.poc_runtime import verify_plan
from tests.unit.test_web_dashboard import dashboard as dashboard
from tests.unit.test_web_tls import certificate_der as certificate_der


def sample(kind="CORS", strategy="cors"):
    url = "http://example.com/"
    rows = [{"url": url, "method": "GET", "headers": {"Origin": origin}} for origin in ("https://one.invalid", "https://two.invalid")]
    return {"id": "finding", "type": kind, "url": url, "endpoint": url, "parameter": None,
            "evidence": "Repeatable evidence", "severity": "medium", "confidence": "candidate",
            "reproduction": {"strategy": strategy, "target": url, "requests": rows}}


@pytest.mark.unit
def test_portable_python_poc_is_valid_and_keeps_data_as_a_literal():
    result = sample()
    result["evidence"] = "__import__('os').system('whoami')"
    code = python_poc(result)
    ast.parse(code)
    namespace = {"__name__": "imported_poc"}
    exec(compile(code, "generated_poc.py", "exec"), namespace)
    assert callable(namespace["verify_plan"])
    assert "requests.Session" in code
    assert "allow_redirects=False" in code


@pytest.mark.unit
def test_cors_poc_reproduces_headers_without_following_redirects(web_response):
    result = sample()
    calls = []
    def send(method, url, **kwargs):
        calls.append(kwargs)
        return web_response("private-body", headers={"Access-Control-Allow-Origin": kwargs["headers"]["Origin"], "Access-Control-Allow-Credentials": "true"})
    verification = verify_plan(build_plan(result), transport=send)
    assert verification["status"] == "reproduced"
    assert verification["impact_verified"] is False
    assert "private-body" not in str(verification)
    assert verification["observations"][0]["headers"]["Access-Control-Allow-Origin"] == "https://one.invalid"
    assert all(not row["allow_redirects"] for row in calls)


@pytest.mark.unit
@pytest.mark.parametrize("mutate", [
    lambda plan: plan["requests"][0].update(url="http://external.com/"),
    lambda plan: plan["requests"][0].update(method="DELETE"),
    lambda plan: plan["requests"][0].update(headers={"Authorization": "secret"}),
    lambda plan: plan["requests"][0].update(url="http://example.com/?token=REDACTED"),
    lambda plan: plan.update(requests=[]),
])
def test_invalid_or_redacted_plans_are_rejected_before_any_request(mutate):
    plan = build_plan(sample())
    mutate(plan)
    with patch("autopwn_suite.web.poc_runtime.requests.Session") as session, pytest.raises(ValueError):
        verify_plan(plan)
    session.assert_not_called()


@pytest.mark.unit
def test_sql_poc_requires_baseline_difference_and_repeat(web_response):
    result = sample("SQLI", "sqli_error")
    result["reproduction"]["requests"] = [{"url": "http://example.com/?id=1", "role": "baseline"},
                                           {"url": "http://example.com/?id=%27", "role": "probe"},
                                           {"url": "http://example.com/?id=%27", "role": "repeat"}]
    responses = [web_response("normal"), web_response("You have an error in your SQL syntax"), web_response("You have an error in your SQL syntax")]
    assert verify_plan(build_plan(result), transport=MagicMock(side_effect=responses))["status"] == "reproduced"
    assert verify_plan(build_plan(result), transport=MagicMock(return_value=web_response("You have an error in your SQL syntax")))["status"] == "not_reproduced"


@pytest.mark.parametrize("kind", ["sqli", "lfi", "xss"])
def test_redirected_findings_record_final_evidence_and_reproduce_without_redirects(web_response, kind):
    from urllib.parse import parse_qs, urlsplit, urlunsplit

    from autopwn_suite.web.lfi import LFIScanner
    from autopwn_suite.web.runtime import ScanContext, redact_url
    from autopwn_suite.web.sqli import SQLIScanner
    from autopwn_suite.web.xss import XSSScanner
    scanners = {"sqli": (SQLIScanner, "test_sqli"), "lfi": (LFIScanner, "test_lfi"), "xss": (XSSScanner, "test_xss")}
    url = "http://example.com/read?file=one&token=private"
    def site(requested, **kwargs):
        parts = urlsplit(requested)
        if parts.path in ("/read", "/middle"):
            path = "/middle" if parts.path == "/read" else "/read/"
            return web_response(status=302, url=requested, headers={"Location": urlunsplit(parts._replace(path=path))})
        value = parse_qs(parts.query)["file"][0]
        if kind == "sqli":
            body = "You have an error in your SQL syntax" if "'" in value else "Normal page"
        elif kind == "lfi":
            body = "root:x:0:0:root:/root:/bin/bash" if "passwd" in value else "Normal page"
        else:
            body = "<html>" + value + "</html>"
        return web_response(body, url=requested)
    context = ScanContext(url, MagicMock(), controls={"speed": 5})
    scanner, method = scanners[kind]
    with context.activate(), patch(f"autopwn_suite.web.{kind}.get", side_effect=site):
        result = getattr(scanner(MagicMock(), MagicMock()), method)(url)[0]
    result["endpoint"] = redact_url(url)
    assert "private" not in str(result)
    plan = build_plan(result)
    assert all(urlsplit(row["url"]).path == "/read/" for row in plan["requests"])
    assert all("REDACTED" in row["url"] for row in plan["requests"])
    statuses = [row["response"]["status"] for row in result["observations"]]
    assert statuses == [302, 302, 200] * len(plan["requests"])
    # Restore the local input as a user would before running the download.
    for row in plan["requests"]:
        row["url"] = row["url"].replace("REDACTED", "private")
    calls = []
    def transport(method, requested, **kwargs):
        calls.append((requested, kwargs))
        return site(requested)
    verified = verify_plan(plan, transport=transport)
    assert verified["status"] == "reproduced"
    assert len(calls) == len(plan["requests"])
    assert all(urlsplit(requested).path == "/read/" and not kwargs["allow_redirects"] for requested, kwargs in calls)
    assert all('/read/?' in line for line in curl_poc(result).splitlines() if line.startswith('curl'))


@pytest.mark.unit
def test_xss_poc_rejects_comment_and_inactive_reflection(web_response):
    result = sample("XSS", "xss_reflection")
    payload = "<script>alert('marker')</script>"
    result["reproduction"].update(marker="marker", payload=payload, requests=[{"url": "http://example.com/?q=x"}])
    for context, expected in (("<html>{}</html>", "reproduced"), ("<!-- {} -->", "not_reproduced"), ("<textarea>{}</textarea>", "not_reproduced")):
        assert verify_plan(build_plan(result), transport=MagicMock(return_value=web_response(context.format(payload))))["status"] == expected


@pytest.mark.unit
def test_browser_poc_escapes_script_closing_payload_and_requires_click():
    result = sample("XSS", "xss_reflection")
    result["url"] = "http://example.com/?q=</script><script>bad()</script>"
    code = browser_poc(result)
    assert "\\u003c/script>" in code
    assert "document.getElementById('run').onclick" in code
    assert "window.open" in code
    assert browser_poc(sample("SQLI")) is None


@pytest.mark.unit
def test_downloads_are_read_only_and_work_in_offline_mode(dashboard):
    wu, client = dashboard
    job = wu.ScanJob("job", "example.com", {})
    job.add_web_finding("example.com", "http://example.com/", sample())
    wu._register_scan(job)
    wu._settings["offline_mode"] = True
    with patch("autopwn_suite.web.poc_runtime.requests.Session") as session:
        response = client.get("/api/web/findings/job/finding/poc?format=python")
        assert response.status_code == 200
        assert "attachment" in response.headers["Content-Disposition"]
        ast.parse(response.get_data(as_text=True))
        assert client.post("/api/web/findings/job/finding/verify", json={}).status_code == 409
    session.assert_not_called()


@pytest.mark.unit
def test_verification_has_explicit_post_and_stores_result(dashboard):
    wu, client = dashboard
    job = wu.ScanJob("job", "example.com", {})
    job.mark_done()
    job.add_web_finding("example.com", "http://example.com/", sample())
    wu._register_scan(job)
    def thread(**kwargs):
        return MagicMock(start=lambda: kwargs["target"]())
    with patch.object(wu.threading, "Thread", side_effect=thread), patch("autopwn_suite.web.poc_runtime.verify_plan", return_value={"status": "reproduced", "impact_verified": False}) as verify:
        assert client.get("/api/web/findings/job/finding/verify").status_code in (404, 405)
        assert client.post("/api/web/findings/job/finding/verify", json={"url": "http://external.com/"}).status_code == 400
        assert client.post("/api/web/findings/job/finding/verify", json={}).status_code == 202
    verify.assert_called_once()
    assert job.web_finding("finding")["verification"]["status"] == "reproduced"
    assert wu._web_verifications_running == 0


@pytest.mark.unit
def test_pending_verification_blocks_duplicate_and_offline_transition(dashboard):
    wu, client = dashboard
    job = wu.ScanJob("job", "example.com", {})
    job.mark_done()
    job.add_web_finding("example.com", "http://example.com/", sample())
    wu._register_scan(job)
    with patch.object(wu.threading, "Thread", return_value=MagicMock()):
        assert client.post("/api/web/findings/job/finding/verify", json={}).status_code == 202
        assert client.post("/api/web/findings/job/finding/verify", json={}).status_code == 409
        assert client.put("/api/settings", json={"offline_mode": True}).status_code == 409
    assert not wu._offline_enabled()


@pytest.mark.unit
@pytest.mark.parametrize("kind,strategy,rows,responses,extra", [
    ("LFI", "file_inclusion", [{"url": "http://example.com/?file=one"}, {"url": "http://example.com/?file=etc"}, {"url": "http://example.com/?file=etc"}],
     ["normal", "root:x:0:0:root:/root:/bin/bash", "root:x:0:0:root:/root:/bin/bash"], {}),
    ("TRACE_ENABLED", "trace", [{"url": "http://example.com/", "method": "TRACE"}, {"url": "http://example.com/", "method": "TRACE"}],
     ["TRACE / HTTP/1.1\nX-Autopwn-Trace: marker\n"] * 2, {"marker": "marker"}),
    ("EXPOSED_FILE", "response", [{"url": "http://example.com/.env"}], ["DB_HOST=localhost\nDB_PASSWORD=secret"], {}),
    ("DIR_LISTING", "response", [{"url": "http://example.com/files/"}], ['<h1>Index of /files/</h1><a href="one">one</a><a href="two">two</a>'], {}),
])
def test_other_poc_signatures_are_reproduced_without_printing_contents(web_response, kind, strategy, rows, responses, extra):
    result = sample(kind, strategy)
    result["reproduction"].update(requests=rows, **extra)
    verification = verify_plan(build_plan(result), transport=MagicMock(side_effect=[web_response(body) for body in responses]))
    assert verification["status"] == "reproduced"
    assert "DB_PASSWORD=secret" not in str(verification)


@pytest.mark.unit
def test_boolean_poc_requires_both_distinct_contrasts(web_response):
    result = sample("SQLI_BOOLEAN", "boolean_sqli")
    result["parameter"] = "id"
    result["reproduction"]["requests"] = [{"url": "http://example.com/?id=" + value} for value in ("1", "1", "true1", "false1", "true2", "false2")]
    good, empty = "<html>Record one with complete details</html>", "<html>No records</html>"
    assert verify_plan(build_plan(result), transport=MagicMock(side_effect=[web_response(body) for body in (good, good, good, empty, good, empty)]))["status"] == "reproduced"
    assert verify_plan(build_plan(result), transport=MagicMock(return_value=web_response(good)))["status"] == "not_reproduced"


@pytest.mark.unit
def test_redirect_and_host_pocs_verify_controlled_hosts(web_response):
    result = sample("OPEN_REDIRECT", "redirect")
    result["parameter"] = "next"
    result["reproduction"]["requests"] = [{"url": "http://example.com/?next=https://" + host} for host in ("one.invalid", "two.invalid")]
    responses = [web_response(status=302, headers={"Location": "https://" + host}) for host in ("one.invalid", "two.invalid")]
    assert verify_plan(build_plan(result), transport=MagicMock(side_effect=responses))["status"] == "reproduced"
    result = sample("HOST_HEADER", "host_header")
    result["reproduction"].update(header="Host", requests=[{"url": "http://example.com/", "headers": {"Host": host}} for host in ("one.invalid", "two.invalid")])
    assert verify_plan(build_plan(result), transport=MagicMock(side_effect=[web_response(f'<a href="https://{host}/reset">Reset</a>') for host in ("one.invalid", "two.invalid")]))["status"] == "reproduced"


@pytest.mark.unit
def test_tls_poc_never_uses_http_transport():
    result = sample("TLS_PROTOCOL")
    result["evidence"] = "Server negotiated obsolete TLSv1.1"
    result["reproduction"]["target"] = "https://example.com/"
    transport = MagicMock()
    with patch("autopwn_suite.web.poc_runtime._check_tls", return_value=True):
        assert verify_plan(build_plan(result), transport=transport)["status"] == "reproduced"
    transport.assert_not_called()


@pytest.mark.parametrize("label,version", [("TLSv1", ssl.TLSVersion.TLSv1), ("TLSv1.1", ssl.TLSVersion.TLSv1_1)])
def test_legacy_tls_poc_only_checks_the_exact_negotiated_version(label, version):
    result = sample("TLS_PROTOCOL")
    result["evidence"] = f"Server negotiated obsolete {label}"
    result["reproduction"]["target"] = "https://example.com:8443/"
    context = MagicMock()
    secure = context.wrap_socket.return_value.__enter__.return_value
    secure.version.return_value = label
    with patch("autopwn_suite.web.poc_runtime.ssl.create_default_context", return_value=context), \
         patch("autopwn_suite.web.poc_runtime.socket.create_connection") as connect:
        assert verify_plan(build_plan(result))["status"] == "reproduced"
    assert context.minimum_version == context.maximum_version == version
    assert secure.method_calls == [call.version()]
    connect.assert_called_once_with(("example.com", 8443), timeout=10)
    connect.return_value.__exit__.assert_called_once()
    context.wrap_socket.return_value.__exit__.assert_called_once()


@pytest.mark.unit
@pytest.mark.parametrize("kind,path,evidence,body,headers,status,expected", [
    ("DEBUG_DISCLOSURE", "/docs", "diagnostic", "DEBUG = True", {"Content-Type": "text/plain"}, 200, "not_reproduced"),
    ("DEBUG_DISCLOSURE", "/debug", "diagnostic", '<html id="summary">Django DEBUG = True</html>', {"Content-Type": "text/html"}, 500, "reproduced"),
    ("DEBUG_DISCLOSURE", "/phpinfo", "diagnostic", '<title>phpinfo()</title>PHP Version 8', {"Content-Type": "text/html"}, 200, "reproduced"),
    ("ERROR_DISCLOSURE", "/error", "trace", "Reference: Source Error:", {}, 500, "not_reproduced"),
    ("ERROR_DISCLOSURE", "/error", "trace", 'Traceback (most recent call last):\nFile "app.py", line 2', {}, 500, "reproduced"),
    ("EXPOSED_FILE", "/.env", "configuration", "<html><body>DB_PASSWORD=example\nDB_HOST=example</body></html>", {}, 200, "not_reproduced"),
    ("EXPOSED_FILE", "/.env", "configuration", "DB_PASSWORD=example\nDB_PASSWORD=example", {}, 200, "not_reproduced"),
    ("EXPOSED_FILE", "/.env", "configuration", "export DB_PASSWORD=example\n  DB_HOST=example", {}, 200, "reproduced"),
    ("EXPOSED_FILE", "/.git/config", "configuration", "[core]\nrepositoryformatversion=0", {}, 200, "reproduced"),
    ("EXPOSED_FILE", "/backup.zip", "archive", b"PK\x03\x04archive", {}, 200, "reproduced"),
    ("WEB_CONFIG", "/", "No enforced Content-Security-Policy on this HTML response", "{}", {"Content-Type": "application/json"}, 200, "not_reproduced"),
    ("WEB_CONFIG", "/", "No enforced Content-Security-Policy on this HTML response", "<html></html>", {}, 200, "reproduced"),
    ("WEB_CONFIG", "/", "X-Content-Type-Options is missing or is not nosniff", "text", {"X-Content-Type-Options": " nosniff "}, 200, "not_reproduced"),
    ("WEB_CONFIG", "/", "HSTS is missing or has no positive max-age", "text", {"Strict-Transport-Security": "max-age=123bad"}, 200, "reproduced"),
])
def test_response_pocs_preserve_scanner_preconditions(web_response, kind, path, evidence, body, headers, status, expected):
    result = sample(kind, "response")
    result.update(url="http://example.com" + path, evidence=evidence)
    result["reproduction"]["requests"] = [{"url": result["url"]}]
    response = web_response(body, status=status, headers=headers)
    assert verify_plan(build_plan(result), transport=MagicMock(return_value=response))["status"] == expected


@pytest.mark.unit
def test_boolean_poc_cannot_reproduce_matching_error_pages(web_response):
    result = sample("SQLI_BOOLEAN", "boolean_sqli")
    result["reproduction"]["requests"] = [{"url": "http://example.com/?id=" + str(index)} for index in range(6)]
    bodies = ("All records", "All records", "All records", "No results", "All records", "No results")
    assert verify_plan(build_plan(result), transport=MagicMock(side_effect=[web_response(body, status=500) for body in bodies]))["status"] == "not_reproduced"


@pytest.mark.unit
def test_verification_metadata_redacts_redirect_credentials_and_cookie_headers(web_response):
    result = sample("WEB_CONFIG", "response")
    result["evidence"] = "X-Content-Type-Options is missing or is not nosniff"
    result["reproduction"]["requests"] = [{"url": "http://example.com/"}]
    response = web_response("", headers={"Location": "http://user:password@example.com/?token=secret#private", "Set-Cookie": "secret=value"})
    verification = verify_plan(build_plan(result), transport=MagicMock(return_value=response))
    assert verification["observations"][0]["headers"]["Location"] == "http://example.com/?token=REDACTED"
    assert "Set-Cookie" not in str(verification)
    assert "password" not in str(verification)
    assert "secret" not in str(verification)


@pytest.mark.unit
def test_curl_poc_quotes_target_controlled_data_as_arguments():
    import shlex
    result = sample()
    result["reproduction"]["requests"][0]["url"] = "http://example.com/?q=';echo danger;$HOME"
    command = curl_poc(result).splitlines()[1]
    args = shlex.split(command)
    assert args[args.index("--url") + 1] == result["reproduction"]["requests"][0]["url"]
    assert "--location" not in args


@pytest.mark.unit
@pytest.mark.parametrize("options,target,evidence,expected", [
    ({"expired": True}, "https://example.com/", "Certificate expired at earlier time", "reproduced"),
    ({}, "https://example.com/", "Certificate expired at earlier time", "not_reproduced"),
    ({"future": True}, "https://example.com/", "Certificate is not valid before later time", "reproduced"),
    ({"names": ("other.example",)}, "https://example.com/", "No certificate subject alternative name matches", "reproduced"),
    ({"names": ("*.example.com",)}, "https://app.example.com/", "No certificate subject alternative name matches", "not_reproduced"),
    ({"names": ("*.com",)}, "https://example.com/", "No certificate subject alternative name matches", "reproduced"),
    ({"names": ("xn--bcher-kva.example",)}, "https://bücher.example/", "No certificate subject alternative name matches", "not_reproduced"),
    ({"names": (ipaddress.ip_address("192.0.2.1"),)}, "https://192.0.2.1/", "No certificate subject alternative name matches", "not_reproduced"),
    ({"names": None}, "https://example.com/", "No certificate subject alternative name matches", "reproduced"),
])
def test_tls_certificate_poc_checks_actual_certificate_metadata(certificate_der, options, target, evidence, expected):
    result = sample("TLS_CERTIFICATE")
    result["evidence"] = evidence
    result["reproduction"]["target"] = target
    context = MagicMock()
    context.wrap_socket.return_value.__enter__.return_value.getpeercert.return_value = certificate_der(**options)
    with patch("autopwn_suite.web.poc_runtime.ssl.create_default_context", return_value=context), patch("autopwn_suite.web.poc_runtime.socket.create_connection"):
        assert verify_plan(build_plan(result))["status"] == expected
    assert context.verify_mode == ssl.CERT_NONE


@pytest.mark.unit
def test_tls_poc_distinguishes_untrusted_certificates_from_connection_failures():
    result = sample("TLS_TRUST")
    result["reproduction"]["target"] = "https://example.com/"
    context = MagicMock()
    with patch("autopwn_suite.web.poc_runtime.ssl.create_default_context", return_value=context), patch("autopwn_suite.web.poc_runtime.socket.create_connection"):
        context.wrap_socket.side_effect = ssl.SSLCertVerificationError("untrusted")
        assert verify_plan(build_plan(result))["status"] == "reproduced"
        context.wrap_socket.side_effect = OSError("unreachable")
        assert verify_plan(build_plan(result))["status"] == "inconclusive"
