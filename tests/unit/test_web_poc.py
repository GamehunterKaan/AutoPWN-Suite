import ast
from unittest.mock import MagicMock, patch

import pytest

from modules.web.poc import browser_poc, build_plan, curl_poc, python_poc
from modules.web.poc_runtime import validate_plan, verify_plan
from tests.unit.test_web_dashboard import dashboard


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
    with patch("modules.web.poc_runtime.requests.Session") as session, pytest.raises(ValueError):
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
    with patch("modules.web.poc_runtime.requests.Session") as session:
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
    with patch.object(wu.threading, "Thread", side_effect=thread), patch("modules.web.poc_runtime.verify_plan", return_value={"status": "reproduced", "impact_verified": False}) as verify:
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
    with patch("modules.web.poc_runtime._check_tls", return_value=True):
        assert verify_plan(build_plan(result), transport=transport)["status"] == "reproduced"
    transport.assert_not_called()
