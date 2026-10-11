from unittest.mock import MagicMock, patch

import pytest

from modules.web.additional import additional_checks
from modules.web.options import normalize_options


@pytest.mark.unit
def test_checks_run_on_static_sites_with_bounded_endpoint_scope(web_response):
    log = MagicMock()
    controls = normalize_options()
    limit = controls["max_endpoints"]
    urls = {f"http://example.com/page{i}" for i in range(limit + 10)} | {"http://external.com/x"}
    with patch("modules.web.http.request", return_value=web_response("<html>Home</html>")) as request, patch("modules.web.additional.check_tls", return_value=[]):
        results = additional_checks("http://example.com/", urls, web_response("<html>Home</html>"), log, MagicMock())
    assert results == []
    assert request.call_count <= controls["request_budget"]
    assert all(call.args[1].startswith("http://example.com/") for call in request.call_args_list)
    baselines = {call.args[1] for call in request.call_args_list if "__autopwn_probe" not in call.args[1]}
    assert len(baselines) == limit
    assert any(f"{limit} discovered endpoints" in call.args[1] for call in log.logger.call_args_list)


@pytest.mark.unit
def test_orchestrator_includes_additional_results(web_response):
    from modules.web.webvuln import webvuln
    result = {"type": "CORS", "url": "http://example.com/", "parameter": None, "severity": "medium", "confidence": "candidate", "evidence": "repeatable"}
    with patch("modules.web.webvuln.get", return_value=web_response(url="http://example.com/")), patch("modules.web.webvuln.dirbust", return_value=[]), patch("modules.web.webvuln.crawl", return_value=set()), patch("modules.web.webvuln.inspect_response", return_value=[]), patch("modules.web.webvuln.additional_checks", return_value=[result]) as additional:
        assert webvuln("example.com", MagicMock(), MagicMock()) == [result]
    additional.assert_called_once()
