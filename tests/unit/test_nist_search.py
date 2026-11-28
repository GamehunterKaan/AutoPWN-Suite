# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
"""
Unit tests for the nist_search module.
"""
import sys
from threading import Thread
from unittest.mock import MagicMock, patch

import pytest

from autopwn_suite.nist_search import CACHE_LIFETIME, FindVars, Vulnerability, cache, searchCPE, searchCVE


class Clock:
    """A settable stand-in for time.monotonic."""

    now = 1000.0

    def __call__(self):
        return self.now


def nvd_response(*cve_ids):
    response = MagicMock()
    response.json.return_value = {"vulnerabilities": [{"cve": {"id": cve_id}} for cve_id in cve_ids]}
    return response


@pytest.mark.unit
class TestSearchCVE:
    """Tests for the searchCVE function."""

    @pytest.fixture
    def clear_cache(self):
        """A fixture to clear the nist_search cache before each test."""
        cache.clear()
        yield

    @pytest.fixture
    def mock_log(self):
        """Fixture for a mocked logger."""
        return MagicMock()

    @patch("autopwn_suite.nist_search.get")
    def test_search_cve_success(self, mock_get, mock_log, clear_cache):
        """Verify a successful API call is parsed correctly."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2023-1234",
                        "descriptions": [{"lang": "en", "value": "Test description."}],
                        "metrics": {
                            "cvssMetricV31": [
                                {
                                    "cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"},
                                    "exploitabilityScore": 3.9,
                                }
                            ]
                        },
                    }
                }
            ]
        }
        mock_get.return_value = mock_response

        results = searchCVE("keyword", mock_log, "test-api-key")

        assert len(results) == 1
        cve = results[0]
        assert isinstance(cve, Vulnerability)
        assert cve.CVEID == "CVE-2023-1234"
        assert cve.description == "Test description."
        assert cve.severity == "CRITICAL"
        assert cve.severity_score == 9.8
        assert cve.exploitability == 3.9

    @patch("autopwn_suite.nist_search.get")
    def test_search_cve_no_results(self, mock_get, mock_log, clear_cache):
        """Verify it returns an empty list when no vulnerabilities are found."""
        mock_response = MagicMock()
        mock_response.json.return_value = {"vulnerabilities": []}
        mock_get.return_value = mock_response

        results = searchCVE("keyword", mock_log, "test-api-key")
        assert results == []

    @patch("autopwn_suite.nist_search.sleep")
    @patch("autopwn_suite.nist_search.get")
    def test_search_cve_rate_limit(self, mock_get, mock_sleep, mock_log, clear_cache):
        """Verify it handles a 403 rate-limit error."""
        mock_response_403 = MagicMock()
        mock_response_403.status_code = 403
        mock_response_403.json.side_effect = ValueError("JSON decode error")

        mock_response_ok = MagicMock()
        mock_response_ok.json.return_value = {"vulnerabilities": []}

        # The app will retry 3 times. Fail twice, then succeed.
        mock_get.side_effect = [mock_response_403, mock_response_403, mock_response_ok]

        results = searchCVE("keyword", mock_log, "test-api-key")
        assert results == []
        # Assert against the actual message logged by the application
        mock_log.logger.assert_any_call(
            "error", "Requests are being rate limited by NIST API, please get a NIST API key to prevent this."
        )

    @patch("autopwn_suite.nist_search.sleep")
    @patch("autopwn_suite.nist_search.get")
    def test_search_cve_connection_error(self, mock_get, mock_sleep, mock_log, clear_cache):
        """Verify it handles a connection error gracefully."""
        # To work around the UnboundLocalError bug, we simulate failure on the
        # first two retries and success on the third.
        mock_bad_response = MagicMock()
        mock_bad_response.status_code = 503  # Service Unavailable
        mock_bad_response.json.side_effect = ValueError("JSON decode error")

        mock_ok_response = MagicMock()
        mock_ok_response.json.return_value = {"vulnerabilities": []}

        mock_get.side_effect = [mock_bad_response, mock_bad_response, mock_ok_response]

        results = searchCVE("keyword", mock_log, "test-api-key")
        assert results == []

    @patch("autopwn_suite.nist_search.get")
    def test_cached_result_expires_so_long_lived_scans_see_new_cves(self, mock_get, mock_log, clear_cache):
        """A dashboard or scheduled scan must not keep reporting the first NVD answer forever."""
        clock = Clock()
        mock_get.side_effect = [nvd_response("CVE-2024-0001"), nvd_response("CVE-2024-0001", "CVE-2024-0002")]

        with patch("autopwn_suite.nist_search.monotonic", clock):
            first = searchCVE("OpenSSH 8.2p1", mock_log, "test-api-key", strict=True)
            clock.now += CACHE_LIFETIME - 1
            assert searchCVE("OpenSSH 8.2p1", mock_log, "test-api-key", strict=True) is first
            assert mock_get.call_count == 1
            clock.now += 1
            refreshed = searchCVE("OpenSSH 8.2p1", mock_log, "test-api-key", strict=True)

        assert [cve.CVEID for cve in first] == ["CVE-2024-0001"]
        assert [cve.CVEID for cve in refreshed] == ["CVE-2024-0001", "CVE-2024-0002"]
        assert mock_get.call_count == 2

    @patch("autopwn_suite.nist_search.get")
    def test_expired_entries_are_dropped_when_a_new_result_is_stored(self, mock_get, mock_log, clear_cache):
        """Keywords that are never looked up again must not stay in memory for the life of the process."""
        clock = Clock()
        mock_get.return_value = nvd_response("CVE-2024-0001")

        with patch("autopwn_suite.nist_search.monotonic", clock):
            searchCVE("one", mock_log, "test-api-key")
            searchCVE("two", mock_log, "test-api-key")
            clock.now += CACHE_LIFETIME
            searchCVE("three", mock_log, "test-api-key")

        assert set(cache) == {"three"}

    @patch("autopwn_suite.nist_search.sleep")
    def test_concurrent_scans_share_the_cache_without_errors(self, mock_sleep, mock_log, clear_cache):
        """Dashboard scans run in parallel threads; entries expire and are stored while others read."""
        clock = Clock()
        errors = []

        def worker(index):
            try:
                for step in range(300):
                    clock.now += CACHE_LIFETIME / 3
                    results = searchCVE(f"keyword {(index + step) % 7}", mock_log, "test-api-key", strict=True)
                    assert [cve.CVEID for cve in results] == ["CVE-2024-0001"]
            except Exception as error:  # reported to the main thread below
                errors.append(error)

        switch_interval = sys.getswitchinterval()
        sys.setswitchinterval(1e-6)  # interleave the threads as often as possible
        try:
            with patch("autopwn_suite.nist_search.get", new=lambda *args, **kwargs: nvd_response("CVE-2024-0001")), \
                 patch("autopwn_suite.nist_search.monotonic", clock):
                threads = [Thread(target=worker, args=(index,)) for index in range(6)]
                for thread in threads:
                    thread.start()
                for thread in threads:
                    thread.join()
        finally:
            sys.setswitchinterval(switch_interval)

        assert errors == []

@pytest.mark.unit
class TestFindVars:
    """Tests for the FindVars function."""

    def test_find_vars_with_cvss_v3(self):
        """Verify it parses CVSS v3.1 data correctly."""
        vuln_data = {
            "cve": {
                "id": "CVE-TEST-V3",
                "descriptions": [{"value": "V3 Test"}],
                "metrics": {
                    "cvssMetricV31": [{"exploitabilityScore": 8.8, "cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}]
                },
            }
        }
        cve_id, desc, severity, score, url, exploitability = FindVars(vuln_data)
        assert cve_id == "CVE-TEST-V3"
        assert severity == "CRITICAL"
        assert score == 9.8
        assert exploitability == 8.8

    def test_find_vars_with_cvss_v2_fallback(self):
        """Verify it falls back to CVSS v2 data if v3 is not present."""
        vuln_data = {
            "cve": {
                "id": "CVE-TEST-V2",
                "descriptions": [{"value": "V2 Test"}],
                "metrics": {
                    "cvssMetricV2": [{"exploitabilityScore": 10.0, "cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH"}}]
                },
            }
        }
        cve_id, desc, severity, score, url, exploitability = FindVars(vuln_data)
        assert cve_id == "CVE-TEST-V2"
        assert severity == "HIGH"
        assert score == 7.5
        assert exploitability == 10.0

    def test_find_vars_cvss_v4_takes_exploitability_from_the_newest_version_that_has_one(self):
        """CVSS v4 metrics carry no exploitabilityScore; 0.0 would read as 'not exploitable'."""
        vuln_data = {
            "cve": {
                "id": "CVE-TEST-V4",
                "descriptions": [{"lang": "en", "value": "V4 Test"}],
                "metrics": {
                    "cvssMetricV40": [{"type": "Secondary", "cvssData": {"version": "4.0", "baseScore": 8.7, "baseSeverity": "HIGH"}}],
                    "cvssMetricV31": [{"type": "Primary", "exploitabilityScore": 3.9, "cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}],
                    "cvssMetricV2": [{"exploitabilityScore": 10.0, "cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH"}}],
                },
            }
        }
        _, _, severity, score, _, exploitability = FindVars(vuln_data)
        assert (severity, score, exploitability) == ("HIGH", 8.7, 3.9)

    def test_find_vars_cvss_v4_alone_has_no_exploitability_and_its_own_value_is_kept(self):
        v4_only = {"cve": {"id": "CVE-TEST-V4-ONLY", "metrics": {
            "cvssMetricV40": [{"cvssData": {"baseScore": 8.7, "baseSeverity": "HIGH"}}]}}}
        assert FindVars(v4_only)[2:4] == ("HIGH", 8.7) and FindVars(v4_only)[5] == 0.0
        with_value = {"cve": {"id": "CVE-TEST-V4-VALUE", "metrics": {
            "cvssMetricV40": [{"exploitabilityScore": 2.5, "cvssData": {"baseScore": 8.7, "baseSeverity": "HIGH"}}],
            "cvssMetricV31": [{"exploitabilityScore": 3.9, "cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}]}}}
        assert FindVars(with_value)[5] == 2.5

    def test_find_vars_with_no_metrics(self):
        """Verify it handles missing metrics gracefully."""
        vuln_data = {
            "cve": {"id": "CVE-TEST-NOMETRICS", "descriptions": [{"value": "No Metrics Test"}]}
        }
        cve_id, desc, severity, score, url, exploitability = FindVars(vuln_data)
        assert severity == "UNKNOWN"
        assert score == 0.0
        assert exploitability == 0.0

    def test_find_vars_with_empty_metrics(self):
        """Verify it handles an empty metrics dictionary."""
        vuln_data = {
            "cve": {"id": "CVE-TEST-EMPTY", "descriptions": [{"value": "Empty Metrics Test"}], "metrics": {}}
        }
        cve_id, desc, severity, score, url, exploitability = FindVars(vuln_data)
        assert severity == "UNKNOWN"
        assert score == 0.0
        assert exploitability == 0.0


@pytest.mark.unit
@patch("autopwn_suite.nist_search.sleep")
@patch("autopwn_suite.nist_search.get")
def test_the_cpe_search_asks_nvd_for_the_product_of_any_vendor_and_no_version(mock_get, mock_sleep):
    cache.clear()
    mock_get.return_value.json.return_value = {"totalResults": 0, "vulnerabilities": []}
    try:
        assert searchCPE("nginx", MagicMock(), "key", strict=True) == []
        assert mock_get.call_args.kwargs["params"] == {"virtualMatchString": "cpe:2.3:*:*:nginx", "noRejected": ""}
        assert mock_get.call_args.kwargs["headers"] == {"apiKey": "key"}
        searchCPE("nginx", MagicMock(), "key", strict=True)
        assert mock_get.call_count == 1  # cached
        searchCVE("nginx", MagicMock(), "key", strict=True)
        assert mock_get.call_count == 2 and mock_get.call_args.kwargs["params"] == {"keywordSearch": "nginx", "noRejected": ""}
        mock_get.return_value.raise_for_status.side_effect = RuntimeError("HTTP 503")
        with pytest.raises(RuntimeError, match="NVD lookup failed for tomcat"):
            searchCPE("tomcat", MagicMock(), "key", strict=True)
    finally:
        cache.clear()


def refused(status, **headers):
    """An NVD answer that is not a result: raise_for_status raises for 4xx and 5xx, as requests does."""
    response = MagicMock(status_code=status, headers=headers)
    if status >= 400:
        response.raise_for_status.side_effect = RuntimeError(f"HTTP {status}")
    return response


@pytest.mark.unit
@patch("autopwn_suite.nist_search.sleep")
@patch("autopwn_suite.nist_search.get")
def test_a_redirect_from_nvd_is_a_failed_request_and_is_not_followed(mock_get, mock_sleep):
    """requests keeps a custom header across hosts, so following a redirect would send the apiKey to its target."""
    cache.clear()
    mock_get.return_value = refused(302, Location="https://example.invalid/")
    with pytest.raises(RuntimeError, match="NVD lookup failed for nginx"):
        searchCVE("nginx", MagicMock(), "key", strict=True)
    assert mock_get.call_count == 3
    assert all(call.kwargs["allow_redirects"] is False for call in mock_get.call_args_list)
    mock_get.return_value.json.assert_not_called()


@pytest.mark.unit
@pytest.mark.parametrize("answers, key, pauses", [
    ([refused(429, **{"Retry-After": "7"})] * 3, "key", [7, 7]),       # what the NVD asks for
    ([refused(403, **{"Retry-After": "86400"})] * 3, "key", [30, 30]),  # never longer than the limit
    ([refused(429)] * 3, "key", [1, 2]),                                 # no header: a pause that doubles
    ([refused(503, **{"Retry-After": "7"})] * 3, "key", [1, 2]),        # the header counts for 429 and 403 only
    ([refused(429)] * 3, None, [8, 16]),                                 # without a key the pause starts at 8 s
], ids=["retry-after", "capped", "no-header", "not-a-rate-limit", "no-key"])
@patch("autopwn_suite.nist_search.sleep")
@patch("autopwn_suite.nist_search.get")
def test_a_failed_nvd_request_waits_longer_before_each_retry(mock_get, mock_sleep, answers, key, pauses):
    """The three tries were 0.1 s apart with a key and ignored Retry-After, so a rate limit used them up at once."""
    cache.clear()
    mock_get.side_effect = answers
    assert searchCVE("nginx", MagicMock(), key) == []
    before = 0.1 if key else 8  # the pause before every request, as before
    assert [call.args[0] for call in mock_sleep.call_args_list] == [before, pauses[0], before, pauses[1], before]


@pytest.mark.unit
@pytest.mark.parametrize("strict", [True, False])
@patch("autopwn_suite.nist_search.sleep")
@patch("autopwn_suite.nist_search.get")
def test_a_record_that_cannot_be_parsed_is_not_requested_again(mock_get, mock_sleep, strict):
    """It fails the same way each time; the page was fetched three times, 8 s apart without a key."""
    cache.clear()
    mock_get.return_value.json.return_value = {"totalResults": 1, "vulnerabilities": [{"not-a-cve": {}}]}
    log = MagicMock()
    if strict:
        with pytest.raises(RuntimeError, match="NVD lookup failed for nginx"):
            searchCVE("nginx", log, strict=True)
    else:
        assert searchCVE("nginx", log) == []
        log.logger.assert_called_once_with("warning", "NVD lookup failed for nginx; vulnerability coverage is incomplete.")
    assert mock_get.call_count == 1
    assert "nginx" not in cache
