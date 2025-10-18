"""
Unit tests for the nist_search module.
"""
from unittest.mock import MagicMock, patch

import pytest
from requests.exceptions import ConnectionError

from modules.nist_search import searchCVE, Vulnerability, cache, FindVars


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

    @patch("modules.nist_search.get")
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

    @patch("modules.nist_search.get")
    def test_search_cve_no_results(self, mock_get, mock_log, clear_cache):
        """Verify it returns an empty list when no vulnerabilities are found."""
        mock_response = MagicMock()
        mock_response.json.return_value = {"vulnerabilities": []}
        mock_get.return_value = mock_response

        results = searchCVE("keyword", mock_log, "test-api-key")
        assert results == []

    @patch("modules.nist_search.get")
    def test_search_cve_rate_limit(self, mock_get, mock_log, clear_cache):
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

    @patch("modules.nist_search.get")
    def test_search_cve_connection_error(self, mock_get, mock_log, clear_cache):
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