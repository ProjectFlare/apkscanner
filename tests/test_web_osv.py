"""Unit tests for scanner.web.osv.

Covers the OSV.dev package vulnerability lookup, parsing of GHSA/CVE aliases,
clean result formatting, and HTTP/network error handling.
"""

from unittest.mock import MagicMock, patch

import pytest

from scanner.web.osv import lookup_osv_vulnerabilities


def test_lookup_osv_vulnerabilities_found():
    """lookup_osv_vulnerabilities returns CVE IDs and OSV links when vulns exist."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "vulns": [
            {
                "id": "GHSA-xxxx-yyyy",
                "summary": "A critical remote code execution vulnerability.",
                "aliases": ["CVE-2024-9999"],
            }
        ]
    }
    with patch("requests.post", return_value=mock_resp):
        result = lookup_osv_vulnerabilities("com.squareup.okhttp3:okhttp", "3.0.0")
    assert "GHSA-xxxx-yyyy" in result
    assert "CVE-2024-9999" in result
    assert "osv.dev" in result


def test_lookup_osv_no_vulns():
    """lookup_osv_vulnerabilities reports no vulns when OSV returns an empty list."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"vulns": []}
    with patch("requests.post", return_value=mock_resp):
        result = lookup_osv_vulnerabilities("com.example:safe", "1.0.0")
    assert "no known vulnerabilities" in result.lower()


def test_lookup_osv_non_200_raises_instead_of_reporting_clean():
    """A non-200 OSV response must raise, never fall through to a 'no vulnerabilities' string."""
    for status in (429, 500, 503):
        mock_resp = MagicMock()
        mock_resp.status_code = status
        mock_resp.json.return_value = {}
        with patch("requests.post", return_value=mock_resp), pytest.raises(RuntimeError) as exc:
            lookup_osv_vulnerabilities("com.example:lib", "1.0.0")
        assert str(status) in str(exc.value)


def test_lookup_osv_network_exception_raises():
    """Network connection exceptions are wrapped in RuntimeError."""
    with patch("requests.post", side_effect=Exception("Connection reset")):
        with pytest.raises(RuntimeError, match=r"OSV\.dev query failed"):
            lookup_osv_vulnerabilities("com.example:lib", "1.0.0")
