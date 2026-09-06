"""Unit tests for scanner.web.nvd.

Covers NVD/NIST REST API integration, CVSS v3.1 and v3.0 metric extraction,
CWE weakness extraction, 404 responses, and network error handling.
"""

from unittest.mock import MagicMock, patch

import pytest

from scanner.web.nvd import _extract_cvss_metrics, _extract_cwes, lookup_nvd_cve


def test_extract_cvss_metrics_v31_and_v30():
    """_extract_cvss_metrics correctly prioritizes v3.1 over v3.0 metrics."""
    metrics_v31 = {
        "cvssMetricV31": [
            {
                "cvssData": {
                    "baseScore": 9.8,
                    "baseSeverity": "CRITICAL",
                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                }
            }
        ]
    }
    assert _extract_cvss_metrics(metrics_v31) == (
        "9.8",
        "CRITICAL",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    )

    metrics_v30 = {
        "cvssMetricV30": [
            {
                "cvssData": {
                    "baseScore": 7.5,
                    "baseSeverity": "HIGH",
                    "vectorString": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                }
            }
        ]
    }
    assert _extract_cvss_metrics(metrics_v30) == (
        "7.5",
        "HIGH",
        "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    )

    assert _extract_cvss_metrics({}) is None


def test_extract_cwes():
    """_extract_cwes extracts English CWE identifiers from weaknesses structures."""
    weaknesses = [
        {
            "description": [
                {"lang": "es", "value": "CWE-Spanish"},
                {"lang": "en", "value": "CWE-89"},
            ]
        },
        {"description": [{"lang": "en", "value": "CWE-79"}]},
    ]
    assert _extract_cwes(weaknesses) == ["CWE-89", "CWE-79"]
    assert _extract_cwes([]) == []


def test_lookup_nvd_cve_found():
    """lookup_nvd_cve returns CVSS v3 score, severity, vector, and CWE."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "vulnerabilities": [
            {
                "cve": {
                    "published": "2024-01-01",
                    "lastModified": "2024-02-01",
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "cvssData": {
                                    "baseScore": 9.8,
                                    "baseSeverity": "CRITICAL",
                                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                }
                            }
                        ]
                    },
                    "weaknesses": [{"description": [{"lang": "en", "value": "CWE-89"}]}],
                }
            }
        ]
    }
    with patch("requests.get", return_value=mock_resp):
        result = lookup_nvd_cve("CVE-2024-9999")

    assert "9.8" in result
    assert "CRITICAL" in result
    assert "CWE-89" in result
    assert "nvd.nist.gov" in result


def test_lookup_nvd_cve_without_cvss_metrics():
    """lookup_nvd_cve formats cleanly when CVSS metrics are absent."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "vulnerabilities": [
            {
                "cve": {
                    "published": "2024-01-01",
                    "lastModified": "2024-02-01",
                    "metrics": {},
                    "weaknesses": [],
                }
            }
        ]
    }
    with patch("requests.get", return_value=mock_resp):
        result = lookup_nvd_cve("CVE-2024-0001")

    assert "CVSS v3: Not available in NVD." in result
    assert "CVE: CVE-2024-0001" in result


def test_lookup_nvd_cve_not_found_404():
    """lookup_nvd_cve returns a not-found message on a 404 response."""
    mock_resp = MagicMock()
    mock_resp.status_code = 404
    with patch("requests.get", return_value=mock_resp):
        result = lookup_nvd_cve("CVE-0000-9999")
    assert "not found" in result.lower()


def test_lookup_nvd_cve_empty_vulns_list():
    """lookup_nvd_cve returns not-found when vulnerabilities array is empty."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"vulnerabilities": []}
    with patch("requests.get", return_value=mock_resp):
        result = lookup_nvd_cve("CVE-0000-0000")
    assert "not found in nvd" in result.lower()


def test_lookup_nvd_cve_non_200_raises():
    """lookup_nvd_cve raises on non-200 / non-404 status codes."""
    mock_resp = MagicMock()
    mock_resp.status_code = 503
    with patch("requests.get", return_value=mock_resp):
        with pytest.raises(RuntimeError, match="NVD API returned HTTP 503"):
            lookup_nvd_cve("CVE-2024-1234")


def test_lookup_nvd_cve_network_exception_raises():
    """lookup_nvd_cve raises on request exceptions."""
    with patch("requests.get", side_effect=Exception("Timeout")):
        with pytest.raises(RuntimeError, match="NVD API query failed"):
            lookup_nvd_cve("CVE-2024-1234")
