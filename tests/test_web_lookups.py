"""Unit tests for scanner.web.lookups (backward-compatible facade).

Ensures that functions re-exported from scanner.web.lookups remain fully importable
and functional for existing callers.
"""

from unittest.mock import MagicMock, patch

from scanner.web.lookups import (
    lookup_maven_version,
    lookup_nvd_cve,
    lookup_osv_vulnerabilities,
    resolve_latest_version,
)


def test_lookups_facade_reexports_maven():
    """lookup_maven_version and resolve_latest_version are callable via lookups facade."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = (
        "<metadata><groupId>com.example</groupId><artifactId>lib</artifactId>"
        "<versioning><latest>1.0.0</latest><release>1.0.0</release></versioning></metadata>"
    )
    with patch("requests.get", return_value=mock_resp):
        lookup_res = lookup_maven_version("com.example", "lib")
        resolve_res = resolve_latest_version("com.example", "lib")

    assert "1.0.0" in lookup_res
    assert resolve_res == ("1.0.0", "https://mvnrepository.com/artifact/com.example/lib")


def test_lookups_facade_reexports_osv():
    """lookup_osv_vulnerabilities is callable via lookups facade."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"vulns": []}
    with patch("requests.post", return_value=mock_resp):
        res = lookup_osv_vulnerabilities("com.example:lib", "1.0.0")
    assert "no known vulnerabilities" in res.lower()


def test_lookups_facade_reexports_nvd():
    """lookup_nvd_cve is callable via lookups facade."""
    mock_resp = MagicMock()
    mock_resp.status_code = 404
    with patch("requests.get", return_value=mock_resp):
        res = lookup_nvd_cve("CVE-2024-0000")
    assert "not found" in res.lower()
