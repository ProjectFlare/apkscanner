"""Unit tests for the domain extraction and classification scanner module."""

import importlib
from unittest import mock

from scanner.scan_modules.domains import extract_domains, is_tracker_domain


def test_extract_domains():
    """Verifies domain categorization into cloud, trackers, and other."""
    urls = {
        "com.google.firebase": ["https://myproject.firebaseio.com/path", "https://googleapis.com/v1"],
        "com.mixpanel": ["http://api.mixpanel.com/track"],
        "com.example": ["https://mybackend.org/api", "https://schemas.android.com/apk/res/android"],
    }

    result = extract_domains(urls)

    assert "myproject.firebaseio.com" in result["cloud_services"]
    assert "googleapis.com" in result["cloud_services"]
    assert "api.mixpanel.com" in result["trackers_and_ads"]
    assert "mybackend.org" in result["other"]
    # Schemas must be ignored/filtered out
    assert not any("schemas.android.com" in d for category in result.values() for d in category)


def test_extract_domains_edge_cases():
    """Verifies domain extraction handles userinfo, ports, and www prefixes correctly."""
    urls = {
        "com.edge.case": [
            "https://user:password@my-secure-backend.com:8080/path",
            "www.my-web-site.org/index.html",
            "http://localhost:3000/api",
        ]
    }
    result = extract_domains(urls)

    assert "my-secure-backend.com" in result["other"]
    assert "my-web-site.org" in result["other"]
    assert "localhost" in result["other"]


def test_domains_coverage():
    """Verifies all branches, edge cases, and fallback paths in domains module."""
    import scanner.scan_modules.domains as domains_module

    # 1. Test sqlite exception when reloading domains_module
    with mock.patch("sqlite3.connect", side_effect=Exception("mocked sqlite error")):
        importlib.reload(domains_module)

    # 2. Test regex compilation exception
    mock_conn = mock.MagicMock()
    mock_cursor = mock.MagicMock()
    mock_conn.cursor.return_value = mock_cursor
    mock_cursor.fetchone.return_value = ("tracker_signatures",)
    mock_cursor.fetchall.return_value = [("[",)]

    with mock.patch("sqlite3.connect", return_value=mock_conn), mock.patch("os.path.exists", return_value=True):
        importlib.reload(domains_module)

    # 3. Test is_tracker_domain edge cases
    with mock.patch("scanner.scan_modules.domains.TRACKER_KEYWORDS", ["ad", "mixpanel"]):
        # Short kw
        assert is_tracker_domain("example.com") is False
        # Segment match
        assert is_tracker_domain("mixpanel.com") is True
        # Well known tracker substring match
        assert is_tracker_domain("my-mixpanel-tracker.com") is True

    # 4. urlparse raising exception
    with mock.patch("scanner.scan_modules.domains.urlparse", side_effect=Exception("mocked urlparse error")):
        result = extract_domains({"lib": ["http://example.com"]})
    assert result == {"cloud_services": [], "trackers_and_ads": [], "other": []}
