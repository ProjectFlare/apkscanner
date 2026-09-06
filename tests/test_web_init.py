"""Unit tests for scanner.web package exports.

Verifies that __all__ defines all public entry points and that they are directly
accessible from the scanner.web namespace.
"""

import scanner.web


def test_web_package_exports():
    """scanner.web exports all primary web functions in __all__."""
    expected_exports = [
        "SearchBlockedError",
        "fetch_play_store_metadata",
        "get_html",
        "lookup_maven_version",
        "lookup_nvd_cve",
        "lookup_osv_vulnerabilities",
        "lookup_play_store",
        "resolve_latest_version",
        "search_ddg",
        "set_scraper_url",
    ]
    for export in expected_exports:
        assert export in scanner.web.__all__
        assert hasattr(scanner.web, export)
        assert getattr(scanner.web, export) is not None
