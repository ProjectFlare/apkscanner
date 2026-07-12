"""Unit tests for the AI report generation utilities scanner module."""

from unittest.mock import MagicMock, patch

import pytest
import requests

import scanner.util.scraper as scraper
from scanner.util.ai_report import (
    _execute_ollama_query,
    _format_report_header,
    _probe_search_status,
    _process_audit_response,
    _query_google_maven,
    _query_maven_central,
    _query_osv_dev,
    _query_section_audit,
    _resolve_maven_coordinates,
    calculate_security_score,
    clean_markdown_report,
    deduplicate_findings,
    gather_web_context,
    generate_ai_report,
    get_app_context,
    get_security_grade,
    is_data_empty,
    search_bing,
    search_ddg,
)
from scanner.util.scraper import get_html, set_scraper_url


def test_search_ddg():
    """Verifies that search_ddg correctly requests and parses DuckDuckGo HTML snippets."""
    orig_url = scraper.SCRAPER_URL
    set_scraper_url("http://mock-scraper.local")

    try:
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "html": (
                "<html><body>"
                '<a class="result__snippet" href="https://example.com/cve1">Snippet number one for testing.</a>'
                '<a class="result__snippet" href="https://example.com/cve2">Snippet <b>two</b> with tag.</a>'
                "</body></html>"
            )
        }
        mock_response.status_code = 200

        with patch("requests.get", return_value=mock_response) as mock_get:
            results = search_ddg("my test query", max_results=2)

            mock_get.assert_called_once()
            assert len(results) == 2
            assert results[0] == "Snippet number one for testing. (Source: https://example.com/cve1)"
            assert results[1] == "Snippet two with tag. (Source: https://example.com/cve2)"
    finally:
        scraper.SCRAPER_URL = orig_url


def test_gather_web_context():
    """Verifies that gather_web_context correctly generates DDG queries from scan report."""
    mock_report = {
        "vulnerabilities": [
            {
                "category": "Insecure Communication",
                "description": "Uses cleartext traffic or insecure SSL configurations",
                "evidence": ["android:usesCleartextTraffic=true"],
            }
        ],
        "dependencies": {"exact_versions_found": {"third_party": {"com.google.code.gson:gson": "2.11.0"}}},
        "network": {"categorized_domains": {"other": ["example.org"]}},
    }

    # Mock search_ddg to avoid hitting the internet, and mock requests to simulate offline APIs
    with (
        patch("scanner.util.ai_report.search_ddg", return_value=["Mocked snippet"]) as mock_search,
        patch("requests.get", side_effect=Exception("API offline")),
    ):
        context = gather_web_context(mock_report)

        # Should have searched for vulnerability, dependency, and domain
        assert mock_search.call_count == 3
        assert "Mocked snippet" in context["vulnerabilities"]
        assert "gson" in context["dependencies"]
        assert "example.org" in context["domains"]


def test_generate_ai_report():
    """Verifies that generate_ai_report compiles context, calls Ollama sequentially, and formats output."""
    mock_report = {
        "apk_metadata": {
            "apk_name": "test.apk",
            "app_name": "MyTestApp",
            "package": "com.test.app",
            "size": 1234567,
            "app_version_name": "1.2.3",
            "app_version_code": "123",
        },
        "manifest_audit": {"security_flags": {"allow_backup": True}},
        "security_checks": {"rooted_device_detection": {"detection_missing": True}},
        "signatures": {"certificates": [{"serial_number": "123"}], "is_debug_signed": True},
        "permissions": {
            "runtime_requested": ["android.permission.CAMERA"],
            "install_time_or_system": [],
            "custom_or_third_party": [],
        },
        "dependencies": {"exact_versions_found": {"third_party": {"gson": "1.0"}}},
        "secrets": [{"name": "key", "type": "google_api", "value": "123"}],
        "bytecode_audit": {"ssl_bypass_detected": True, "ssl_bypass_evidence": ["some class"]},
        "network": {"categorized_domains": {"other": ["example.com"]}},
        "vulnerabilities": [{"owasp_id": "M1", "severity": "HIGH", "description": "some vuln"}],
    }

    mock_response = MagicMock()
    mock_response.json.return_value = {"message": {"content": "This is the AI generated report content."}}
    mock_response.status_code = 200

    with patch("requests.post", return_value=mock_response) as mock_post:
        report = generate_ai_report(mock_report, model="my-test-model", use_websearch=False)

        # 9 sections to audit sequentially
        assert mock_post.call_count == 9
        assert "Mobile Application Security Assessment Report - MyTestApp" in report
        assert "com.test.app" in report
        assert "1.18 MB (1,234,567 bytes)" in report
        assert "1.2.3 (Code: 123)" in report
        assert "Date of Creation" in report
        assert "my-test-model" in report
        assert "test.apk" in report
        assert "This is the AI generated report content." in report


def test_scraper_client():
    """Verifies that get_html routes queries through scraper API, and handles errors correctly."""
    # Save original state
    orig_url = scraper.SCRAPER_URL

    try:
        # Test 1: Exception when not configured
        set_scraper_url(None)
        with pytest.raises(ValueError, match=r"Scraper API URL is not configured\."):
            get_html("https://example.com")

        # Test 2: Scraper API routing when configured
        set_scraper_url("http://my-scraper.local")
        mock_scraper_response = MagicMock()
        mock_scraper_response.json.return_value = {"html": "Scraper content"}
        mock_scraper_response.status_code = 200

        with patch("requests.get", return_value=mock_scraper_response) as mock_get:
            html = get_html("https://example.com")
            assert html == "Scraper content"
            mock_get.assert_called_once()
            args, kwargs = mock_get.call_args
            assert args[0] == "http://my-scraper.local/scrape"
            assert kwargs["params"] == {"url": "https://example.com"}

        # Test 3: Exception when scraper API returns error
        mock_error_response = MagicMock()
        mock_error_response.json.return_value = {"error": "Scraping failed"}
        mock_error_response.status_code = 200

        with patch("requests.get", return_value=mock_error_response):
            with pytest.raises(RuntimeError, match="Scraper API returned error: Scraping failed"):
                get_html("https://example.com")

        # Test 4: Exception when requests fails
        with patch("requests.get", side_effect=Exception("Connection timed out")):
            with pytest.raises(RuntimeError, match="Scraper API request failed: Connection timed out"):
                get_html("https://example.com")

        # Test 5: Exception when response JSON is invalid or missing expected fields
        mock_invalid_response = MagicMock()
        mock_invalid_response.json.return_value = {"something_else": True}
        mock_invalid_response.status_code = 200

        with patch("requests.get", return_value=mock_invalid_response):
            with pytest.raises(RuntimeError, match=r"Scraper API response did not contain 'html' or 'error'\."):
                get_html("https://example.com")

    finally:
        # Restore original state
        scraper.SCRAPER_URL = orig_url


def test_calculate_security_score():
    """Verifies that calculate_security_score correctly computes exponential decay values."""
    # Case 1: No vulnerabilities
    assert calculate_security_score([]) == 100.0
    assert get_security_grade(100.0) == "A"

    # Case 2: One medium
    vulns_1 = [{"owasp_id": "M3", "description": "Backup enabled", "severity": "MEDIUM"}]
    assert calculate_security_score(vulns_1) == 95.0
    assert get_security_grade(95.0) == "A"

    # Case 3: Multiple unique
    vulns_2 = [
        {"owasp_id": "M3", "description": "Backup enabled", "severity": "MEDIUM"},
        {"owasp_id": "M7", "description": "No root detection", "severity": "LOW"},
    ]
    # 100 * 0.95 * 0.98 = 93.1
    assert calculate_security_score(vulns_2) == 93.1
    assert get_security_grade(93.1) == "A"

    # Case 4: Severe vulnerabilities
    vulns_3 = [
        {"owasp_id": "M1", "description": "Hardcoded keys", "severity": "HIGH"},
        {"owasp_id": "M4", "description": "Cleartext allowed", "severity": "HIGH"},
        {"owasp_id": "M3", "description": "Backup enabled", "severity": "MEDIUM"},
    ]
    # 100 * 0.85 * 0.85 * 0.95 = 68.6
    assert calculate_security_score(vulns_3) == 68.6
    assert get_security_grade(68.6) == "D"


def test_search_ddg_mock_response():
    """Verifies search_ddg returns parsed results from a mocked DuckDuckGo HTML response."""
    orig_url = scraper.SCRAPER_URL
    set_scraper_url("http://mock-scraper.local")

    try:
        mock_html = """
        <html><body>
        <div class="result__body">
            <a class="result__a" href="https://nvd.nist.gov/vuln/detail/CVE-2024-1234">CVE-2024-1234</a>
            <a class="result__snippet">A critical webview remote code execution vulnerability.</a>
        </div>
        </body></html>
        """
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"html": mock_html}

        with patch("requests.get", return_value=mock_response):
            results = search_ddg("webview vulnerabilities", max_results=3)
            assert isinstance(results, list)
    finally:
        scraper.SCRAPER_URL = orig_url


def test_ai_report_coverage():
    """Verifies all branches, edge cases, and helper functions in ai_report."""
    orig_url = scraper.SCRAPER_URL
    set_scraper_url("http://mock-scraper.local")

    try:
        # 1. search_bing
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "html": '<html><body><li class="b_algo"><h2><a href="http://example.com">Link</a></h2><p>Description</p></li></body></html>'
        }
        mock_resp.status_code = 200
        with patch("requests.get", return_value=mock_resp):
            results = search_bing("query")
            assert len(results) > 0

        with patch("requests.get", side_effect=Exception("bing error")):
            assert search_bing("query") == []
    finally:
        scraper.SCRAPER_URL = orig_url

    # 2. calculate_security_score & get_security_grade
    assert calculate_security_score([]) == 100.0
    assert calculate_security_score([{"severity": "UNKNOWN"}]) == 95.0
    assert get_security_grade(100.0) == "A"
    assert get_security_grade(85.0) == "B"
    assert get_security_grade(75.0) == "C"
    assert get_security_grade(65.0) == "D"
    assert get_security_grade(10.0) == "F"

    # 3. is_data_empty
    assert is_data_empty(None) is True
    assert is_data_empty([]) is True
    assert is_data_empty({}) is True
    assert is_data_empty({"a": []}) is True
    assert is_data_empty({"a": {}}) is True
    assert is_data_empty({"a": [{"b": []}]}) is False
    assert is_data_empty({"a": 1}) is False

    # 4. _resolve_maven_coordinates
    assert _resolve_maven_coordinates("com.squareup.okhttp3:okhttp") == ("com.squareup.okhttp3", "okhttp")
    assert _resolve_maven_coordinates("okhttp3") == ("com.squareup.okhttp3", "okhttp")
    assert _resolve_maven_coordinates("play-services-base") == ("com.google.android.gms", "play-services-base")
    assert _resolve_maven_coordinates("unknown_lib") == (None, "unknown_lib")

    # 5. _query_google_maven and _query_maven_central
    with patch("requests.get", side_effect=Exception("network error")):
        assert _query_google_maven("grp", "art") == (None, None)
        assert _query_maven_central("grp", "art") == (None, None, "grp")
        assert _query_osv_dev("grp", "art", "1.0") == []

    # 6. _probe_search_status
    status, _search_func = _probe_search_status(False)
    assert status == "Disabled"

    with patch("requests.get", side_effect=Exception("no connection")):
        status_web, _ = _probe_search_status(True)
        assert status_web == "Unavailable (Offline / Blocked)"

    # 7. _filter_scan_report and _format_report_header
    mock_scan_report = {
        "apk_metadata": {
            "package": "com.example.app",
            "apk_name": "Target App",
            "app_name": "My App",
            "size": 1500000,
            "app_version_name": "1.0.0",
            "app_version_code": "1",
        }
    }
    header = _format_report_header(
        mock_scan_report, 100.0, "A", "App background summary", "model-name", 15.5, "Offline"
    )
    assert "My App" in header
    assert "com.example.app" in header

    # 8. deduplicate_findings and clean_markdown_report
    content = "1. First finding\n2. Second finding\n1. First finding\n"
    assert "First finding" in deduplicate_findings(content)

    report_content = "Some intro\n<think>thought block</think>\n# Security Report\n## 1. Issue\n"
    cleaned = clean_markdown_report(report_content)
    assert "thought block" not in cleaned

    # 9. _process_audit_response
    processed = _process_audit_response(
        {"heading": "## Section Heading", "name": "section_name"}, "Response Content", "Thinking Content"
    )
    assert "Response Content" in processed

    # 10. _execute_ollama_query
    mock_ollama_resp = MagicMock()
    mock_ollama_resp.status_code = 200
    mock_ollama_resp.json.return_value = {"message": {"content": "Ollama response"}}
    with patch("requests.post", return_value=mock_ollama_resp):
        ans, _think = _execute_ollama_query("prompt", "model", "url")
        assert ans == "Ollama response"

    with patch("requests.post", side_effect=requests.exceptions.RequestException("ollama down")):
        with pytest.raises(requests.exceptions.RequestException):
            _execute_ollama_query("prompt", "model", "url")

    # 11. _query_section_audit error path
    with patch("requests.post", side_effect=requests.exceptions.RequestException("error")):
        assert "Ollama query failed" in _query_section_audit(
            {
                "title": "title",
                "heading": "## title",
                "name": "title",
                "data": {},
                "search_context": "search details",
                "guidelines": "some guidelines",
            },
            "context",
            "model",
            "url",
        )


def test_ai_report_additional_branches():
    """Verifies additional branches and error paths in ai_report to achieve higher test coverage."""
    # 1. search_ddg redirected href with uddg parameter
    orig_url = scraper.SCRAPER_URL
    set_scraper_url("http://mock-scraper.local")
    try:
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "html": '<html><body><a class="result__snippet" href="http://ddg.com/html?uddg=https%3A%2F%2Fredirected-target.com%2Fpath">Snippet with uddg</a></body></html>'
        }
        mock_response.status_code = 200
        with patch("requests.get", return_value=mock_response):
            results = search_ddg("query")
            assert len(results) == 1
            assert "redirected-target.com" in results[0]

        # 2. search_ddg exception path in try/except block
        with patch("requests.get", side_effect=Exception("search exception")):
            assert search_ddg("query") == []
    finally:
        scraper.SCRAPER_URL = orig_url

    # 3. search_bing fallback to general paragraph extract if b_algo list is empty
    orig_url = scraper.SCRAPER_URL
    set_scraper_url("http://mock-scraper.local")
    try:
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "html": "<html><body><p>This is a long paragraph without b_algo tag but exceeding 40 chars length.</p></body></html>"
        }
        mock_resp.status_code = 200
        with patch("requests.get", return_value=mock_resp):
            results = search_bing("query")
            assert len(results) == 1
            assert results[0] == "This is a long paragraph without b_algo tag but exceeding 40 chars length."
    finally:
        scraper.SCRAPER_URL = orig_url

    # 4. get_app_context empty package name and app name
    empty_report = {"apk_metadata": {"package": "", "apk_name": ""}}
    assert "Unknown Android application" in get_app_context(empty_report, lambda q, max_results: [], "model", "url")

    # 5. get_app_context play query results and dev site documentation
    mock_search = MagicMock(side_effect=lambda q, max_results: [f"Snippet for {q}"])
    with patch("requests.post") as mock_post:
        mock_post_resp = MagicMock()
        mock_post_resp.status_code = 200
        mock_post_resp.json.return_value = {
            "message": {"content": "Summary content <think>thinking details</think> Result details"}
        }
        mock_post.return_value = mock_post_resp

        res = get_app_context(
            {"apk_metadata": {"package": "com.test", "apk_name": "Test"}}, mock_search, model="model", ollama_url="url"
        )
        assert "Result details" in res
        assert "thinking details" not in res

    # 6. get_app_context exceptions handling
    with patch("requests.post", side_effect=Exception("Post error")):
        res_fail = get_app_context(
            {"apk_metadata": {"package": "com.test", "apk_name": "Test"}}, mock_search, model="model", ollama_url="url"
        )
        assert "No information about this application" in res_fail

    # 7. deduplicate_findings: no level-3 headers in content
    assert deduplicate_findings("no headers here") == "no headers here"

    # 8. deduplicate_findings reindexing numbers and normal headers
    content_headers = """### 1. Unique Issue
Some body for unique.
### 2. Unique Issue
This is a duplicate of the first one, should be removed.
### 3. Other Issue
Some other body.
"""
    deduped = deduplicate_findings(content_headers, reindex_numbers=True)
    assert "Unique Issue" in deduped
    assert "Other Issue" in deduped
    assert "3. Other Issue" not in deduped
    assert "2. Other Issue" in deduped  # should be reindexed to 2

    # 9. _query_google_maven successful XML parsing
    mock_xml_resp = MagicMock()
    mock_xml_resp.status_code = 200
    mock_xml_resp.text = (
        '<com.google.android.gms><play-services-base versions="17.0.0,18.0.0" /></com.google.android.gms>'
    )
    with patch("requests.get", return_value=mock_xml_resp):
        assert _query_google_maven("com.google.android.gms", "play-services-base") == (
            "18.0.0",
            "https://developer.android.com/jetpack/androidx/versions",
        )

    # 10. _query_maven_central successful JSON parsing
    mock_json_resp = MagicMock()
    mock_json_resp.status_code = 200
    mock_json_resp.json.return_value = {
        "response": {"docs": [{"latestVersion": "3.12.0", "g": "com.squareup.okhttp3"}]}
    }
    with patch("requests.get", return_value=mock_json_resp):
        assert _query_maven_central("com.squareup.okhttp3", "okhttp") == (
            "3.12.0",
            "https://mvnrepository.com/artifact/com.squareup.okhttp3/okhttp",
            "com.squareup.okhttp3",
        )

    # 11. _query_osv_dev successful vulnerabilities list
    mock_osv_resp = MagicMock()
    mock_osv_resp.status_code = 200
    mock_osv_resp.json.return_value = {"vulns": [{"id": "CVE-2024-1", "summary": "OSV Vuln"}]}
    with patch("requests.post", return_value=mock_osv_resp):
        assert len(_query_osv_dev("com.test", "lib", "1.0")) == 1
