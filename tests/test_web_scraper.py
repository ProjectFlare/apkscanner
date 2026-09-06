"""Unit tests for scanner.web.scraper.

Covers scraper API URL configuration and the HTML fetching helper, including
error handling for unconfigured URLs, API error responses, and network exceptions.
"""

from unittest.mock import MagicMock, patch

import pytest
import requests

from scanner.web import scraper
from scanner.web.scraper import get_html, set_scraper_url


def test_set_scraper_url():
    """set_scraper_url strips trailing slashes and handles None correctly."""
    set_scraper_url("http://localhost:3000/")
    assert scraper.SCRAPER_URL == "http://localhost:3000"

    set_scraper_url("http://localhost:3000")
    assert scraper.SCRAPER_URL == "http://localhost:3000"

    set_scraper_url(None)
    assert scraper.SCRAPER_URL is None


def test_get_html_raises_when_unconfigured():
    """get_html raises ValueError when SCRAPER_URL is not set."""
    set_scraper_url(None)
    with pytest.raises(ValueError, match="Scraper API URL is not configured"):
        get_html("https://example.com")


def test_get_html_success():
    """get_html returns raw HTML on successful scraper response."""
    set_scraper_url("http://localhost:3000")
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"html": "<html><body>Success</body></html>"}

    with patch("requests.get", return_value=mock_resp) as mock_get:
        html = get_html("https://example.com/page")

    assert "Success" in html
    mock_get.assert_called_once_with(
        "http://localhost:3000/scrape",
        params={"url": "https://example.com/page"},
        timeout=60.0,
    )


def test_get_html_raises_on_scraper_api_error_message():
    """get_html raises RuntimeError when scraper API reports an error."""
    set_scraper_url("http://localhost:3000")
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"error": "Page load timed out"}

    with patch("requests.get", return_value=mock_resp):
        with pytest.raises(RuntimeError, match="Page load timed out"):
            get_html("https://example.com/timeout")


def test_get_html_raises_on_invalid_payload():
    """get_html raises RuntimeError when response contains neither html nor error."""
    set_scraper_url("http://localhost:3000")
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"unexpected": "data"}

    with patch("requests.get", return_value=mock_resp):
        with pytest.raises(RuntimeError, match="did not contain 'html' or 'error'"):
            get_html("https://example.com/bad-json")


def test_get_html_raises_on_http_or_network_failure():
    """get_html wraps request exceptions in RuntimeError."""
    set_scraper_url("http://localhost:3000")
    with patch("requests.get", side_effect=requests.exceptions.ConnectionError("Connection refused")):
        with pytest.raises(RuntimeError, match="Scraper API request failed"):
            get_html("https://example.com/fail")
