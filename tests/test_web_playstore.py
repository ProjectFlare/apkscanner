"""Unit tests for scanner.web.playstore.

Covers the Play Store HTML metadata extraction with its markup fallbacks, the
deterministic pre-fetch entry point, and the model-facing tool string formatting.
"""

from unittest.mock import patch

import pytest

from scanner.web.playstore import _extract_play_store_metadata, fetch_play_store_metadata, lookup_play_store

_SAMPLE_PLAY_STORE_HTML = (
    "<html><head><title>EU Login - Apps on Google Play</title></head><body>"
    + "x" * 1500
    + '<a href="/store/apps/dev?id=123"><span>European Union</span></a>'
    + '<div data-g-id="description">The EU Login app provides <br>multi-factor authentication.</div>'
    + "</body></html>"
)


def test_extract_play_store_metadata_uses_title_and_description_fallbacks():
    """Name falls back from the (missing) itemprop span to <title>; description is extracted and cleaned."""
    meta = _extract_play_store_metadata(_SAMPLE_PLAY_STORE_HTML, "eu.europa.ec.ecas")
    assert meta is not None
    # The Play Store title suffix is stripped, leaving the bare app name.
    assert meta["name"] == "EU Login"
    assert meta["developer"] == "European Union"
    # Tags become spaces so <br>-separated words are not glued together.
    assert "multi-factor authentication" in meta["description"]
    assert "provides multi-factor" in meta["description"]
    assert meta["source"].endswith("id=eu.europa.ec.ecas")


def test_extract_play_store_metadata_itemprop_name_and_meta_description():
    """itemprop='name' takes priority and meta tag description fallback works."""
    html = (
        "<html><head><title>Ignored Title</title>"
        '<meta name="description" content="A meta description for the app.">'
        "</head><body>"
        + "x" * 1500
        + '<h1 itemprop="name"><span>Direct App Name</span></h1>'
        + '<a href="/store/apps/developer?id=Google+LLC">Google LLC</a>'
        + "</body></html>"
    )
    meta = _extract_play_store_metadata(html, "com.google.android.app")
    assert meta is not None
    assert meta["name"] == "Direct App Name"
    assert meta["developer"] == "Google LLC"
    assert meta["description"] == "A meta description for the app."


def test_extract_play_store_metadata_itemprop_description_container():
    """itemprop='description' on a div container extracts multiline text cleanly."""
    html = (
        "<html><head><title>My App - Google Play</title></head><body>"
        + "x" * 1500
        + '<div itemprop="description"><p>First paragraph.</p><p>Second paragraph.</p></div>'
        + "</body></html>"
    )
    meta = _extract_play_store_metadata(html, "com.example.myapp")
    assert meta is not None
    assert meta["name"] == "My App"
    assert meta["description"] == "First paragraph. Second paragraph."


def test_extract_play_store_metadata_returns_none_for_not_found():
    """A 404 / too-small page yields None so the app is treated as not listed."""
    assert _extract_play_store_metadata("<html>tiny</html>", "com.x") is None
    assert _extract_play_store_metadata("We're sorry, the requested URL was not found" + "y" * 2000, "com.x") is None


def test_fetch_play_store_metadata_returns_none_on_scraper_failure():
    """The deterministic pre-fetch swallows scraper errors and returns None instead of raising."""
    with patch("scanner.web.playstore.get_html", side_effect=RuntimeError("scraper down")):
        assert fetch_play_store_metadata("com.example.app") is None
    # An empty package id short-circuits without any network call.
    assert fetch_play_store_metadata("") is None


def test_lookup_play_store_formats_from_extracted_metadata():
    """The model-facing tool string is built from the structured extraction, including the source line."""
    with patch("scanner.web.playstore.get_html", return_value=_SAMPLE_PLAY_STORE_HTML):
        result = lookup_play_store("eu.europa.ec.ecas")
    assert "App Name: EU Login" in result
    assert "Developer: European Union" in result
    assert "Source: https://play.google.com/store/apps/details?id=eu.europa.ec.ecas" in result


def test_lookup_play_store_reports_unlisted_app():
    """A not-found page yields an explicit 'not found' tool string instead of raising."""
    with patch("scanner.web.playstore.get_html", return_value="<html>tiny</html>"):
        result = lookup_play_store("com.missing.app")
    assert "not found" in result.lower()


def test_lookup_play_store_raises_on_scraper_failure():
    """The model-facing tool propagates scraper failures for the retry layer to handle."""
    with patch("scanner.web.playstore.get_html", side_effect=RuntimeError("scraper down")):
        with pytest.raises(RuntimeError, match="Play Store scrape failed"):
            lookup_play_store("com.fail.app")
