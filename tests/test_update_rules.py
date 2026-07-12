"""Unit tests for the rules database updater module.

Verifies page scraping, URL fetching, token/keyword extraction, and rules database generation
using SQLModel ORM.
"""

import os
import unittest.mock as mock

import pytest
import requests
from sqlmodel import Session, create_engine, select

import scanner.util.scraper as scraper
from scanner.models import (
    RuntimePermission,
    TrackerSignature,
)
from scanner.util.update_rules import (
    AOSP_MANIFEST_URL,
    URLHAUS_DOMAINS_URL,
    _extract_text_from_html,
    _extract_tokens_from_signature,
    _populate_db_data,
    fetch_dangerous_permissions,
    fetch_exodus_trackers,
    fetch_url_content,
    fetch_urlhaus_domains,
    update_rules_db,
)


def test_extract_text_from_html():
    """Verifies HTML extractor retrieves plain text content from different wrappers.

    Ensures that <pre> content is extracted, fallback body tag is parsed,
    and fallback tags-stripping works, unescaping HTML entities correctly.
    """
    html_pre = '<html><body><pre style="white-space: pre;">Hello &amp; Welcome</pre></body></html>'
    assert _extract_text_from_html(html_pre) == "Hello & Welcome"

    html_body = "<html><body><p>Hello</p> &lt;World&gt;</body></html>"
    assert _extract_text_from_html(html_body) == "Hello <World>"

    html_raw = "Plain text only"
    assert _extract_text_from_html(html_raw) == "Plain text only"


def test_extract_tokens_from_signature():
    """Verifies that keywords are extracted from code/network signature strings.

    Ensures ignored tokens and short tokens are discarded.
    """
    sig = "com.nonexistentcompany.helper.MyComponent"
    tokens = _extract_tokens_from_signature(sig)
    assert "nonexistentcompany" in tokens
    assert "helper" in tokens
    assert "mycomponent" in tokens
    assert "com" not in tokens
    assert "my" not in tokens

    assert _extract_tokens_from_signature("") == []


def test_fetch_url_content_direct():
    """Verifies fetch_url_content fetches text content directly when successful."""
    mock_response = mock.MagicMock()
    mock_response.text = "raw response text"
    mock_response.status_code = 200

    with mock.patch("requests.get", return_value=mock_response) as mock_get:
        content = fetch_url_content("https://example.com/test", headers={"User-Agent": "Test"})
        assert content == "raw response text"
        mock_get.assert_called_once_with("https://example.com/test", headers={"User-Agent": "Test"}, timeout=15)


def test_fetch_url_content_scraper_fallback():
    """Verifies fetch_url_content falls back to Playwright scraper API on failure.

    Ensures that if the direct request fails and SCRAPER_URL is set, it attempts
    to use the scraper API, converting the HTML wrapper successfully.
    """
    orig_url = scraper.SCRAPER_URL
    scraper.SCRAPER_URL = "http://my-scraper.local"

    try:
        mock_requests_get = mock.MagicMock()
        mock_requests_get.side_effect = requests.RequestException("CF block")

        with mock.patch("requests.get", mock_requests_get):
            with mock.patch(
                "scanner.util.scraper.get_html", return_value="<html><body><pre>scraped data</pre></body></html>"
            ) as mock_get_html:
                content = fetch_url_content("https://example.com/test")
                assert content == "scraped data"
                mock_get_html.assert_called_once_with("https://example.com/test")

        with mock.patch("requests.get", mock_requests_get):
            with mock.patch("scanner.util.scraper.get_html", side_effect=RuntimeError("scraper down")):
                with pytest.raises(RuntimeError, match="Failed to fetch"):
                    fetch_url_content("https://example.com/test")
    finally:
        scraper.SCRAPER_URL = orig_url


def test_fetch_url_content_failure_no_scraper():
    """Verifies fetch_url_content raises RuntimeError when direct request fails and no scraper is configured."""
    orig_url = scraper.SCRAPER_URL
    scraper.SCRAPER_URL = None

    try:
        with mock.patch("requests.get", side_effect=requests.RequestException("Network error")):
            with pytest.raises(RuntimeError, match="Failed to fetch"):
                fetch_url_content("https://example.com/test")
    finally:
        scraper.SCRAPER_URL = orig_url


def test_fetch_dangerous_permissions():
    """Verifies parsing of runtime permissions from the AOSP manifest."""
    xml_data = """<?xml version="1.0" encoding="utf-8"?>
    <manifest xmlns:android="http://schemas.android.com/apk/res/android">
        <permission android:name="android.permission.CAMERA" android:protectionLevel="dangerous" />
        <permission android:name="android.permission.INTERNET" android:protectionLevel="normal" />
        <permission android:name="android.permission.READ_CONTACTS" android:protectionLevel="signature|dangerous" />
    </manifest>
    """
    with mock.patch("scanner.util.update_rules.fetch_url_content", return_value=xml_data) as mock_fetch:
        perms = fetch_dangerous_permissions()
        assert perms == ["android.permission.CAMERA", "android.permission.READ_CONTACTS"]
        mock_fetch.assert_called_once_with(AOSP_MANIFEST_URL)

    with mock.patch("scanner.util.update_rules.fetch_url_content", side_effect=RuntimeError("fetch error")):
        perms = fetch_dangerous_permissions()
        assert perms == []


def test_fetch_exodus_trackers():
    """Verifies fetching and parsing of Exodus tracker signatures."""
    json_data = """{
        "trackers": {
            "1": {
                "name": "Google AdMob",
                "code_signature": "com/google/android/gms/ads",
                "network_signature": "googleads.g.doubleclick.net"
            }
        }
    }"""
    with mock.patch("scanner.util.update_rules.fetch_url_content", return_value=json_data) as mock_fetch:
        keywords, signatures = fetch_exodus_trackers()
        assert "googleads" in keywords
        assert "doubleclick" in keywords
        assert len(signatures) == 1
        assert signatures[0]["name"] == "Google AdMob"
        mock_fetch.assert_called_once()

    with mock.patch("scanner.util.update_rules.fetch_url_content", side_effect=RuntimeError("json fetch error")):
        keywords, signatures = fetch_exodus_trackers()
        assert keywords == []
        assert signatures == []


def test_fetch_urlhaus_domains():
    """Verifies threat intelligence domains fetching and parsing from URLHaus."""
    hostfile_data = """# URLHaus Hostlist
    127.0.0.1   malicious.example.com
    127.0.0.1   phishing.net
    127.0.0.1   localhost
    """
    with mock.patch("scanner.util.update_rules.fetch_url_content", return_value=hostfile_data) as mock_fetch:
        domains = fetch_urlhaus_domains()
        assert domains == ["malicious.example.com", "phishing.net"]
        mock_fetch.assert_called_once_with(URLHAUS_DOMAINS_URL)

    with mock.patch("scanner.util.update_rules.fetch_url_content", side_effect=RuntimeError("hostfile fetch error")):
        domains = fetch_urlhaus_domains()
        assert domains == []


def test_populate_db_data():
    """Verifies population of SQLModel tables using _populate_db_data."""
    from sqlmodel import SQLModel

    engine = create_engine("sqlite:///:memory:")
    SQLModel.metadata.create_all(engine)

    perms = ["android.permission.CAMERA"]
    tracker_keywords = ["admob"]
    tracker_sigs = [{"id": "1", "name": "AdMob", "code_signature": "com/admob", "network_signature": "admob.com"}]
    domains = ["malicious.org"]

    with Session(engine) as session:
        _populate_db_data(session, perms, tracker_keywords, tracker_sigs, domains)
        session.commit()

        # Check values
        perm_res = session.exec(select(RuntimePermission)).first()
        assert perm_res is not None
        assert perm_res.name == "android.permission.CAMERA"

        tracker_sig_res = session.exec(select(TrackerSignature)).first()
        assert tracker_sig_res is not None
        assert tracker_sig_res.name == "AdMob"


def test_update_rules_db_success(tmp_path):
    """Verifies successful compilation and saving of the rules database.

    Ensures rules.db is created, populated correctly, and structured nicely via SQLModel.
    """
    db_file = tmp_path / "rules.db"

    mock_perms = ["android.permission.CAMERA"]
    mock_keywords = ["track"]
    mock_sigs = [{"id": "1", "name": "Tracker", "code_signature": "sig", "network_signature": "netsig"}]
    mock_domains = ["evil.com"]

    with mock.patch("scanner.util.update_rules.fetch_dangerous_permissions", return_value=mock_perms):
        with mock.patch("scanner.util.update_rules.fetch_exodus_trackers", return_value=(mock_keywords, mock_sigs)):
            with mock.patch("scanner.util.update_rules.fetch_urlhaus_domains", return_value=mock_domains):
                success = update_rules_db(str(db_file))
                assert success is True
                assert os.path.exists(db_file)

                # Connect and check data via Session
                engine = create_engine(f"sqlite:///{db_file}")
                with Session(engine) as session:
                    perm_res = session.exec(select(RuntimePermission)).first()
                    assert perm_res is not None
                    assert perm_res.name == "android.permission.CAMERA"


def test_update_rules_db_fallback_missing_perms(tmp_path):
    """Verifies update_rules_db returns False when fetching permissions returns nothing."""
    db_file = tmp_path / "rules.db"

    with mock.patch("scanner.util.update_rules.fetch_dangerous_permissions", return_value=[]):
        success = update_rules_db(str(db_file))
        assert success is False
        assert not os.path.exists(db_file)


def test_update_rules_db_write_error():
    """Verifies graceful handling of database connection or execution failures.

    Checks that update_rules_db catches database exceptions and logs the errors.
    """
    mock_perms = ["android.permission.CAMERA"]
    mock_keywords = ["track"]
    mock_sigs = [{"id": "1", "name": "Tracker", "code_signature": "sig", "network_signature": "netsig"}]
    mock_domains = ["evil.com"]

    with mock.patch("scanner.util.update_rules.fetch_dangerous_permissions", return_value=mock_perms):
        with mock.patch("scanner.util.update_rules.fetch_exodus_trackers", return_value=(mock_keywords, mock_sigs)):
            with mock.patch("scanner.util.update_rules.fetch_urlhaus_domains", return_value=mock_domains):
                success = update_rules_db("/invalid_dir_path_that_does_not_exist/rules.db")
                assert success is False


def test_update_rules_db_remove_existing_fails(tmp_path):
    """Verifies that update_rules_db still proceeds when os.remove fails on an existing file."""
    db_file = tmp_path / "rules.db"
    db_file.touch()

    mock_perms = ["android.permission.CAMERA"]
    mock_keywords = ["track"]
    mock_sigs = [{"id": "1", "name": "Tracker", "code_signature": "sig", "network_signature": "netsig"}]
    mock_domains = ["evil.com"]

    with mock.patch("scanner.util.update_rules.fetch_dangerous_permissions", return_value=mock_perms):
        with mock.patch("scanner.util.update_rules.fetch_exodus_trackers", return_value=(mock_keywords, mock_sigs)):
            with mock.patch("scanner.util.update_rules.fetch_urlhaus_domains", return_value=mock_domains):
                with mock.patch("os.remove", side_effect=OSError("Permission denied")):
                    success = update_rules_db(str(db_file))
                    assert success is True
                    assert os.path.exists(db_file)


def test_main_block():
    """Verifies that the main block executes without errors when imported/run."""
    import runpy

    with mock.patch("requests.get", side_effect=RuntimeError("mock network disabled")):
        runpy.run_module("scanner.util.update_rules", run_name="__main__")
