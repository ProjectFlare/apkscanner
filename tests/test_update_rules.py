"""Unit tests for the rules database updater module."""

import os
from unittest import mock

from sqlmodel import Session, create_engine, select

from scanner.models import (
    DangerousDomain,
    RuntimePermission,
    TrackerKeyword,
    TrackerSignature,
)
from scanner.util.update_rules import (
    AOSP_MANIFEST_URL,
    EXODUS_TRACKERS_URL,
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
    """Verifies extracting plain text from HTML, including pre and body tags."""
    # Test <pre> extraction
    html_pre = "<html><body><pre>Line 1\nLine 2 &amp; test</pre></body></html>"
    assert _extract_text_from_html(html_pre) == "Line 1\nLine 2 & test"

    # Test <body> fallback without <pre>
    html_body = "<html><body><div>Hello <b>World</b></div></body></html>"
    assert _extract_text_from_html(html_body) == "Hello World"

    # Test raw fallback without <body> or <pre>
    html_raw = "<p>Plain &lt;text&gt;</p>"
    assert _extract_text_from_html(html_raw) == "Plain <text>"


def test_fetch_url_content_direct_success():
    """Verifies direct HTTP request success."""
    mock_resp = mock.MagicMock()
    mock_resp.text = "Sample Content"
    mock_resp.raise_for_status.return_value = None

    with mock.patch("requests.get", return_value=mock_resp) as mock_get:
        content = fetch_url_content("https://example.com/test")
        assert content == "Sample Content"
        mock_get.assert_called_once_with("https://example.com/test", headers=None, timeout=15)


def test_fetch_url_content_scraper_fallback():
    """Verifies fallback to scraper API when direct request fails and scraper is configured."""
    with mock.patch("requests.get", side_effect=Exception("Direct request timed out")):
        with mock.patch("scanner.web.scraper.SCRAPER_URL", "http://localhost:8000"):
            with mock.patch("scanner.web.scraper.get_html", return_value="<pre>Scraped Content</pre>") as mock_scraper:
                content = fetch_url_content("https://example.com/fallback")
                assert content == "Scraped Content"
                mock_scraper.assert_called_once_with("https://example.com/fallback")


def test_fetch_url_content_all_fail():
    """Verifies RuntimeError when both direct request and scraper fallback fail."""
    import pytest

    with mock.patch("requests.get", side_effect=Exception("Direct request failed")):
        with mock.patch("scanner.web.scraper.SCRAPER_URL", "http://localhost:8000"):
            with mock.patch("scanner.web.scraper.get_html", side_effect=Exception("Scraper API failed")):
                with pytest.raises(RuntimeError, match=r"Failed to fetch .* via scraper"):
                    fetch_url_content("https://example.com/fail")

        # Test failure when scraper is not configured
        with mock.patch("scanner.web.scraper.SCRAPER_URL", None):
            with pytest.raises(RuntimeError, match=r"Failed to fetch https://example\.com/fail directly"):
                fetch_url_content("https://example.com/fail")


def test_fetch_dangerous_permissions_success():
    """Verifies parsing of dangerous permissions from AOSP manifest XML."""
    manifest_xml = """<?xml version="1.0" encoding="utf-8"?>
    <manifest xmlns:android="http://schemas.android.com/apk/res/android">
        <permission android:name="android.permission.CAMERA" android:protectionLevel="dangerous" />
        <permission android:name="android.permission.INTERNET" android:protectionLevel="normal" />
        <permission android:name="android.permission.RECORD_AUDIO" android:protectionLevel="dangerous|instant" />
    </manifest>
    """
    with mock.patch("scanner.util.update_rules.fetch_url_content", return_value=manifest_xml) as mock_fetch:
        perms = fetch_dangerous_permissions()
        assert perms == ["android.permission.CAMERA", "android.permission.RECORD_AUDIO"]
        mock_fetch.assert_called_once_with(AOSP_MANIFEST_URL)


def test_fetch_dangerous_permissions_failure():
    """Verifies that an empty list is returned on exception."""
    with mock.patch("scanner.util.update_rules.fetch_url_content", side_effect=RuntimeError("fetch error")):
        perms = fetch_dangerous_permissions()
        assert perms == []


def test_extract_tokens_from_signature():
    """Verifies tokenization and stop-word filtering from signatures."""
    assert _extract_tokens_from_signature("") == []

    sig = "com.google.android.gms.ads.AdActivity;net.tracker.sdk"
    # "com", "google", "android", "sdk" are in IGNORED_TOKENS, len <= 3 discarded
    tokens = _extract_tokens_from_signature(sig)
    assert "adactivity" in tokens
    assert "tracker" in tokens
    assert "google" not in tokens
    assert "sdk" not in tokens


def test_fetch_exodus_trackers_success():
    """Verifies fetching and parsing tracker JSON from Exodus Privacy."""
    import json

    exodus_json = json.dumps(
        {
            "trackers": {
                "1": {
                    "name": "Google AdMob",
                    "code_signature": "com.google.android.gms.ads",
                    "network_signature": "googleads\\.g\\.doubleclick\\.net",
                },
                "2": {
                    "name": "Custom Tracker",
                    "code_signature": "io.custom.tracker",
                    "network_signature": "",
                },
            }
        }
    )

    with mock.patch("scanner.util.update_rules.fetch_url_content", return_value=exodus_json) as mock_fetch:
        keywords, signatures = fetch_exodus_trackers()

        assert "custom" in keywords
        assert "doubleclick" in keywords
        assert len(signatures) == 2
        assert signatures[0]["id"] == "1"
        assert signatures[0]["name"] == "Google AdMob"
        assert signatures[0]["network_signature"] == "googleads\\.g\\.doubleclick\\.net"
        mock_fetch.assert_called_once_with(EXODUS_TRACKERS_URL, headers={"User-Agent": "APKScanner/1.0.0"})


def test_fetch_exodus_trackers_failure():
    """Verifies fallback on Exodus fetch exception."""
    with mock.patch("scanner.util.update_rules.fetch_url_content", side_effect=RuntimeError("tracker error")):
        keywords, signatures = fetch_exodus_trackers()
        assert keywords == []
        assert signatures == []


def test_fetch_urlhaus_domains():
    """Verifies parsing of domains from URLHaus hostfile format."""
    hostfile_data = """
    # URLhaus host file
    # Last updated: 2026-01-01
    127.0.0.1 localhost
    127.0.0.1 malicious.example.com
    0.0.0.0 phishing.net
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
    tracker_sigs = [{"id": "1", "name": "AdMob", "network_signature": "admob.com"}]
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

        domain_res = session.exec(select(DangerousDomain)).first()
        assert domain_res is not None
        assert domain_res.domain == "malicious.org"


def test_update_rules_db_success(tmp_path):
    """Verifies successful compilation and saving of the rules database.

    Ensures rules.db is created, populated correctly, and structured nicely via SQLModel.
    """
    db_file = tmp_path / "rules.db"

    mock_perms = ["android.permission.CAMERA"]
    mock_keywords = ["track"]
    mock_sigs = [{"id": "1", "name": "Tracker", "network_signature": "netsig"}]
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

                    tracker_res = session.exec(select(TrackerSignature)).first()
                    assert tracker_res is not None
                    assert tracker_res.name == "Tracker"


def test_update_rules_db_fallback_missing_perms(tmp_path):
    """Verifies update_rules_db returns False when fetching permissions returns nothing."""
    db_file = tmp_path / "rules.db"

    with mock.patch("scanner.util.update_rules.fetch_dangerous_permissions", return_value=[]):
        success = update_rules_db(str(db_file))
        assert success is False
        assert not os.path.exists(db_file)


def test_update_rules_db_aborts_on_partial_fetch_failure(tmp_path):
    """A failed Exodus or URLHaus fetch must abort BEFORE the old database is deleted, so a
    partial outage never silently replaces good tracker/domain tables with empty ones."""
    db_file = tmp_path / "rules.db"
    db_file.write_bytes(b"previous good database")
    mock_perms = ["android.permission.CAMERA"]

    with mock.patch("scanner.util.update_rules.fetch_dangerous_permissions", return_value=mock_perms):
        with mock.patch("scanner.util.update_rules.fetch_exodus_trackers", return_value=([], [])):
            with mock.patch("scanner.util.update_rules.fetch_urlhaus_domains", return_value=["evil.com"]):
                assert update_rules_db(str(db_file)) is False
        with mock.patch(
            "scanner.util.update_rules.fetch_exodus_trackers",
            return_value=(["track"], [{"id": "1", "name": "T", "network_signature": "n"}]),
        ):
            with mock.patch("scanner.util.update_rules.fetch_urlhaus_domains", return_value=[]):
                assert update_rules_db(str(db_file)) is False

    # The previous database file must remain untouched after both aborted runs.
    assert db_file.read_bytes() == b"previous good database"


def test_load_dynamic_rules_overlays_threat_feeds(tmp_path):
    """Dynamic threat feeds (permissions, trackers, dangerous domains) must overlay
    the static defaults when rules.db is present."""
    from sqlmodel import SQLModel

    import scanner.util.rules as rules_mod
    from scanner.models import DangerousDomain, RuntimePermission, TrackerSignature

    db_file = tmp_path / "rules.db"
    engine = create_engine(f"sqlite:///{db_file}")
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        session.add(RuntimePermission(name="android.permission.NEW_DYNAMIC_PERM"))
        session.add(TrackerKeyword(keyword="dynamic_tracker"))
        session.add(TrackerSignature(id="999", name="DynamicSig", network_signature=r"dynamic\.tracker\.com"))
        session.add(DangerousDomain(domain="dynamic-malware.org"))
        session.commit()

    saved = {
        "RUNTIME_PERMISSIONS": set(rules_mod.RUNTIME_PERMISSIONS),
        "TRACKER_KEYWORDS": list(rules_mod.TRACKER_KEYWORDS),
        "DANGEROUS_DOMAINS": set(rules_mod.DANGEROUS_DOMAINS),
    }
    try:
        rules_mod.load_dynamic_rules(str(db_file))
        assert "android.permission.NEW_DYNAMIC_PERM" in rules_mod.RUNTIME_PERMISSIONS
        assert "dynamic_tracker" in rules_mod.TRACKER_KEYWORDS
        assert "dynamic-malware.org" in rules_mod.DANGEROUS_DOMAINS
        assert any(p.search("https://dynamic.tracker.com/endpoint") for p in rules_mod.TRACKER_SIGNATURE_PATTERNS)
    finally:
        rules_mod.RUNTIME_PERMISSIONS = saved["RUNTIME_PERMISSIONS"]
        rules_mod.TRACKER_KEYWORDS = saved["TRACKER_KEYWORDS"]
        rules_mod.DANGEROUS_DOMAINS = saved["DANGEROUS_DOMAINS"]


def test_update_rules_db_write_error():
    """Verifies graceful handling of database connection or execution failures."""
    mock_perms = ["android.permission.CAMERA"]
    mock_keywords = ["track"]
    mock_sigs = [{"id": "1", "name": "Tracker", "network_signature": "netsig"}]
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
    mock_sigs = [{"id": "1", "name": "Tracker", "network_signature": "netsig"}]
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
    import warnings

    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", category=RuntimeWarning, message=".*found in sys.modules.*")
        with mock.patch("requests.get", side_effect=RuntimeError("mock network disabled")):
            runpy.run_module("scanner.util.update_rules", run_name="__main__")
