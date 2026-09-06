"""Unit tests for scanner.web.maven.

Covers the Maven version resolution chain (Google Maven, Maven Central metadata,
Solr-index last resort), prerelease filtering, and programmatic prefetching.
"""

from unittest.mock import MagicMock, patch

from scanner.web.maven import (
    _latest_stable,
    lookup_maven_version,
    resolve_latest_version,
)

_MAVEN_METADATA_XML = (
    "<metadata><groupId>com.squareup.okhttp3</groupId><artifactId>okhttp</artifactId>"
    "<versioning><latest>4.12.0</latest><release>4.12.0</release></versioning></metadata>"
)


def test_latest_stable_empty_and_prereleases():
    """_latest_stable returns None for empty input and handles all-prerelease lists."""
    assert _latest_stable([]) is None
    assert _latest_stable(["  ", ""]) is None
    assert _latest_stable(["1.0.0-alpha", "1.0.0-beta"]) == "1.0.0-beta"
    assert _latest_stable(["1.0.0", "2.0.0-alpha"]) == "1.0.0"


def test_resolve_latest_version_google_maven():
    """resolve_latest_version resolves Google Maven libraries directly."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = '<group><credentials versions="1.2.0,1.3.0,1.4.0-alpha01"/></group>'
    with patch("requests.get", return_value=mock_resp):
        res = resolve_latest_version("androidx.credentials", "credentials")
    assert res is not None
    version, source_url = res
    assert version == "1.3.0"
    assert "maven.google.com" in source_url


def test_resolve_latest_version_maven_central():
    """resolve_latest_version falls through to Maven Central metadata."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = _MAVEN_METADATA_XML
    with patch("requests.get", return_value=mock_resp):
        res = resolve_latest_version("com.squareup.okhttp3", "okhttp")
    assert res is not None
    version, source_url = res
    assert version == "4.12.0"
    assert "mvnrepository.com" in source_url


def test_resolve_latest_version_not_found():
    """resolve_latest_version returns None when artifact is not found."""
    mock_resp = MagicMock()
    mock_resp.status_code = 404
    with patch("requests.get", return_value=mock_resp):
        res = resolve_latest_version("com.example.nonexistent", "notfound")
    assert res is None


def test_lookup_maven_version_reads_authoritative_metadata():
    """lookup_maven_version reads the authoritative maven-metadata.xml release version."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = _MAVEN_METADATA_XML
    with patch("requests.get", return_value=mock_resp) as mock_get:
        result = lookup_maven_version("com.squareup.okhttp3", "okhttp")
        requested_urls = [call.args[0] for call in mock_get.call_args_list]
    assert "4.12.0" in result
    assert "Latest version" in result
    # The stale search.maven.org Solr index must not be consulted when the metadata resolves.
    assert any("repo1.maven.org" in url and "maven-metadata.xml" in url for url in requested_urls)
    assert not any("search.maven.org" in url for url in requested_urls)


def test_lookup_maven_version_google_maven_fallback():
    """lookup_maven_version falls through to Maven Central when Google Maven returns nothing."""

    def side_effect(url, **kwargs):
        resp = MagicMock()
        resp.status_code = 200
        # Google Maven call: return an empty group; Maven Central metadata: return valid XML
        if "dl.google.com" in url:
            resp.text = "<group></group>"
        else:
            resp.text = _MAVEN_METADATA_XML.replace("4.12.0", "3.0.0")
        return resp

    with patch("requests.get", side_effect=side_effect):
        result = lookup_maven_version("com.google.mlkit", "okhttp")
    assert "3.0.0" in result


def test_lookup_maven_version_flags_different_group_match():
    """A version found only under a different group is returned with an explicit warning."""

    def side_effect(url, **kwargs):
        resp = MagicMock()
        resp.status_code = 200
        if "search.maven.org" in url:
            resp.json.return_value = {"response": {"docs": [{"latestVersion": "9.9.9", "g": "io.github.other"}]}}
        elif "io/github/other" in url:
            resp.text = _MAVEN_METADATA_XML.replace("4.12.0", "9.9.9")
        else:
            resp.status_code = 404
            resp.text = "not found"
        return resp

    with patch("requests.get", side_effect=side_effect):
        result = lookup_maven_version("com.example.wrong", "okhttp")
    assert "9.9.9" in result
    assert "DIFFERENT group" in result
    assert "io.github.other" in result


def test_lookup_maven_version_skips_prereleases_in_google_index():
    """Google Maven's ascending index often ends with alpha/rc builds; the last STABLE entry
    must be reported so apps on the current stable release are not flagged as outdated."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = '<group><credentials versions="1.5.0,1.6.0-rc01,1.6.0,1.7.0-alpha01,1.7.0-alpha03"/></group>'
    with patch("requests.get", return_value=mock_resp):
        result = lookup_maven_version("androidx.credentials", "credentials")
    assert "1.6.0" in result
    assert "alpha" not in result

    # When ONLY prereleases exist, the newest prerelease is the honest answer.
    mock_resp.text = '<group><credentials versions="1.0.0-alpha01,1.0.0-alpha02"/></group>'
    with patch("requests.get", return_value=mock_resp):
        result = lookup_maven_version("androidx.credentials", "credentials")
    assert "1.0.0-alpha02" in result


def test_lookup_maven_version_replaces_prerelease_release_tag_with_stable():
    """A prerelease <release> value falls back to the newest stable from the version list."""
    metadata = (
        "<metadata><versioning><latest>5.0.0-alpha.14</latest><release>5.0.0-alpha.14</release>"
        "<versions><version>4.11.0</version><version>4.12.0</version>"
        "<version>5.0.0-alpha.14</version></versions></versioning></metadata>"
    )
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = metadata
    with patch("requests.get", return_value=mock_resp) as mock_get:
        result = lookup_maven_version("com.squareup.okhttp3", "okhttp")
        assert any("repo1.maven.org" in call.args[0] for call in mock_get.call_args_list)
    assert "4.12.0" in result
    assert "alpha" not in result


def test_lookup_maven_version_not_found():
    """When no source resolves a version, an explicit not-found message is returned."""
    mock_resp = MagicMock()
    mock_resp.status_code = 404
    mock_resp.text = "not found"
    with patch("requests.get", return_value=mock_resp):
        result = lookup_maven_version("com.example.missing", "nothing")
    assert "Not found" in result
