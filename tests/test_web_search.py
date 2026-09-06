"""Unit tests for scanner.web.search.

Covers bot-check detection, redirect unwrapping, organic-result parsing with its
structural fallbacks, allowlist filtering, the randomized search throttle, and
the search_ddg entry point.
"""

from unittest.mock import patch

import pytest

from scanner.web.search import (
    SEARCH_DELAY_RANGE_SECONDS,
    SearchBlockedError,
    _is_organic,
    _throttle_search,
    _unwrap_redirect,
    detect_block,
    host_allowed,
    parse_results,
    search_ddg,
)

_DDG_RESULT_HTML = """
<html><body>
<div class="serp__results">
  <div class="result results_links results_links_deep web-result">
    <div class="result__body">
      <h2 class="result__title">
        <a class="result__a" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fdeveloper.android.com%2Ftarget&amp;rut=abc">Vulnerability Info</a>
      </h2>
      <a class="result__snippet" href="#">OkHttp versions before 4.9.2 are vulnerable to leaks.</a>
    </div>
  </div>
  <div class="result result--ad">
    <div class="result__body">
      <a class="result__a" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fportswigger.net%2Fsponsored">Sponsored Result</a>
      <a class="result__snippet" href="#">Buy our product.</a>
    </div>
  </div>
  <div class="result">
    <div class="result__body">
      <a class="result__a" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.com%2Fspam">Untrusted</a>
      <a class="result__snippet" href="#">Unverified claim.</a>
    </div>
  </div>
  <div class="result">
    <div class="result__body">
      <a class="result__a" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fdeveloper.android.com%2Ftarget">Duplicate Of First</a>
    </div>
  </div>
</div>
</body></html>
"""


def test_detect_block_finds_marker():
    """A bot-check page is recognised by its marker text."""
    assert detect_block("<html><body>Unusual traffic detected, are you a robot?</body></html>") is not None
    assert detect_block("<html><body>please solve this CAPTCHA</body></html>") == "captcha"


def test_detect_block_clean_page_returns_none():
    """A regular result page contains no block marker."""
    assert detect_block(_DDG_RESULT_HTML) is None


def test_unwrap_redirect_resolves_uddg_target():
    """The /l/?uddg= redirect is decoded back to the real target URL."""
    href = "//duckduckgo.com/l/?uddg=https%3A%2F%2Fdeveloper.android.com%2Fdocs&rut=xyz"
    assert _unwrap_redirect(href) == "https://developer.android.com/docs"


def test_unwrap_redirect_leaves_plain_urls_untouched():
    """A non-redirect URL passes through unchanged."""
    assert _unwrap_redirect("https://snyk.io/vuln/1") == "https://snyk.io/vuln/1"


def test_is_organic_rejects_ddg_internal_links():
    """DuckDuckGo-internal navigation is not an organic result."""
    assert _is_organic("https://developer.android.com/x")
    assert not _is_organic("https://duckduckgo.com/settings")
    assert not _is_organic("relative/path")


def test_parse_results_extracts_organic_results():
    """Organic results are unwrapped, ads skipped, and duplicates dropped."""
    results = parse_results(_DDG_RESULT_HTML)
    urls = [r["url"] for r in results]

    assert "https://developer.android.com/target" in urls
    assert "https://example.com/spam" in urls
    # The sponsored block shares the organic link class but must be skipped.
    assert "https://portswigger.net/sponsored" not in urls
    # The duplicate URL appears only once.
    assert urls.count("https://developer.android.com/target") == 1

    first = results[0]
    assert first["title"] == "Vulnerability Info"
    assert first["domain"] == "developer.android.com"
    assert "OkHttp versions before 4.9.2" in (first["snippet"] or "")


def test_parse_results_falls_back_on_redirect_signature():
    """A renamed result link class still yields results via the /l/?uddg= fallback."""
    html = _DDG_RESULT_HTML.replace("result__a", "renamed__link")
    results = parse_results(html)
    urls = [r["url"] for r in results]
    assert "https://developer.android.com/target" in urls


def test_parse_results_empty_page():
    """A page without results parses to an empty list without raising."""
    assert parse_results("<html><body><p>No results.</p></body></html>") == []


def test_host_allowed_matches_and_rejects():
    """host_allowed accepts allowlisted domains and subdomains, rejects everything else."""
    # Exact registrable domain and subdomains are accepted.
    assert host_allowed("https://reuters.com/world/article")
    assert host_allowed("https://www.bbc.co.uk/news")
    assert host_allowed("https://security.snyk.io/vuln/1")  # subdomain of snyk.io
    assert host_allowed("https://developer.android.com/privacy")
    # Untrusted hosts are rejected.
    assert not host_allowed("https://example.com/x")
    assert not host_allowed("https://evil-reuters.com/x")  # not a subdomain of reuters.com
    # Tool-handled domains are deliberately excluded from the search allowlist.
    assert not host_allowed("https://play.google.com/store/apps/details?id=x")
    assert not host_allowed("https://osv.dev/vulnerability/GHSA-1")
    assert not host_allowed("https://nvd.nist.gov/vuln/detail/CVE-2024-1")
    # Empty, relative, or unparseable URLs are rejected without raising.
    assert not host_allowed("")
    assert not host_allowed("/relative/path")


def test_host_allowed_custom_allowlist():
    """host_allowed honours an explicit allowlist argument."""
    assert host_allowed("https://foo.test/x", {"foo.test"})
    assert not host_allowed("https://foo.test/x", {"bar.test"})


def test_search_ddg_filters_to_allowlisted_sources():
    """search_ddg returns formatted snippets for allowlisted hosts only."""
    with (
        patch("scanner.web.search._throttle_search"),
        patch("scanner.web.search.get_html", return_value=_DDG_RESULT_HTML),
    ):
        res = search_ddg("okhttp leak")

    assert len(res) == 1
    assert "Vulnerability Info" in res[0]
    assert "OkHttp versions before 4.9.2" in res[0]
    assert "Source: https://developer.android.com/target" in res[0]
    assert "example.com" not in res[0]


def test_search_ddg_raises_on_bot_check():
    """A bot-check page raises SearchBlockedError instead of returning an empty list."""
    blocked_html = "<html><body>Our systems detected unusual traffic. Are you a robot?</body></html>"
    with (
        patch("scanner.web.search._throttle_search"),
        patch("scanner.web.search.get_html", return_value=blocked_html),
    ):
        with pytest.raises(SearchBlockedError, match="bot check"):
            search_ddg("blocked query")


def test_search_ddg_does_not_flag_block_marker_inside_real_results():
    """A served page keeps its results even when a snippet contains a block marker word.

    Android security snippets routinely read "cleartext traffic is blocked by default",
    which previously self-rejected an HTTP 200 page carrying ten organic results.
    """
    html_with_marker = _DDG_RESULT_HTML.replace(
        "OkHttp versions before 4.9.2",
        "Since API 28 cleartext HTTP traffic is blocked by default",
    )
    with (
        patch("scanner.web.search._throttle_search"),
        patch("scanner.web.search.get_html", return_value=html_with_marker),
    ):
        res = search_ddg("cleartext traffic remediation")

    assert len(res) == 1
    assert "blocked by default" in res[0]


def test_search_ddg_empty_results_returns_empty_list():
    """A genuinely empty (non-blocked) result page yields an empty list."""
    with (
        patch("scanner.web.search._throttle_search"),
        patch("scanner.web.search.get_html", return_value="<html><body>No results.</body></html>"),
    ):
        assert search_ddg("obscure query") == []


def test_search_ddg_propagates_scraper_errors():
    """Scraper failures bubble up so the tool runner's retry logic can handle them."""
    with (
        patch("scanner.web.search._throttle_search"),
        patch("scanner.web.search.get_html", side_effect=RuntimeError("scraper down")),
    ):
        with pytest.raises(RuntimeError, match="scraper down"):
            search_ddg("query")


def test_throttle_search_uses_randomized_delay_range():
    """The inter-search pause is drawn from the 3-6s range and enforced via sleep."""
    assert SEARCH_DELAY_RANGE_SECONDS == (3.0, 6.0)

    with (
        patch("scanner.web.search.random.uniform", return_value=4.5) as mock_uniform,
        patch("scanner.web.search.time.monotonic", side_effect=[100.0, 104.5]),
        patch("scanner.web.search.time.sleep") as mock_sleep,
        patch("scanner.web.search._last_search_at", 99.0),
    ):
        _throttle_search()

    mock_uniform.assert_called_once_with(3.0, 6.0)
    # Last search was 1.0s ago, so the 4.5s randomized delay leaves 3.5s to wait.
    mock_sleep.assert_called_once()
    assert mock_sleep.call_args[0][0] == pytest.approx(3.5)


def test_detect_block_ignores_marker_inside_the_echoed_query():
    """DuckDuckGo echoes the query in the page title, which must not trip the markers."""
    html = "<html><head><title>why is cleartext blocked at DuckDuckGo</title></head><body></body></html>"
    assert detect_block(html) == "blocked"
    assert detect_block(html, query="why is cleartext blocked") is None


def test_detect_block_still_flags_real_challenge_page_with_query_given():
    """Stripping the echoed query must not mask a genuine bot check."""
    html = "<html><title>captcha test at DuckDuckGo</title><body>Our systems detected unusual traffic.</body></html>"
    assert detect_block(html, query="captcha test") == "unusual traffic"


def test_search_ddg_empty_page_for_marker_query_returns_empty_list():
    """A zero-result page for a query containing a marker word is data, not a block."""
    empty_html = "<html><head><title>site blocked forever at DuckDuckGo</title></head><body></body></html>"
    with (
        patch("scanner.web.search._throttle_search"),
        patch("scanner.web.search.get_html", return_value=empty_html),
    ):
        assert search_ddg("site blocked forever") == []


def test_unwrap_redirect_preserves_percent_encoding():
    """parse_qs already decodes once; decoding twice corrupts encoded characters."""
    href = "//duckduckgo.com/l/?uddg=https%3A%2F%2Fex.com%2Fa%2520b%26x%3D1"
    assert _unwrap_redirect(href) == "https://ex.com/a%20b&x=1"


def test_unwrap_redirect_passes_through_non_redirect_href():
    assert _unwrap_redirect("https://developer.android.com/guide") == "https://developer.android.com/guide"
