"""DuckDuckGo web search for the AI report generator.

Queries DuckDuckGo's no-JS HTML endpoint (``html.duckduckgo.com``) through the
Playwright scraper container and parses the result page into snippet strings.
The markup handling is deliberately defensive: organic links are unwrapped from
DuckDuckGo's ``/l/?uddg=`` redirect back to their real target URL, sponsored
blocks are skipped, bot-check pages are detected and reported as a distinct
error instead of being mistaken for an empty result page, and results are
restricted to the trusted source allowlist.
"""

import random
import threading
import time
import urllib.parse

from loguru import logger

from scanner.util.rules import SEARCH_ALLOWLIST
from scanner.web.scraper import get_html

SEARCH_URL_TEMPLATE = "https://html.duckduckgo.com/html/?q={query}"

# The no-JS endpoint keeps these class names stable across releases; they are used
# as primary hints, with a structural fallback on the /l/?uddg= redirect signature.
RESULT_CLASS = "result"
AD_CLASS = "result--ad"
RESULT_LINK_CLASS = "result__a"
SNIPPET_CLASS = "result__snippet"
RESULT_BLOCK_DEPTH = 5

# Markers that distinguish a bot block from a genuinely empty result page.
BLOCK_MARKERS = [
    "anomaly",
    "are you a robot",
    "captcha",
    "unusual traffic",
    "too many requests",
    "blocked",
]

# Inclusive range the inter-search pause is drawn from. Sections are audited in
# parallel threads, so bursts of near-simultaneous queries would otherwise hit
# DuckDuckGo hard enough to trigger CAPTCHAs and rate limits. The delay is
# randomized to avoid a regular request cadence, which is itself a bot signal.
SEARCH_DELAY_RANGE_SECONDS: tuple[float, float] = (3.0, 6.0)
_search_throttle_lock = threading.Lock()
_last_search_at: float = 0.0


class SearchBlockedError(RuntimeError):
    """Raised when DuckDuckGo served a bot check instead of a result page."""


def _throttle_search() -> None:
    """Blocks until a randomized delay has passed since the last outgoing search.

    The lock is deliberately held across the sleep so that concurrent section threads
    queue up behind each other rather than all waking at once.
    """
    global _last_search_at
    with _search_throttle_lock:
        delay = random.uniform(*SEARCH_DELAY_RANGE_SECONDS)
        wait = delay - (time.monotonic() - _last_search_at)
        if wait > 0:
            logger.debug(f"[search throttle] waiting {wait:.2f}s before next web search")
            time.sleep(wait)
        _last_search_at = time.monotonic()


def detect_block(html: str, query: str | None = None) -> str | None:
    """Returns the block marker found in ``html``, or ``None`` if it looks clean.

    A challenge page and a genuinely empty result page both parse to zero results,
    so the two must be told apart before an empty list is treated as data.

    Args:
        html (str): The page HTML.
        query (str | None): The query that produced the page. DuckDuckGo echoes it in
            the page title and the search box, so a query containing a marker word
            ("blocked", "captcha") would otherwise flag its own result page. When given,
            the echoed text is removed before the markers are matched.

    Returns:
        str | None: The matched marker, or ``None``.
    """
    haystack = html[:20000].lower()
    if query:
        haystack = haystack.replace(query.lower(), " ")
    return next((marker for marker in BLOCK_MARKERS if marker in haystack), None)


def _unwrap_redirect(href: str) -> str:
    """Resolves a DuckDuckGo ``/l/?uddg=`` redirect to its real target URL.

    Args:
        href (str): The raw anchor href, possibly scheme-relative.

    Returns:
        str: The decoded target URL, or ``href`` unchanged when it is not a redirect.
    """
    if href.startswith("//"):
        href = f"https:{href}"
    parsed = urllib.parse.urlparse(href)
    if parsed.path.startswith("/l/"):
        # parse_qs already percent-decodes the value; decoding it a second time would
        # turn an encoded %2520 into a literal space and split %26 into a live separator.
        target = urllib.parse.parse_qs(parsed.query).get("uddg", [""])[0]
        if target:
            return target
    return href


def _is_organic(url: str) -> bool:
    """Whether a URL is an organic result rather than DuckDuckGo-internal navigation.

    Args:
        url (str): The unwrapped candidate result URL.

    Returns:
        bool: True for external result URLs, False for DuckDuckGo-internal ones.
    """
    host = urllib.parse.urlparse(url).netloc.lower()
    return bool(host) and not host.endswith("duckduckgo.com")


def host_allowed(url: str, allowlist: set[str] | None = None) -> bool:
    """Checks whether a result URL's host is on the trusted search allowlist.

    A host matches if it equals an allowlisted registrable domain or is a subdomain of
    one (e.g. ``security.snyk.io`` matches ``snyk.io``). Results whose host is absent from
    the allowlist are dropped so only high-quality, trusted sources reach the model. A
    ``www.`` prefix is ignored and matching is case-insensitive.

    Args:
        url (str): The candidate result URL.
        allowlist (set[str] | None): Registrable domains to allow. Defaults to
            :data:`scanner.util.rules.SEARCH_ALLOWLIST`.

    Returns:
        bool: True if the URL's host is allowlisted, False otherwise (including for
            empty, relative, or unparseable URLs).
    """
    allow = SEARCH_ALLOWLIST if allowlist is None else allowlist
    if not url:
        return False
    try:
        host = urllib.parse.urlparse(url).netloc.lower().split(":")[0].strip(".")
    except ValueError:
        return False
    if not host:
        return False
    if host.startswith("www."):
        host = host[4:]
    return any(host == domain or host.endswith("." + domain) for domain in allow)


def parse_results(html: str) -> list[dict[str, str | None]]:
    """Extracts organic DuckDuckGo results from a result page.

    Detection is class-hinted but degrades gracefully: the real signal is an anchor
    whose href routes through DuckDuckGo's ``/l/?uddg=`` redirect, so a class rename
    thins the snippet rather than emptying the result list.

    Args:
        html (str): The full search result page HTML.

    Returns:
        list[dict[str, str | None]]: Dicts with ``title``, ``url``, ``domain``
            and ``snippet`` keys, in page order and deduplicated by URL.
    """
    from bs4 import BeautifulSoup
    from bs4.element import Tag

    soup = BeautifulSoup(html, "html.parser")
    results: list[dict[str, str | None]] = []
    seen: set[str] = set()

    # Primary hint is the stable result link class; the structural fallback accepts any
    # anchor routed through the /l/?uddg= redirect so a class rename does not empty the list.
    anchors = soup.find_all("a", class_=RESULT_LINK_CLASS)
    if not anchors:
        anchors = [a for a in soup.find_all("a", href=True) if isinstance(a, Tag) and "uddg=" in str(a.get("href", ""))]

    for anchor in anchors:
        if not isinstance(anchor, Tag):
            continue
        href = anchor.get("href")
        if not href or not isinstance(href, str):
            continue
        url = _unwrap_redirect(href)
        if not url.startswith("http") or not _is_organic(url) or url in seen:
            continue
        title = anchor.get_text(strip=True)
        if not title:
            continue

        # The result container is the nearest ancestor carrying the snippet; walking
        # up a few levels from the anchor is stable across class renames.
        block: Tag = anchor
        for _ in range(RESULT_BLOCK_DEPTH):
            parent = block.parent
            if parent is None or parent.name == "body":
                break
            block = parent
            if RESULT_CLASS in (block.get("class") or []):
                break

        # Skip sponsored blocks, which share the organic link class but carry an ad marker.
        if AD_CLASS in (block.get("class") or []):
            continue

        seen.add(url)

        snippet = None
        snippet_node = block.find(class_=SNIPPET_CLASS)
        if snippet_node is not None:
            snippet = snippet_node.get_text(strip=True) or None

        results.append(
            {
                "title": title,
                "url": url,
                "domain": urllib.parse.urlparse(url).netloc,
                "snippet": snippet,
            }
        )
    return results


def search_ddg(query: str, max_results: int = 5) -> list[str]:
    """Runs a DuckDuckGo search via the scraper container and returns snippet strings.

    Outgoing searches are globally throttled with a randomized delay. Results are
    restricted to the trusted source allowlist before capping.

    Args:
        query (str): The search query to run.
        max_results (int): Maximum number of snippets to return.

    Returns:
        list[str]: Cleaned ``"title: snippet (Source: url)"`` strings.

    Raises:
        SearchBlockedError: If DuckDuckGo served a bot check instead of results.
        RuntimeError: If the scraper request itself failed.
        ValueError: If no scraper URL is configured.
    """
    _throttle_search()
    url = SEARCH_URL_TEMPLATE.format(query=urllib.parse.quote_plus(query))
    logger.debug(f"Executing DuckDuckGo search: {query}")
    html = get_html(url)

    # The block markers are single words that legitimately occur in security snippets
    # ("cleartext traffic is blocked by default"), so they may only be trusted on a page
    # that yielded no results at all. A challenge page never parses into organic results,
    # so results present is itself proof the request was served.
    parsed = parse_results(html)
    if not parsed:
        marker = detect_block(html, query)
        if marker is not None:
            raise SearchBlockedError(f"DuckDuckGo served a bot check (matched {marker!r}) for query: {query}")

    snippets = []
    for result in parsed:
        result_url = result["url"] or ""
        if not host_allowed(result_url):
            continue
        snippet = result["snippet"] or ""
        snippets.append(f"{result['title']}: {snippet} (Source: {result_url})")
    return snippets[:max_results]
