"""Google Play Store metadata retrieval for the AI report generator.

Fetches an app's Play Store detail page through the Playwright scraper container
and extracts structured metadata (name, developer, description) with multiple
markup fallbacks, so a single Play Store markup change does not blank a field.
"""

import re
from typing import Any

from bs4 import BeautifulSoup
from loguru import logger

from scanner.web.scraper import get_html


def _extract_play_store_metadata(html: str, package_id: str) -> dict[str, Any] | None:
    """Parses Google Play Store HTML into a structured metadata dict.

    The extraction never depends on a single markup pattern: the app name falls back from the
    ``itemprop`` span to the page ``<title>``, and the description falls back from the full
    ``data-g-id`` block to the ``itemprop`` meta tag, so a change to one Play Store markup path
    does not silently blank the field.

    Args:
        html (str): The raw Play Store detail-page HTML.
        package_id (str): Android package ID (e.g. com.example.app).

    Returns:
        dict[str, Any] | None: A dict with ``package`` and ``source`` always present and optional ``name``,
            ``developer``, and ``description`` keys, or ``None`` if the page is a 404 / not-found
            / empty page (meaning the app is not listed on the store).
    """
    # Treat an error page or a suspiciously small body as "not listed" before extracting anything.
    if "We're sorry, the requested URL was not found" in html or len(html) < 1000:
        return None

    soup = BeautifulSoup(html, "html.parser")
    meta: dict[str, Any] = {
        "package": package_id,
        "source": f"https://play.google.com/store/apps/details?id={package_id}",
    }

    # Extract App Name (prefer itemprop="name", fallback to <title>)
    name: str | None = None
    name_elem = soup.select_one('[itemprop="name"]')
    if name_elem:
        name = name_elem.get_text(strip=True)
    if not name and soup.title and soup.title.string:
        name = soup.title.string.strip()

    if name:
        # Strip the standard Play Store title suffixes so only the bare app name remains.
        name = re.sub(r"\s*-\s*(?:Android\s+)?Apps\s+on\s+Google\s+Play\s*$", "", name, flags=re.IGNORECASE)
        name = re.sub(r"\s*-\s*Google\s+Play\s*$", "", name, flags=re.IGNORECASE).strip()
        if name:
            meta["name"] = name

    # Extract Developer (target links pointing to developer profile pages)
    dev_elem = soup.select_one('a[href*="/store/apps/dev"], a[href*="/store/apps/developer"]')
    if dev_elem:
        dev_text = dev_elem.get_text(strip=True)
        if dev_text:
            meta["developer"] = dev_text

    # Extract Description (prefer container elements, fallback to meta tags)
    desc: str | None = None
    desc_elem = soup.select_one('[data-g-id="description"]') or soup.select_one('[itemprop="description"]:not(meta)')

    if desc_elem:
        # get_text with separator=" " converts <br> and <p> boundaries into spaces without gluing words together.
        desc = desc_elem.get_text(separator=" ", strip=True)
    else:
        meta_desc = soup.select_one('meta[itemprop="description"], meta[name="description"]')
        if meta_desc and meta_desc.get("content"):
            content_val = meta_desc["content"]
            if isinstance(content_val, str):
                desc = content_val

    if desc:
        cleaned_desc = re.sub(r"\s+", " ", desc).strip()
        if cleaned_desc:
            meta["description"] = cleaned_desc

    return meta


def fetch_play_store_metadata(package_id: str) -> dict[str, Any] | None:
    """Deterministically fetches and parses Play Store metadata for a package.

    This is the non-agentic entry point used by the report layer to obtain guaranteed app
    identity data (name, developer, description) independently of the model's tool-calling, so
    the app overview never degrades to a package-only stub when the store page actually exists.

    Args:
        package_id (str): Android package ID (e.g. com.example.app).

    Returns:
        dict[str, Any] | None: The structured metadata dict (see :func:`_extract_play_store_metadata`), or
            ``None`` if the package is empty, the scraper is unavailable, or the app is not listed.
    """
    if not package_id:
        return None

    url = f"https://play.google.com/store/apps/details?id={package_id}&hl=en"
    try:
        html = get_html(url)
    except Exception as e:
        logger.warning(f"Play Store metadata pre-fetch failed for {package_id}: {e}")
        return None
    return _extract_play_store_metadata(html, package_id)


def lookup_play_store(package_id: str) -> str:
    """Scrapes Google Play Store to fetch app metadata for a given package ID.

    Args:
        package_id (str): Android package ID (e.g. com.example.app).

    Returns:
        str: Formatted key-value metadata string for the model.

    Raises:
        RuntimeError: If the Play Store page could not be fetched.
    """
    url = f"https://play.google.com/store/apps/details?id={package_id}&hl=en"
    try:
        html = get_html(url)
    except Exception as e:
        raise RuntimeError(f"Play Store scrape failed for {package_id}: {e}") from e

    meta = _extract_play_store_metadata(html, package_id)
    if meta is None:
        return f"App not found on Google Play Store for package ID: {package_id}"

    lines = [
        f"Google Play Store metadata for: {package_id}",
        f"Source: {meta['source']}",
    ]
    if name := meta.get("name"):
        lines.append(f"App Name: {name}")
    if developer := meta.get("developer"):
        lines.append(f"Developer: {developer}")
    if description := meta.get("description"):
        lines.append(f"Description: {description[:300]}")
    return "\n".join(lines)
