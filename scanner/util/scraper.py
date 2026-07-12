"""Web scraping helper for the APK static scanner.

Supports querying a custom Playwright-based scraper API to bypass bot protections.
"""

import requests
from loguru import logger

# Global scraper URL configuration
SCRAPER_URL: str | None = None


def set_scraper_url(url: str | None) -> None:
    """Sets the global scraper API URL.

    Args:
        url (str | None): The HTTP URL of the custom Playwright scraper service.
    """
    global SCRAPER_URL
    if url:
        SCRAPER_URL = url.rstrip("/")
        logger.info(f"Scraper API URL configured: {SCRAPER_URL}")
    else:
        SCRAPER_URL = None


def get_html(url: str) -> str:
    """Fetches the HTML source of a URL, utilizing the scraper API.

    Args:
        url (str): The target URL to fetch.

    Returns:
        str: The raw HTML content.

    Raises:
        ValueError: If the scraper API URL is not configured.
        RuntimeError: If the scraper API returns an error or if the request fails.
    """
    if not SCRAPER_URL:
        raise ValueError("Scraper API URL is not configured.")

    scraper_endpoint = f"{SCRAPER_URL}/scrape"
    logger.debug(f"Fetching via scraper API: {url}")
    try:
        response = requests.get(scraper_endpoint, params={"url": url}, timeout=60.0)
        response.raise_for_status()
        data = response.json()
        if "html" in data:
            return data["html"]
        if "error" in data:
            raise RuntimeError(f"Scraper API returned error: {data['error']}")
        raise RuntimeError("Scraper API response did not contain 'html' or 'error'.")
    except Exception as e:
        logger.error(f"Failed to fetch via scraper API for {url}: {e}")
        raise RuntimeError(f"Scraper API request failed: {e}") from e
