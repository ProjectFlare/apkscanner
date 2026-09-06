"""Outbound web access for the APK static scanner.

Groups every module that talks to the network on behalf of the scanner or the
AI report generator: the Playwright scraper client, the DuckDuckGo web search,
and the structured registry lookups (Maven, OSV.dev, NVD, Google Play Store).
"""

from scanner.web.maven import lookup_maven_version, resolve_latest_version
from scanner.web.nvd import lookup_nvd_cve
from scanner.web.osv import lookup_osv_vulnerabilities
from scanner.web.playstore import fetch_play_store_metadata, lookup_play_store
from scanner.web.scraper import get_html, set_scraper_url
from scanner.web.search import SearchBlockedError, search_ddg

__all__ = [
    "SearchBlockedError",
    "fetch_play_store_metadata",
    "get_html",
    "lookup_maven_version",
    "lookup_nvd_cve",
    "lookup_osv_vulnerabilities",
    "lookup_play_store",
    "resolve_latest_version",
    "search_ddg",
    "set_scraper_url",
]
