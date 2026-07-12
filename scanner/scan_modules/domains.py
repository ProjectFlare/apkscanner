"""Module for loading domain categorization rules and classifying extracted hostnames.

Classifies hostnames into categories such as cloud_services, trackers_and_ads, and others.
"""

import os
import re
from urllib.parse import urlparse

from loguru import logger

from scanner.util.rules import CLOUD_KEYWORDS, SCHEMA_KEYWORDS, TRACKER_KEYWORDS

# Pre-compiled list of Exodus tracker network signature regexes
TRACKER_SIGNATURE_PATTERNS = []

db_path = os.path.join(os.path.dirname(__file__), "rules.db")
if os.path.exists(db_path):
    try:
        import sqlite3

        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Check if table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='tracker_signatures'")
        if cursor.fetchone() is not None:
            cursor.execute(
                "SELECT network_signature FROM tracker_signatures WHERE network_signature IS NOT NULL AND network_signature != ''"
            )
            for row in cursor.fetchall():
                net_sig = row[0]
                try:
                    # Exodus patterns are often pipe-separated choices
                    pattern = re.compile(f"(?:{net_sig})", re.IGNORECASE)
                    TRACKER_SIGNATURE_PATTERNS.append(pattern)
                except Exception:
                    pass
        conn.close()
    except Exception as e:
        logger.warning(f"Failed to load tracker signatures in domains.py: {e}")


def is_tracker_domain(domain):
    """Checks if a domain matches known tracker network signatures or keywords.

    Args:
        domain (str): The domain name to check.

    Returns:
        bool: True if the domain is identified as a tracker/ad network.
    """
    # 1. Match against official Exodus network signature regexes (high precision)
    for pattern in TRACKER_SIGNATURE_PATTERNS:
        if pattern.search(domain):
            return True

    # 2. Match against fallback keywords, checking exact domain segments
    # to avoid false positives (e.g. keyword 'sync' matching 'carsync.de')
    segments = domain.split(".")
    for kw in TRACKER_KEYWORDS:
        kw_lower = kw.lower()
        if len(kw_lower) <= 3:
            continue

        # Match if the keyword matches a domain segment exactly
        if kw_lower in segments:
            return True

        # Match specific well-known tracker substrings
        well_known_trackers = {
            "doubleclick",
            "googleadservices",
            "googletagmanager",
            "crashlytics",
            "mixpanel",
            "appsflyer",
            "adjust",
        }
        if kw_lower in well_known_trackers and kw_lower in domain.lower():
            return True

    return False


def extract_domains(attributed_urls):
    """Extracts hostnames/domains from attributed URLs and groups them into categories.

    The categories are:
    - cloud_services: Domains associated with cloud hosting, storage, and backend APIs.
    - trackers_and_ads: Domains associated with telemetry, ad delivery, and tracking SDKs.
    - other: Any remaining domains that are not matched by filters.

    Any domains matching XML schema namespaces or generic test structures are excluded.

    Args:
        attributed_urls (dict): Dictionary mapping owner library prefixes to a list of URLs.

    Returns:
        dict: Categorized domains sorted alphabetically.
    """
    domains = set()

    for url_list in attributed_urls.values():
        for url in url_list:
            parse_url = url if url.startswith(("http://", "https://")) else f"http://{url}"
            try:
                netloc = urlparse(parse_url).netloc
                if "@" in netloc:
                    netloc = netloc.split("@")[-1]
                if ":" in netloc:
                    netloc = netloc.split(":")[0]
                if netloc.startswith("www."):
                    netloc = netloc[4:]
                if netloc:
                    domains.add(netloc.lower())
            except Exception:
                pass

    categorized_domains = {"cloud_services": [], "trackers_and_ads": [], "other": []}

    for domain in sorted(domains):
        # Exclude internal schemas or dummy testing sites
        if any(k in domain for k in SCHEMA_KEYWORDS):
            continue

        # Group domains based on keywords and signatures
        if any(k in domain for k in CLOUD_KEYWORDS):
            categorized_domains["cloud_services"].append(domain)
        elif is_tracker_domain(domain):
            categorized_domains["trackers_and_ads"].append(domain)
        else:
            categorized_domains["other"].append(domain)

    return categorized_domains
