"""Module for loading domain categorization rules and classifying extracted hostnames.

Classifies hostnames into categories such as cloud_services, trackers_and_ads, and others.
"""

from urllib.parse import urlparse

from scanner.util.rules import CLOUD_KEYWORDS, SCHEMA_KEYWORDS, TRACKER_KEYWORDS, TRACKER_SIGNATURE_PATTERNS

# Well-known tracker and telemetry domain substrings
_WELL_KNOWN_TRACKERS: frozenset[str] = frozenset(
    {
        "doubleclick",
        "googleadservices",
        "googletagmanager",
        "crashlytics",
        "mixpanel",
        "appsflyer",
        "adjust",
    }
)


def is_tracker_domain(domain: str) -> bool:
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
    # to avoid false positives (e.g. keyword 'sync' matching 'mysync.example.com')
    segments = domain.split(".")
    domain_lower = domain.lower()
    for kw in TRACKER_KEYWORDS:
        kw_lower = kw.lower()
        if len(kw_lower) <= 3:
            continue

        # Match if the keyword matches a domain segment exactly
        if kw_lower in segments:
            return True

        # Match specific well-known tracker substrings
        if kw_lower in _WELL_KNOWN_TRACKERS and kw_lower in domain_lower:
            return True

    return False


def normalize_domain_from_url(url: str) -> str:
    """Extracts a normalized hostname/domain from a URL string.

    Strips schemes, authentication credentials, port numbers, and leading 'www.' prefixes,
    returning a clean lowercase domain name.

    Args:
        url (str): The URL or host string to normalize.

    Returns:
        str: Normalized domain name in lowercase, or empty string on failure.
    """
    parse_url = url if url.startswith(("http://", "https://")) else f"http://{url}"
    try:
        netloc = urlparse(parse_url).netloc
        if "@" in netloc:
            netloc = netloc.split("@")[-1]
        if ":" in netloc:
            netloc = netloc.split(":")[0]
        if netloc.startswith("www."):
            netloc = netloc[4:]
        return netloc.lower()
    except Exception:
        return ""


def extract_domains(attributed_urls: dict[str, list[str]]) -> dict[str, list[str]]:
    """Extracts hostnames/domains from attributed URLs and groups them into categories.

    The categories are:
    - cloud_services: Domains associated with cloud hosting, storage, and backend APIs.
    - trackers_and_ads: Domains associated with telemetry, ad delivery, and tracking SDKs.
    - other: Any remaining domains that are not matched by filters.

    Any domains matching XML schema namespaces or generic test structures are excluded.

    Args:
        attributed_urls (dict[str, list[str]]): Dictionary mapping owner library prefixes to a list of URLs.

    Returns:
        dict[str, list[str]]: Categorized domains sorted alphabetically.
    """
    domains: set[str] = set()

    for url_list in attributed_urls.values():
        for url in url_list:
            domain = normalize_domain_from_url(url)
            if domain:
                domains.add(domain)

    categorized_domains: dict[str, list[str]] = {"cloud_services": [], "trackers_and_ads": [], "other": []}

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
