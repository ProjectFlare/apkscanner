# This module loads domain categorization rules and classifies extracted hostnames
# into categories such as cloud_services, trackers_and_ads, and others.

from urllib.parse import urlparse
from .rules import CLOUD_KEYWORDS, TRACKER_KEYWORDS, SCHEMA_KEYWORDS

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
                    domains.add(netloc)
            except Exception:
                pass
                
    categorized_domains = {
        "cloud_services": [],
        "trackers_and_ads": [],
        "other": []
    }
    
    for domain in sorted(domains):
        # Exclude internal schemas or dummy testing sites
        if any(k in domain for k in SCHEMA_KEYWORDS):
            continue
            
        if any(k in domain for k in CLOUD_KEYWORDS):
            categorized_domains["cloud_services"].append(domain)
        elif any(k in domain for k in TRACKER_KEYWORDS):
            categorized_domains["trackers_and_ads"].append(domain)
        else:
            categorized_domains["other"].append(domain)
            
    return categorized_domains