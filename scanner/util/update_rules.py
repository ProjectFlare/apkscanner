"""Updater module for APK Scanner rules database.

Fetches permissions from AOSP, trackers from Exodus, and dangerous domains from URLHaus,
saving them using the SQLModel ORM to rules.db.
"""

import html
import os
import re
import xml.etree.ElementTree as ET

import requests
from loguru import logger
from sqlmodel import Session, SQLModel, create_engine

from scanner.models import (
    CloudKeyword,
    DangerousDomain,
    MavenMapping,
    RuntimePermission,
    SchemaKeyword,
    SecretsPattern,
    TrackerKeyword,
    TrackerSignature,
    TrustedPackagePrefix,
)
from scanner.util import scraper
from scanner.util.rules import (
    CLOUD_KEYWORDS,
    IGNORED_TOKENS,
    MAVEN_MAPPING,
    SCHEMA_KEYWORDS,
    SECRETS_PATTERNS,
    TRUSTED_PACKAGE_PREFIXES,
)

# Default URLs of trusted databases
AOSP_MANIFEST_URL = (
    "https://raw.githubusercontent.com/aosp-mirror/platform_frameworks_base/master/core/res/AndroidManifest.xml"
)
EXODUS_TRACKERS_URL = "https://reports.exodus-privacy.eu.org/api/trackers"
URLHAUS_DOMAINS_URL = "https://urlhaus.abuse.ch/downloads/hostfile/"


def _extract_text_from_html(html_content: str) -> str:
    """Extracts raw text content from a Playwright-rendered HTML response.

    When Chromium loads plain text, XML, or JSON, it wraps the content inside a `<pre>` tag.
    This helper extracts the inner text of the `<pre>` tag if present, or strips HTML tags if not.

    Args:
        html_content (str): The raw HTML string fetched from the scraper.

    Returns:
        str: The extracted plain text content.
    """
    pre_match = re.search(r"<pre[^>]*>(.*?)</pre>", html_content, re.DOTALL | re.IGNORECASE)
    if pre_match:
        content = pre_match.group(1)
        return html.unescape(content)

    body_match = re.search(r"<body[^>]*>(.*?)</body>", html_content, re.DOTALL | re.IGNORECASE)
    if body_match:
        content = body_match.group(1)
        content = re.sub(r"<[^>]+>", "", content)
        return html.unescape(content)

    content = re.sub(r"<[^>]+>", "", html_content)
    return html.unescape(content)


def fetch_url_content(url: str, headers: dict | None = None) -> str:
    """Fetches text content from a URL, with optional fallback to the Playwright scraper API.

    Args:
        url (str): The target URL to fetch.
        headers (dict | None): Optional HTTP headers for the direct request.

    Returns:
        str: The raw text content of the URL.

    Raises:
        RuntimeError: If both direct request and scraper fallback fail.
    """
    logger.info(f"Fetching URL: {url}")
    try:
        response = requests.get(url, headers=headers, timeout=15)
        response.raise_for_status()
        return response.text
    except Exception as e:
        logger.warning(f"Direct request to {url} failed: {e}")

        if scraper.SCRAPER_URL:
            logger.info(f"Attempting to fetch via scraper API: {url}")
            try:
                html_content = scraper.get_html(url)
                return _extract_text_from_html(html_content)
            except Exception as scraper_err:
                logger.error(f"Scraper fallback failed for {url}: {scraper_err}")
                raise RuntimeError(
                    f"Failed to fetch {url} directly ({e}) and via scraper ({scraper_err})"
                ) from scraper_err
        else:
            raise RuntimeError(f"Failed to fetch {url} directly: {e}") from e


def fetch_dangerous_permissions():
    """Fetches runtime/dangerous permissions from the official AOSP manifest.

    Returns:
        list[str]: Sorted list of dangerous permission names.
    """
    logger.info(f"Fetching Android permissions from AOSP: {AOSP_MANIFEST_URL}")
    try:
        xml_content = fetch_url_content(AOSP_MANIFEST_URL)

        # Parse XML structure to retrieve permissions
        root = ET.fromstring(xml_content)
        ns = {"android": "http://schemas.android.com/apk/res/android"}

        dangerous_perms = []
        for perm in root.findall(".//permission", ns):
            name = perm.attrib.get("{http://schemas.android.com/apk/res/android}name")
            protection = perm.attrib.get("{http://schemas.android.com/apk/res/android}protectionLevel")

            if name and protection and "dangerous" in protection:
                dangerous_perms.append(name)

        return sorted(set(dangerous_perms))
    except Exception as e:
        logger.error(f"Failed to fetch permissions from AOSP: {e}")
        return []


def _extract_tokens_from_signature(signature: str) -> list[str]:
    """Extracts meaningful keywords from a signature string.

    Args:
        signature (str): The code or network signature string to tokenize.

    Returns:
        list[str]: Filtered list of lowercased tokens.
    """
    if not signature:
        return []
    tokens = re.findall(r"[a-zA-Z0-9_-]+", signature)
    return [t_low for t in tokens if (t_low := t.lower()) not in IGNORED_TOKENS and len(t_low) > 3]


def fetch_exodus_trackers():
    """Fetches known Android tracker signatures from Exodus Privacy.

    Returns:
        tuple[list[str], list[dict]]: A tuple of tracker keywords and detailed signatures.
    """
    logger.info(f"Fetching trackers from Exodus Privacy: {EXODUS_TRACKERS_URL}")
    try:
        # User-Agent is required by Exodus API policy to prevent blocks
        headers = {"User-Agent": "APKScanner/1.0.0"}
        json_content = fetch_url_content(EXODUS_TRACKERS_URL, headers=headers)

        import json

        data = json.loads(json_content)
        trackers_dict = data.get("trackers", {})

        keywords = set()
        signatures = []

        for tracker_id, info in trackers_dict.items():
            name = info.get("name", "")
            code_sig = info.get("code_signature", "")
            net_sig = info.get("network_signature", "")

            # Extract meaningful keywords from package/class/network signatures
            keywords.update(_extract_tokens_from_signature(code_sig))
            keywords.update(_extract_tokens_from_signature(net_sig))

            signatures.append(
                {"id": tracker_id, "name": name, "code_signature": code_sig, "network_signature": net_sig}
            )

        return sorted(keywords), signatures
    except Exception as e:
        logger.error(f"Failed to fetch trackers from Exodus Privacy: {e}")
        return [], []


def fetch_urlhaus_domains():
    """Fetches active malware and phishing domains from URLHaus blocklist.

    Returns:
        list[str]: Sorted list of malicious domain names.
    """
    logger.info(f"Fetching threat intelligence domains from URLHaus: {URLHAUS_DOMAINS_URL}")
    try:
        text_content = fetch_url_content(URLHAUS_DOMAINS_URL)

        domains = set()
        for line in text_content.splitlines():
            line = line.strip()
            # Ignore comments and empty lines
            if not line or line.startswith("#"):
                continue

            parts = line.split()
            if len(parts) >= 2:
                domain = parts[1].strip()
                if domain != "localhost":
                    domains.add(domain)

        return sorted(domains)
    except Exception as e:
        logger.error(f"Failed to fetch domains from URLHaus: {e}")
        return []


def _populate_db_data(session: Session, perms, tracker_keywords, tracker_sigs, dangerous_domains) -> None:
    """Populates the database tables with default, config, and scraped rules.

    Args:
        session (Session): The SQLModel session.
        perms (list[str]): List of dangerous runtime permissions.
        tracker_keywords (list[str]): List of tracker keywords.
        tracker_sigs (list[dict]): List of tracker signatures.
        dangerous_domains (list[str]): List of dangerous domains.
    """
    # Insert permissions
    for p in perms:
        session.add(RuntimePermission(name=p))

    # Insert cloud keywords
    for k in CLOUD_KEYWORDS:
        session.add(CloudKeyword(keyword=k))

    # Insert tracker keywords
    if tracker_keywords:
        for k in tracker_keywords:
            session.add(TrackerKeyword(keyword=k))

    # Insert tracker signatures
    if tracker_sigs:
        for s in tracker_sigs:
            session.add(
                TrackerSignature(
                    id=s["id"],
                    name=s["name"],
                    code_signature=s["code_signature"],
                    network_signature=s["network_signature"],
                )
            )

    # Insert schema keywords
    for k in SCHEMA_KEYWORDS:
        session.add(SchemaKeyword(keyword=k))

    # Insert dangerous domains
    if dangerous_domains:
        for d in dangerous_domains:
            session.add(DangerousDomain(domain=d))

    # Insert trusted package prefixes
    for p in TRUSTED_PACKAGE_PREFIXES:
        session.add(TrustedPackagePrefix(prefix=p))

    # Insert maven mappings
    for k, v in MAVEN_MAPPING.items():
        session.add(MavenMapping(lib_name=k, coordinate=v))

    # Insert secrets patterns
    for k, v in SECRETS_PATTERNS.items():
        session.add(SecretsPattern(key=k, pattern=v.pattern))


def update_rules_db(output_path):
    """Executes the updates and saves compiled SQLite database via SQLModel.

    Args:
        output_path (str): File system path to write rules.db.

    Returns:
        bool: True if compilation succeeded and wrote to file.
    """
    perms = fetch_dangerous_permissions()
    tracker_keywords, tracker_sigs = fetch_exodus_trackers()
    dangerous_domains = fetch_urlhaus_domains()

    # Verify we got valid data from the sources, otherwise use local fallbacks
    if not perms:
        logger.warning("Could not fetch permissions; updater will use existing defaults.")
        return False

    try:
        # If the file exists, we remove it to ensure a clean slate database
        if os.path.exists(output_path):
            try:
                os.remove(output_path)
            except Exception as e:
                logger.warning(f"Could not remove old rules DB file: {e}")

        engine = create_engine(f"sqlite:///{output_path}")
        SQLModel.metadata.create_all(engine)

        with Session(engine) as session:
            _populate_db_data(
                session,
                perms=perms,
                tracker_keywords=tracker_keywords,
                tracker_sigs=tracker_sigs,
                dangerous_domains=dangerous_domains,
            )
            session.commit()

        logger.info(f"Rules database successfully updated and written to SQLite DB at {output_path}")
        return True
    except Exception as e:
        logger.error(f"Failed to write rules database to {output_path}: {e}")
        return False


if __name__ == "__main__":
    db_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "rules.db")
    update_rules_db(db_path)
