# Updater module for APK Scanner rules database.
# Fetches permissions from AOSP, trackers from Exodus, and dangerous domains from URLHaus.

import os
import re
import json
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
import requests
from loguru import logger

# Default URLs of trusted databases
AOSP_MANIFEST_URL = "https://raw.githubusercontent.com/aosp-mirror/platform_frameworks_base/master/core/res/AndroidManifest.xml"
EXODUS_TRACKERS_URL = "https://reports.exodus-privacy.eu.org/api/trackers"
URLHAUS_DOMAINS_URL = "https://urlhaus.abuse.ch/downloads/hostfile/"

from .rules import CLOUD_KEYWORDS, SCHEMA_KEYWORDS, IGNORED_TOKENS, TRUSTED_PACKAGE_PREFIXES, MAVEN_MAPPING, SECRETS_PATTERNS

def fetch_dangerous_permissions():
    """Fetches runtime/dangerous permissions from the official AOSP manifest.

    Returns:
        list[str]: Sorted list of dangerous permission names.
    """
    logger.info(f"Fetching Android permissions from AOSP: {AOSP_MANIFEST_URL}")
    try:
        response = requests.get(AOSP_MANIFEST_URL, timeout=15)
        response.raise_for_status()
        
        # Parse XML structure to retrieve permissions
        root = ET.fromstring(response.text)
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

def fetch_exodus_trackers():
    """Fetches known Android tracker signatures from Exodus Privacy.

    Returns:
        tuple[list[str], list[dict]]: A tuple of tracker keywords and detailed signatures.
    """
    logger.info(f"Fetching trackers from Exodus Privacy: {EXODUS_TRACKERS_URL}")
    try:
        # User-Agent is required by Exodus API policy to prevent blocks
        headers = {"User-Agent": "APKScanner/1.0.0"}
        response = requests.get(EXODUS_TRACKERS_URL, headers=headers, timeout=15)
        response.raise_for_status()
        
        data = response.json()
        trackers_dict = data.get("trackers", {})
        
        keywords = set()
        signatures = []
        

        
        for tracker_id, info in trackers_dict.items():
            name = info.get("name", "")
            code_sig = info.get("code_signature", "")
            net_sig = info.get("network_signature", "")
            
            # Extract meaningful keywords from package/class signatures
            if code_sig:
                tokens = re.findall(r'[a-zA-Z0-9_-]+', code_sig)
                for token in tokens:
                    token_lower = token.lower()
                    if len(token_lower) > 3 and token_lower not in IGNORED_TOKENS:
                        keywords.add(token_lower)
                        
            # Extract meaningful keywords from network regex patterns
            if net_sig:
                tokens = re.findall(r'[a-zA-Z0-9_-]+', net_sig)
                for token in tokens:
                    token_lower = token.lower()
                    if len(token_lower) > 3 and token_lower not in IGNORED_TOKENS:
                        keywords.add(token_lower)
                        
            signatures.append({
                "id": tracker_id,
                "name": name,
                "code_signature": code_sig,
                "network_signature": net_sig
            })
            
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
        response = requests.get(URLHAUS_DOMAINS_URL, timeout=15)
        response.raise_for_status()
        
        domains = set()
        for line in response.text.splitlines():
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

def update_rules_db(output_path):
    """Executes the updates and saves compiled SQLite database.

    Args:
        output_path (str): File system path to write rules.db.

    Returns:
        bool: True if compilation succeeded and wrote to file.
    """
    import sqlite3

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
                logger.warning(f"Could not remove old rules DB file, clearing tables instead: {e}")

        conn = sqlite3.connect(output_path)
        cursor = conn.cursor()

        # Create Schema tables
        cursor.execute("CREATE TABLE IF NOT EXISTS runtime_permissions (name TEXT PRIMARY KEY)")
        cursor.execute("CREATE TABLE IF NOT EXISTS cloud_keywords (keyword TEXT PRIMARY KEY)")
        cursor.execute("CREATE TABLE IF NOT EXISTS tracker_keywords (keyword TEXT PRIMARY KEY)")
        cursor.execute("CREATE TABLE IF NOT EXISTS tracker_signatures (id TEXT PRIMARY KEY, name TEXT, code_signature TEXT, network_signature TEXT)")
        cursor.execute("CREATE TABLE IF NOT EXISTS schema_keywords (keyword TEXT PRIMARY KEY)")
        cursor.execute("CREATE TABLE IF NOT EXISTS dangerous_domains (domain TEXT PRIMARY KEY)")
        cursor.execute("CREATE TABLE IF NOT EXISTS trusted_package_prefixes (prefix TEXT PRIMARY KEY)")
        cursor.execute("CREATE TABLE IF NOT EXISTS maven_mappings (lib_name TEXT PRIMARY KEY, coordinate TEXT)")
        cursor.execute("CREATE TABLE IF NOT EXISTS secrets_patterns (key TEXT PRIMARY KEY, pattern TEXT)")

        # Clear existing table data in case remove file was skipped
        cursor.execute("DELETE FROM runtime_permissions")
        cursor.execute("DELETE FROM cloud_keywords")
        cursor.execute("DELETE FROM tracker_keywords")
        cursor.execute("DELETE FROM tracker_signatures")
        cursor.execute("DELETE FROM schema_keywords")
        cursor.execute("DELETE FROM dangerous_domains")
        cursor.execute("DELETE FROM trusted_package_prefixes")
        cursor.execute("DELETE FROM maven_mappings")
        cursor.execute("DELETE FROM secrets_patterns")

        # Insert permissions
        cursor.executemany("INSERT INTO runtime_permissions (name) VALUES (?)", [(p,) for p in perms])

        # Insert cloud keywords
        cursor.executemany("INSERT INTO cloud_keywords (keyword) VALUES (?)", [(k,) for k in CLOUD_KEYWORDS])

        # Insert tracker keywords
        if tracker_keywords:
            cursor.executemany("INSERT INTO tracker_keywords (keyword) VALUES (?)", [(k,) for k in tracker_keywords])

        # Insert tracker signatures
        if tracker_sigs:
            cursor.executemany(
                "INSERT INTO tracker_signatures (id, name, code_signature, network_signature) VALUES (?, ?, ?, ?)",
                [(s["id"], s["name"], s["code_signature"], s["network_signature"]) for s in tracker_sigs]
            )

        # Insert schema keywords
        cursor.executemany("INSERT INTO schema_keywords (keyword) VALUES (?)", [(k,) for k in SCHEMA_KEYWORDS])

        # Insert dangerous domains
        if dangerous_domains:
            cursor.executemany("INSERT INTO dangerous_domains (domain) VALUES (?)", [(d,) for d in dangerous_domains])

        # Insert trusted package prefixes
        cursor.executemany("INSERT INTO trusted_package_prefixes (prefix) VALUES (?)", [(p,) for p in TRUSTED_PACKAGE_PREFIXES])

        # Insert maven mappings
        cursor.executemany("INSERT INTO maven_mappings (lib_name, coordinate) VALUES (?, ?)", [(k, v) for k, v in MAVEN_MAPPING.items()])

        # Insert secrets patterns
        # We store compiled pattern values as their raw regex string representations
        cursor.executemany("INSERT INTO secrets_patterns (key, pattern) VALUES (?, ?)", [(k, v.pattern) for k, v in SECRETS_PATTERNS.items()])

        conn.commit()
        conn.close()
        logger.info(f"Rules database successfully updated and written to SQLite DB at {output_path}")
        return True
    except Exception as e:
        logger.error(f"Failed to write rules database to {output_path}: {e}")
        return False

if __name__ == "__main__":
    db_path = os.path.join(os.path.dirname(__file__), "rules.db")
    update_rules_db(db_path)
