"""Module for scanning the DEX file string pool and assets for potential secrets.

Uses regular expressions for common keys, tokens, and credentials, recording
their metadata names and origin sources.
"""

import xml.etree.ElementTree as ET

from scanner.util.rules import SECRETS_PATTERNS


def _scan_dex_strings(dx):
    """Scans the DEX string pool for potential secrets.

    Args:
        dx (androguard.core.analysis.analysis.Analysis): Analysis object containing class
            information and strings.

    Returns:
        list[dict[str, str]]: A list of dictionaries representing found secrets.
    """
    secrets = []
    for string_val in dx.get_strings():
        val = string_val.get_value()
        if len(val) < 16:
            continue

        for key, pattern in SECRETS_PATTERNS.items():
            match = pattern.search(val)
            if match:
                matched_val = match.group(1) if (match.groups() and match.group(1)) else match.group(0)

                # Map Dalvik class names (e.g. Lcom/foo/Bar;) to standard class names
                # and collect cross-references to trace origin locations.
                xrefs = []
                for class_ana, method_ana in string_val.get_xref_from():
                    class_name = class_ana.name
                    if class_name.startswith("L") and class_name.endswith(";"):
                        class_name = class_name[1:-1].replace("/", ".")
                    xrefs.append(f"{class_name}->{method_ana.name}")

                source = ", ".join(xrefs) if xrefs else "DEX String Pool"
                secrets.append(
                    {
                        "type": key,
                        "value": matched_val,
                        "name": "Hardcoded String Constant",
                        "source": source,
                    }
                )
    return secrets


def _scan_resource_strings(apk):
    """Scans resource string table XML of an APK for potential secrets.

    Args:
        apk (APK): A parsed APK object.

    Returns:
        list[dict[str, str]]: A list of dictionaries representing found secrets.
    """
    secrets = []
    try:
        res = apk.get_android_resources()
        if res:
            xml_data = res.get_strings_resources()
            if xml_data:
                root = ET.fromstring(xml_data)
                for elem in root.findall(".//string"):
                    val = elem.text
                    if val and len(val) >= 16:
                        for key, pattern in SECRETS_PATTERNS.items():
                            match = pattern.search(val)
                            if match:
                                matched_val = match.group(1) if (match.groups() and match.group(1)) else match.group(0)
                                name = elem.attrib.get("name", "unknown")
                                secrets.append(
                                    {
                                        "type": key,
                                        "value": matched_val,
                                        "name": name,
                                        "source": "resource string XML table",
                                    }
                                )
    except Exception:
        # Ignore resource parsing exceptions to keep scanning robust.
        pass
    return secrets


def _scan_raw_assets(apk):
    """Scans raw assets and XML files of an APK for potential secrets.

    Args:
        apk (APK): A parsed APK object.

    Returns:
        list[dict[str, str]]: A list of dictionaries representing found secrets.
    """
    secrets = []
    text_extensions = (".json", ".properties", ".txt", ".conf", ".ini", ".yml", ".yaml", ".xml")
    try:
        for filename in apk.get_files():
            if filename.startswith(("assets/", "res/raw/", "res/xml/")):
                if filename.lower().endswith(text_extensions):
                    try:
                        raw_data = apk.get_file(filename)
                        # Avoid scanning excessively large files to conserve memory and time.
                        if raw_data and len(raw_data) < 1024 * 1024:
                            content = raw_data.decode("utf-8", errors="ignore")
                            for line in content.splitlines():
                                line = line.strip()
                                if len(line) >= 16:
                                    for key, pattern in SECRETS_PATTERNS.items():
                                        match = pattern.search(line)
                                        if match:
                                            matched_val = (
                                                match.group(1)
                                                if (match.groups() and match.group(1))
                                                else match.group(0)
                                            )

                                            # Try parsing configuration key name (e.g. key=val or key: val)
                                            prop_name = "unknown"
                                            for sep in ("=", ":"):
                                                if sep in line:
                                                    parts = line.split(sep, 1)
                                                    k = parts[0].strip()
                                                    if len(k) < 100:
                                                        prop_name = k
                                                        break

                                            secrets.append(
                                                {
                                                    "type": key,
                                                    "value": matched_val,
                                                    "name": prop_name,
                                                    "source": f"Asset File: {filename}",
                                                }
                                            )
                    except Exception:
                        pass
    except Exception:
        pass
    return secrets


def _deduplicate_secrets(secrets):
    """De-duplicates the list of extracted secrets.

    Args:
        secrets (list[dict[str, str]]): List of secrets to deduplicate.

    Returns:
        list[dict[str, str]]: De-duplicated list of secrets.
    """
    unique_secrets = []
    seen = set()
    for secret in secrets:
        key = (secret["type"], secret["value"])
        if key not in seen:
            seen.add(key)
            unique_secrets.append(secret)
    return unique_secrets


def extract_secrets(dx, apks=None):
    """Scans DEX strings, resource tables, and text assets for potential secrets.

    Detects common credentials (e.g., Google API keys, AWS keys, JWT tokens, etc.)
    and parses XML resource string files and raw assets line-by-line.

    Args:
        dx (androguard.core.analysis.analysis.Analysis): Analysis object containing class
            information and strings.
        apks (APK or list, optional): A single parsed APK object or a list of split APK objects.

    Returns:
        list[dict[str, str]]: A list of dictionaries, each containing:
            - type (str): The identifier representing the secret pattern.
            - value (str): The secret string matching the pattern.
            - name (str): The name/variable associated with the secret.
            - source (str): The origin class or file location.
    """
    secrets = []

    # 1. Scan DEX string pool
    secrets.extend(_scan_dex_strings(dx))

    # 2. Scan Resource Tables & Asset files if apks list or single apk is provided
    if apks:
        if not isinstance(apks, list):
            apks = [apks]

        for apk in apks:
            # Parse Resource string table XML
            secrets.extend(_scan_resource_strings(apk))
            # Scan raw assets and text resources
            secrets.extend(_scan_raw_assets(apk))

    return _deduplicate_secrets(secrets)
