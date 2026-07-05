# This module scans the DEX file string pool for potential secrets
# using regular expressions for common keys, tokens, and credentials.

from scanner.rules import SECRETS_PATTERNS

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
            - pattern (str): The regex pattern used to detect the secret.
    """
    secrets = []
    
    # 1. Scan DEX string pool
    for string_val in dx.get_strings():
        val = string_val.get_value()
        if len(val) < 16:
            continue
            
        for key, pattern in SECRETS_PATTERNS.items():
            match = pattern.search(val)
            if match:
                matched_val = match.group(1) if (match.groups() and match.group(1)) else match.group(0)
                secrets.append({"type": key, "value": matched_val})
                
    # 2. Scan Resource Tables & Asset files if apks list is provided
    if apks:
        if not isinstance(apks, list):
            apks = [apks]
            
        import xml.etree.ElementTree as ET
        TEXT_EXTENSIONS = ('.json', '.properties', '.txt', '.conf', '.ini', '.yml', '.yaml', '.xml')
        
        for apk in apks:
            # Parse Resource string table XML
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
                                        secrets.append({"type": key, "value": matched_val})
            except Exception:
                pass

            # Scan raw assets and text resources
            try:
                for filename in apk.get_files():
                    if filename.startswith(("assets/", "res/raw/", "res/xml/")):
                        if filename.lower().endswith(TEXT_EXTENSIONS):
                            try:
                                raw_data = apk.get_file(filename)
                                if raw_data and len(raw_data) < 1024 * 1024:  # Under 1MB
                                    content = raw_data.decode('utf-8', errors='ignore')
                                    for line in content.splitlines():
                                        line = line.strip()
                                        if len(line) >= 16:
                                            for key, pattern in SECRETS_PATTERNS.items():
                                                match = pattern.search(line)
                                                if match:
                                                    matched_val = match.group(1) if (match.groups() and match.group(1)) else match.group(0)
                                                    secrets.append({"type": key, "value": matched_val})
                            except Exception:
                                pass
            except Exception:
                pass
                
    unique_secrets = []
    seen = set()
    for secret in secrets:
        key = (secret["type"], secret["value"])
        if key not in seen:
            seen.add(key)
            unique_secrets.append(secret)
    return unique_secrets