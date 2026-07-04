# This module scans the DEX file string pool for potential secrets
# using regular expressions for common keys, tokens, and credentials.

import re

# Pre-compiled patterns to avoid recompilation overhead inside loops.
SECRETS_PATTERNS = {
    "google_api": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "aws_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "slack_token": re.compile(r"xox[baprs]-[0-9a-zA-Z]{10,48}"),
    "stripe_standard": re.compile(r"sk_live_[0-9a-zA-Z]{24}"),
    "rsa_private_key": re.compile(r"-----BEGIN RSA PRIVATE KEY-----"),
    "generic_api_key": re.compile(r"(?i)(?:api[-_]?key|secret[-_]?key|access[-_]?token)[=:]\s*[\"']?([a-z0-9\-_]{16,64})[\"']?"),
    "jwt_token": re.compile(r"ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")
}

def extract_secrets(dx):
    """Scans the DEX file string pool for secrets using predefined patterns.

    Detects common credentials (e.g., Google API keys, AWS keys, JWT tokens, etc.) and
    optimizes execution speed by using a length pre-filter.

    Args:
        dx (androguard.core.analysis.analysis.Analysis): Analysis object containing class
            information and strings.

    Returns:
        list[dict[str, str]]: A list of dictionaries, each containing:
            - type (str): The identifier representing the secret pattern.
            - value (str): The secret string matching the pattern.
    """
    secrets = []
    
    for string_val in dx.get_strings():
        val = string_val.get_value()
        
        # Fast path check: if the string length is less than 16, skip regex search (minimum pattern length is 16)
        if len(val) < 16:
            continue
            
        for key, pattern in SECRETS_PATTERNS.items():
            if pattern.search(val):
                secrets.append({"type": key, "value": val})
                
    unique_secrets = []
    seen = set()
    for secret in secrets:
        key = (secret["type"], secret["value"])
        if key not in seen:
            seen.add(key)
            unique_secrets.append(secret)
    return unique_secrets