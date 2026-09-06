"""Unit tests for scanner.util.rules module.

Tests static fallback rule constants, regex patterns, and dynamic SQLite database loading.
"""

from unittest.mock import patch

from scanner.util.rules import (
    CLOUD_KEYWORDS,
    DANGEROUS_DOMAINS,
    DEOBFUSCATOR_IGNORED_PKG_PREFIXES,
    IGNORED_AI_DOMAINS,
    IGNORED_TOKENS,
    MASVS_RULES,
    MAVEN_MAPPING,
    MAVEN_PREFIXES,
    NEWS_SOURCE_DOMAINS,
    OBFUSCATED_SUBMODULE,
    PACKER_SIGNATURES,
    ROOT_STRINGS,
    RUNTIME_PERMISSIONS,
    SCHEMA_KEYWORDS,
    SEARCH_ALLOWLIST,
    SECRETS_PATTERNS,
    SECURITY_REFERENCE_DOMAINS,
    TRACKER_KEYWORDS,
    TRUSTED_PACKAGE_PREFIXES,
    VERSION_PATTERNS,
    load_dynamic_rules,
)


def test_rules_constants_integrity():
    """Verifies that all core fallback constants are non-empty and well-formed."""
    assert len(RUNTIME_PERMISSIONS) > 0
    assert "android.permission.CAMERA" in RUNTIME_PERMISSIONS
    assert "firebase" in CLOUD_KEYWORDS
    assert "analytics" in TRACKER_KEYWORDS
    assert "schemas.android.com" in SCHEMA_KEYWORDS
    assert "kotlinlang.org" in IGNORED_AI_DOMAINS
    assert "reuters.com" in NEWS_SOURCE_DOMAINS
    assert "developer.android.com" in SECURITY_REFERENCE_DOMAINS
    assert NEWS_SOURCE_DOMAINS.issubset(SEARCH_ALLOWLIST)
    assert SECURITY_REFERENCE_DOMAINS.issubset(SEARCH_ALLOWLIST)
    assert "com" in IGNORED_TOKENS
    assert "Landroid/" in TRUSTED_PACKAGE_PREFIXES
    assert "okhttp3" in MAVEN_MAPPING
    assert "firebase-" in MAVEN_PREFIXES
    assert isinstance(DANGEROUS_DOMAINS, set)
    assert "java.lang" in DEOBFUSCATOR_IGNORED_PKG_PREFIXES
    assert "/system/bin/su" in ROOT_STRINGS
    assert "Qihoo 360 / Jiagu" in PACKER_SIGNATURES
    assert "hardcoded_secrets" in MASVS_RULES
    assert MASVS_RULES["hardcoded_secrets"]["masvs_id"] == "MASVS-STORAGE-1"
    assert MASVS_RULES["hardcoded_secrets"]["default_severity"] == "INFORMATIONAL"
    assert MASVS_RULES["hardcoded_crypto_keys"]["default_severity"] == "INFORMATIONAL"
    assert MASVS_RULES["zip_slip"]["default_severity"] == "INFORMATIONAL"
    assert MASVS_RULES["deprecated_cipher_algorithm"]["default_severity"] == "MEDIUM"
    assert MASVS_RULES["unpadded_ecb_primitive"]["default_severity"] == "MEDIUM"
    assert MASVS_RULES["permissive_webview_file_access"]["default_severity"] == "MEDIUM"
    assert "aes_hex_key" in SECRETS_PATTERNS


def test_obfuscated_submodule_regex():
    """Verifies OBFUSCATED_SUBMODULE matches single letters and letter+digit tokens."""
    # Obfuscated tokens: single letter or letter + digits
    assert OBFUSCATED_SUBMODULE.match("a") is not None
    assert OBFUSCATED_SUBMODULE.match("Z") is not None
    assert OBFUSCATED_SUBMODULE.match("a1") is not None
    assert OBFUSCATED_SUBMODULE.match("b123") is not None
    assert OBFUSCATED_SUBMODULE.match("X9") is not None

    # Non-obfuscated tokens: multi-letter names or starting with digits
    assert OBFUSCATED_SUBMODULE.match("core") is None
    assert OBFUSCATED_SUBMODULE.match("utils") is None
    assert OBFUSCATED_SUBMODULE.match("123") is None
    assert OBFUSCATED_SUBMODULE.match("") is None
    assert OBFUSCATED_SUBMODULE.match("abc1") is None


def test_version_patterns_matching():
    """Verifies VERSION_PATTERNS correctly matches and captures versions."""
    test_strings = [
        "okhttp/4.12.0",
        "firebase-sessions:1.1.0",
        "Mixpanel (8.0.2)",
        "Crashlytics Android SDK/19.4.1",
        "com.google.gson:gson@@2.10.1",
    ]
    for ts in test_strings:
        matched = False
        for pat in VERSION_PATTERNS:
            if match := pat.search(ts):
                matched = True
                assert len(match.groups()) == 2
                break
        assert matched, f"Expected a match for {ts}"


def test_secrets_patterns_matching():
    """Verifies SECRETS_PATTERNS compiles and matches known secret signatures."""
    dummy_google = "".join(["AIza", "SyD-1234567890abcdefghijklmnopqrstuv"])
    dummy_slack = "-".join(["xoxb", "123456789012", "abcdefghijklmnopqrstuvwx"])
    dummy_stripe = "_".join(["sk", "live", "123456789012345678901234"])

    assert SECRETS_PATTERNS["google_api"].search(dummy_google) is not None
    assert SECRETS_PATTERNS["aws_key"].search("AKIAIOSFODNN7EXAMPLE") is not None
    assert SECRETS_PATTERNS["slack_token"].search(dummy_slack) is not None
    assert SECRETS_PATTERNS["stripe_standard"].search(dummy_stripe) is not None
    assert SECRETS_PATTERNS["rsa_private_key"].search("-----BEGIN RSA PRIVATE KEY-----") is not None


def test_packer_signatures():
    """Verifies PACKER_SIGNATURES defines lib and class patterns."""
    for info in PACKER_SIGNATURES.values():
        assert "libs" in info
        assert "classes" in info
        assert isinstance(info["libs"], list)
        assert isinstance(info["classes"], list)


def test_load_dynamic_rules_nonexistent_path(tmp_path):
    """load_dynamic_rules returns safely when the database file does not exist."""
    nonexistent = str(tmp_path / "nonexistent_rules.db")
    # Should not raise
    load_dynamic_rules(nonexistent)


def test_load_dynamic_rules_invalid_sqlite(tmp_path):
    """load_dynamic_rules logs warning on corrupt SQLite file and falls back gracefully."""
    corrupt_file = tmp_path / "corrupt.db"
    corrupt_file.write_bytes(b"not a sqlite database")

    with patch("scanner.util.rules.logger.warning") as mock_warn:
        load_dynamic_rules(str(corrupt_file))
        mock_warn.assert_called_once()
