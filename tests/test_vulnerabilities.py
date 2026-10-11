"""Unit tests for the vulnerability mapping and analysis scanner module (OWASP mapping)."""

import xml.etree.ElementTree as ET
from unittest.mock import MagicMock, patch

from scanner.scan_modules.vulnerabilities import (
    analyze_vulnerabilities,
    audit_exported_components,
    audit_intent_schemas,
)


def test_audit_exported_components():
    """Verifies exported components audit logic from manifest."""
    # Build a mock XML manifest
    xml_content = """<?xml version="1.0" encoding="utf-8"?>
    <manifest xmlns:android="http://schemas.android.com/apk/res/android">
        <application>
            <!-- Case 1: Exported component without permission (exposed) -->
            <activity android:name="com.example.ExposedActivity" android:exported="true" />
            <!-- Case 2: Exported component with permission (guarded) -->
            <activity android:name="com.example.GuardedActivity" android:exported="true" android:permission="android.permission.BIND_JOB_SERVICE" />
            <!-- Case 3: Non-exported component (safe) -->
            <service android:name="com.example.PrivateService" android:exported="false" />
            <!-- Case 4: Default exported activity because of intent-filters (exposed) -->
            <receiver android:name="com.example.ImplicitReceiver">
                <intent-filter>
                    <action android:name="android.intent.action.BOOT_COMPLETED" />
                </intent-filter>
            </receiver>
            <!-- Case 5: Launcher activity (safe by design) -->
            <activity android:name="com.example.MainActivity" android:exported="true">
                <intent-filter>
                    <action android:name="android.intent.action.MAIN" />
                    <category android:name="android.intent.category.LAUNCHER" />
                </intent-filter>
            </activity>
        </application>
    </manifest>
    """

    mock_apk = MagicMock()
    mock_root = ET.fromstring(xml_content)
    mock_apk.get_android_manifest_xml.return_value = mock_root
    mock_apk.get_res_value.side_effect = lambda x: x

    exposed = audit_exported_components(mock_apk)

    # Exposed should have ExposedActivity and ImplicitReceiver
    exposed_names = [e["name"] for e in exposed]
    assert "com.example.ExposedActivity" in exposed_names
    assert "com.example.ImplicitReceiver" in exposed_names
    assert "com.example.GuardedActivity" not in exposed_names
    assert "com.example.PrivateService" not in exposed_names
    assert "com.example.MainActivity" not in exposed_names

    # Test manifest exception fallback
    mock_apk.get_android_manifest_xml.side_effect = Exception("manifest error")
    assert audit_exported_components(mock_apk) == []


def test_audit_intent_schemas():
    """Verifies intent schemas custom scheme auditing from manifest."""
    # Build mock XML manifest
    xml_content = """<?xml version="1.0" encoding="utf-8"?>
    <manifest xmlns:android="http://schemas.android.com/apk/res/android">
        <application>
            <activity android:name="com.example.DeepLinkActivity">
                <intent-filter>
                    <data android:scheme="myapp" android:host="profile" />
                    <!-- Excluded schemes -->
                    <data android:scheme="https" android:host="example.com" />
                    <data android:scheme="http" />
                </intent-filter>
            </activity>
        </application>
    </manifest>
    """

    mock_apk = MagicMock()
    mock_root = ET.fromstring(xml_content)
    mock_apk.get_android_manifest_xml.return_value = mock_root
    mock_apk.get_res_value.side_effect = lambda x: x

    schemes = audit_intent_schemas(mock_apk)

    assert len(schemes) == 1
    assert schemes[0]["activity"] == "com.example.DeepLinkActivity"
    assert schemes[0]["scheme"] == "myapp"
    assert schemes[0]["host"] == "profile"

    # Test manifest exception fallback
    mock_apk.get_android_manifest_xml.side_effect = Exception("manifest error")
    assert audit_intent_schemas(mock_apk) == []


def test_owasp_mapping_helpers():
    """Verifies each individual OWASP mapping helper function parses correctly."""
    from scanner.scan_modules.vulnerabilities import (
        _map_m1_credentials,
        _map_m2_supply_chain,
        _map_m3_data_storage,
        _map_m4_communication,
        _map_m5_platform_interaction,
        _map_m6_security_controls,
        _map_m7_binary_protection,
    )

    # M1: Credentials (informational only now, not confirmed vulnerabilities)
    report_m1 = {
        "secrets": [{"type": "aws_key", "value": "AKIA..."}],
        "bytecode_audit": {"hardcoded_crypto_keys": ["found key"]},
    }
    m1_vulns = _map_m1_credentials(report_m1)
    assert len(m1_vulns) == 0

    # M2: Supply Chain (empty)
    report_m2 = {"dependencies": {"third_party": {}}}
    m2_vulns = _map_m2_supply_chain(report_m2)
    assert len(m2_vulns) == 0

    # M2: Supply Chain (unified schema)
    report_m2_unified = {
        "dependencies": {
            "third_party": {
                "com.squareup.okhttp3:okhttp": {
                    "version_used": "4.9.0",
                    "latest_version": "5.0.0",
                    "osv_findings": [
                        {
                            "library": "com.squareup.okhttp3:okhttp",
                            "version": "4.9.0",
                            "cve_id": "CVE-2021-0341",
                            "summary": "Hostname verification bypass",
                            "details_url": "https://osv.dev/vulnerability/GHSA-example",
                        }
                    ],
                }
            },
            "android_default": {},
        }
    }
    unified_vulns = _map_m2_supply_chain(report_m2_unified)
    assert len(unified_vulns) == 1
    assert unified_vulns[0]["owasp_id"] == "M2"
    assert unified_vulns[0]["masvs_id"] == "MASVS-CODE-4"
    assert "CVE-2021-0341" in unified_vulns[0]["evidence"][0]

    # M2 consumes legacy OSV results precomputed at scan time WITHOUT re-querying OSV.dev.
    report_m2_stored = {
        "dependencies": {
            "osv_findings": [
                {
                    "library": "com.squareup.okhttp3:okhttp",
                    "version": "4.9.0",
                    "cve_id": "CVE-2021-0341",
                    "summary": "Hostname verification bypass",
                    "details_url": "https://osv.dev/vulnerability/GHSA-example",
                }
            ]
        }
    }
    with patch(
        "scanner.scan_modules.vulnerabilities.check_dependencies_osv",
        side_effect=AssertionError("must not re-query OSV when osv_findings is stored"),
    ):
        stored_vulns = _map_m2_supply_chain(report_m2_stored)
    assert len(stored_vulns) == 1
    assert stored_vulns[0]["owasp_id"] == "M2"
    assert stored_vulns[0]["masvs_id"] == "MASVS-CODE-4"
    assert stored_vulns[0]["mastg_id"] == "MASTG-CODE-4"
    assert "CVE-2021-0341" in stored_vulns[0]["evidence"][0]

    # M3: Data storage (zip_slip is informational only, allow_backup is confirmed)
    report_m3 = {
        "manifest_audit": {"security_flags": {"allow_backup": True}},
        "bytecode_audit": {"zip_slip": ["zip slip"]},
    }
    m3_vulns = _map_m3_data_storage(report_m3)
    assert len(m3_vulns) == 1
    assert m3_vulns[0]["owasp_id"] == "M3"
    assert m3_vulns[0]["masvs_id"] == "MASVS-STORAGE-2"

    # M4: Communication
    report_m4 = {
        "manifest_audit": {
            "security_flags": {"uses_cleartext_traffic": True},
            "network_security_config": {
                "global_cleartext": True,
                "domain_cleartext_list": ["clear.com"],
                "trusts_user_certs": True,
            },
        },
        "network": {
            "attributed_urls": {"com.foo": ["http://insecure-url.com"]},
            "categorized_domains": {"other": ["malicious.com"]},
        },
        "bytecode_audit": {"ssl_bypass": ["ssl bypass"]},
    }
    m4_vulns = _map_m4_communication(report_m4)
    # Cleartext (uses_cleartext_traffic or malicious domain or http urls) -> 1
    # Global cleartext -> 1
    # Domain cleartext -> 1
    # User certs -> 1
    # SSL bypass -> 1
    # Total = 5
    assert len(m4_vulns) == 5
    for v in m4_vulns:
        assert v["owasp_id"] == "M4"
        assert v["masvs_id"].startswith("MASVS-NETWORK")

    # M5: Platform interaction — universal access is HIGH, local file access is MEDIUM.
    report_m5_universal = {
        "bytecode_audit": {
            "unsafe_webview_settings": [
                "Class 'com.example.Viewer' in method 'init' calls setAllowUniversalAccessFromFileURLs while JavaScript is enabled."
            ],
        }
    }
    m5_vulns_u = _map_m5_platform_interaction(report_m5_universal)
    assert len(m5_vulns_u) == 1
    assert "Universal" in m5_vulns_u[0]["title"]
    assert m5_vulns_u[0]["severity"] == "HIGH"

    report_m5_local = {
        "bytecode_audit": {
            "unsafe_webview_settings": [
                "Class 'com.example.Help' in method 'init' calls setAllowFileAccess while JavaScript is enabled."
            ],
        }
    }
    m5_vulns_l = _map_m5_platform_interaction(report_m5_local)
    assert len(m5_vulns_l) == 1
    assert "Permissive" in m5_vulns_l[0]["title"]
    assert m5_vulns_l[0]["severity"] == "MEDIUM"

    # M6: Security Controls — debuggable + debug-signed (dynamic code loading moved to informational).
    report_m6 = {
        "manifest_audit": {"security_flags": {"debuggable": True}},
        "signatures": {"is_debug_signed": True},
        "bytecode_audit": {
            "dynamic_code_loading": ["dcl"],
        },
    }
    m6_vulns = _map_m6_security_controls(report_m6)
    assert len(m6_vulns) == 2
    assert m6_vulns[0]["owasp_id"] == "M6"
    assert m6_vulns[0]["masvs_id"] == "MASVS-CODE-2"
    assert m6_vulns[1]["owasp_id"] == "M6"
    assert m6_vulns[1]["masvs_id"] == "MASVS-CODE-1"

    # M7: Binary Protection — weak hash + insecure crypto + deprecated cipher (DES) + unpadded ECB.
    report_m7 = {
        "security_checks": {"rooted_device_detection": []},
        "signatures": {"has_weak_hash": True, "certificates": [{"subject": "CN=test", "hash_algo": "md5"}]},
        "bytecode_audit": {
            "insecure_crypto_mode": ["AES/ECB/PKCS5Padding"],
            "unpadded_ecb_primitive": ["Unpadded single-block ECB mode 'AES/ECB/NoPadding' referenced in nm0"],
            "deprecated_cipher_algorithm": ["Insecure crypto algorithm/mode 'DES' referenced in NTLMEngineImpl"],
        },
    }
    m7_vulns = _map_m7_binary_protection(report_m7)
    assert len(m7_vulns) == 4
    assert m7_vulns[0]["owasp_id"] == "M7"
    assert m7_vulns[0]["masvs_id"] == "MASVS-CODE-1"
    # Deprecated cipher (DES) is MEDIUM (OWASP M10)
    des_vuln = next(v for v in m7_vulns if "DES" in v["title"])
    assert des_vuln["severity"] == "MEDIUM"
    assert des_vuln["owasp_id"] == "M10"
    # Unpadded ECB primitive (NoPadding) is MEDIUM (OWASP M10)
    unpad_vuln = next(v for v in m7_vulns if "NoPadding" in v["title"] or "Unpadded" in v["title"])
    assert unpad_vuln["severity"] == "MEDIUM"
    assert unpad_vuln["owasp_id"] == "M10"
    # AES/ECB/PKCS5Padding is HIGH (OWASP M10)
    ecb_vuln = next(v for v in m7_vulns if "Insecure Cryptographic Encryption Mode (ECB)" in v["title"])
    assert ecb_vuln["severity"] == "HIGH"
    assert ecb_vuln["owasp_id"] == "M10"

    # M7: v1-only (JAR) signing is a Janus-exposure finding; the minSdk evidence states
    # whether Janus-vulnerable Android versions (API <= 27) can install the app.
    report_v1 = {
        "apk_metadata": {"min_sdk_version": "21"},
        "signatures": {"v1_only_signature": True, "scheme_versions": ["v1"]},
    }
    v1_vulns = _map_m7_binary_protection(report_v1)
    assert len(v1_vulns) == 1
    assert v1_vulns[0]["owasp_id"] == "M7"
    assert "Janus" in v1_vulns[0]["title"]
    assert any("installable on Janus-vulnerable" in e for e in v1_vulns[0]["evidence"])

    report_v1_modern = {
        "apk_metadata": {"min_sdk_version": "28"},
        "signatures": {"v1_only_signature": True, "scheme_versions": ["v1"]},
    }
    modern_vulns = _map_m7_binary_protection(report_v1_modern)
    assert len(modern_vulns) == 0


def test_analyze_vulnerabilities_mapping():
    """Verifies mapping of report security issues to OWASP Mobile Top 10 categories."""
    mock_apk = MagicMock()
    mock_xml = MagicMock()
    mock_apk.get_android_manifest_xml.return_value = mock_xml
    mock_xml.find.return_value = None  # No application element to avoid component audit noise

    # Mock report with allowBackup=True, debuggable=True, secrets and cleartext
    report = {
        "manifest_audit": {
            "security_flags": {"allow_backup": True, "debuggable": True, "uses_cleartext_traffic": True}
        },
        "secrets": [{"type": "google_api", "value": "AIzaSy..."}],
        "security_checks": {"rooted_device_detection": []},
        "dependencies": {},
        "network": {},
    }

    vulns = analyze_vulnerabilities(report)

    ids = [v["owasp_id"] for v in vulns]
    assert "M1" not in ids  # Secrets are now in informational security posture
    assert "M3" in ids  # allowBackup
    assert "M4" in ids  # cleartext
    assert "M6" in ids  # debuggable
    # Missing root detection is no longer a scored M7 finding; it is informational only.
    assert "M7" not in ids


def test_analyze_security_posture_informational_items():
    """Posture collects attack-surface + defensive signals with no severity/score fields."""
    from scanner.scan_modules.vulnerabilities import analyze_security_posture

    mock_apk = MagicMock()
    mock_apk.get_android_manifest_xml.return_value = None  # no exported/scheme noise
    report = {
        "security_checks": {
            "rooted_device_detection": ["RootBeer detected"],
            "static_analysis": {"packer_detected": None},
        },
        "secrets": [{"type": "google_api", "value": "AIzaSy..."}],
        "bytecode_audit": {
            "dynamic_code_loading": ["PathClassLoader"],
            "zip_slip": ["Class 'com.airbnb.lottie' extracts ZipEntry"],
        },
    }
    items = analyze_security_posture(mock_apk, report)
    by_type = {i["type"]: i for i in items}

    # Only present facts are returned: root detection is present, packer is absent so it is omitted.
    # Dedicated sections audit secrets (Section 6) and bytecode (Section 7), so they are excluded here.
    assert "root_detection" in by_type
    assert "packer" not in by_type
    assert "dynamic_code_loading" in by_type
    assert "hardcoded_secrets" not in by_type
    assert "zip_slip" not in by_type
    # Presence in the list is the signal itself; items carry no status flag and must never
    # carry a severity, score, or owasp_id.
    for item in items:
        assert "status" not in item
        assert "severity" not in item
        assert "owasp_id" not in item


def test_analyze_security_posture_omits_absent_items():
    """Absent defensive features (no root detection, no packer) are omitted, not listed as absent."""
    from scanner.scan_modules.vulnerabilities import analyze_security_posture

    mock_apk = MagicMock()
    mock_apk.get_android_manifest_xml.return_value = None
    items = analyze_security_posture(mock_apk, {})
    assert items == []  # nothing present -> empty, so the section stays useful


def test_map_m4_cleartext_suppressed_when_cleartext_traffic_disabled():
    """Plain http:// URLs in bytecode must NOT generate a cleartext finding if cleartext is blocked."""
    from scanner.scan_modules.vulnerabilities import _map_m4_communication

    report_blocked = {
        "manifest_audit": {
            "security_flags": {"uses_cleartext_traffic": False},
            "network_security_config": {
                "global_cleartext": False,
                "domain_cleartext_list": [],
                "trusts_user_certs": False,
            },
        },
        "network": {
            "attributed_urls": {"com.example.app": ["http://insecure.example.com", "http://example.org"]},
            "categorized_domains": {"other": ["insecure.example.com"]},
        },
        "bytecode_audit": {"ssl_bypass": []},
    }
    vulns = _map_m4_communication(report_blocked)
    assert len(vulns) == 0

    # If domain is in domain_cleartext_list, it must be flagged
    report_domain_allowed = {
        "manifest_audit": {
            "security_flags": {"uses_cleartext_traffic": False},
            "network_security_config": {
                "global_cleartext": False,
                "domain_cleartext_list": ["insecure.example.com"],
                "trusts_user_certs": False,
            },
        },
        "network": {
            "attributed_urls": {"com.example.app": ["http://insecure.example.com", "http://example.org"]},
            "categorized_domains": {},
        },
        "bytecode_audit": {"ssl_bypass": []},
    }
    vulns_domain = _map_m4_communication(report_domain_allowed)
    assert len(vulns_domain) == 2  # cleartext_traffic (for insecure.example.com) and net_domain_cleartext
    titles = [v["title"] for v in vulns_domain]
    assert "Cleartext Traffic Allowed or Insecure Hosts" in titles
    assert "Domain-Specific Cleartext Traffic Permitted" in titles


def test_map_m1_filters_public_client_identifiers():
    """Public OAuth Client IDs and Firebase App IDs must not trigger hardcoded secret vulnerabilities."""
    from scanner.scan_modules.vulnerabilities import _map_m1_credentials

    report_public_only = {
        "secrets": [
            {"type": "google_oauth", "value": "123-abc.apps.googleusercontent.com"},
            {"type": "firebase_app_id", "value": "1:123:android:456"},
        ],
        "bytecode_audit": {},
    }
    vulns = _map_m1_credentials(report_public_only)
    assert len(vulns) == 0


def test_map_m7_filters_trusted_crypto_libraries():
    """Bytecode references to AES/ECB inside Google Tink or BouncyCastle must be ignored."""
    from scanner.scan_modules.vulnerabilities import _map_m7_binary_protection

    report_tink = {
        "signatures": {},
        "bytecode_audit": {
            "insecure_crypto_mode": [
                "Insecure crypto algorithm/mode 'AES/ECB/NoPadding' referenced in class 'Og.o [com.google.crypto.tink]' method '<init>'."
            ],
        },
    }
    vulns = _map_m7_binary_protection(report_tink)
    assert len(vulns) == 0

    report_pslocks = {
        "signatures": {},
        "bytecode_audit": {
            "insecure_crypto_mode": [
                "Insecure crypto algorithm/mode 'AES/ECB/NoPadding' referenced in class 'B8.h [com.pslocks.sdk]' method 'b'."
            ],
        },
    }
    vulns_pslocks = _map_m7_binary_protection(report_pslocks)
    assert len(vulns_pslocks) == 0

    # Weak hash: omitted when modern v2 or v3 scheme is present
    report_v2_weak_hash = {
        "signatures": {
            "has_weak_hash": True,
            "scheme_versions": ["v1", "v2"],
            "certificates": [{"subject": "CN=test", "hash_algo": "sha1"}],
        },
        "bytecode_audit": {},
    }
    assert len(_map_m7_binary_protection(report_v2_weak_hash)) == 0

    # Custom first-party code using AES/ECB/PKCS5Padding is flagged as HIGH
    report_custom = {
        "signatures": {},
        "bytecode_audit": {
            "insecure_crypto_mode": [
                "Insecure crypto algorithm/mode 'AES/ECB/PKCS5Padding' referenced in class 'com.app.CryptoHelper' method 'encrypt'."
            ],
        },
    }
    vulns_custom = _map_m7_binary_protection(report_custom)
    assert len(vulns_custom) == 1
    assert vulns_custom[0]["masvs_id"] == "MASVS-CRYPTO-1"

    # Weak hash: flagged as HIGH when strictly v1-only
    report_v1_weak_hash = {
        "signatures": {
            "has_weak_hash": True,
            "v1_only_signature": True,
            "scheme_versions": ["v1"],
            "certificates": [{"subject": "CN=test", "hash_algo": "sha1"}],
        },
        "bytecode_audit": {},
    }
    v1_wh_vulns = _map_m7_binary_protection(report_v1_weak_hash)
    v1_titles = [v["title"] for v in v1_wh_vulns]
    assert "Weak Signature Hash Algorithm" in v1_titles
