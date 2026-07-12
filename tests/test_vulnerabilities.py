"""Unit tests for the vulnerability mapping and analysis scanner module (OWASP mapping)."""

import xml.etree.ElementTree as ET
from unittest.mock import MagicMock

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
        _map_m8_untrusted_inputs,
    )

    # M1: Credentials
    report_m1 = {
        "secrets": [{"type": "aws_key", "value": "AKIA..."}],
        "bytecode_audit": {"hardcoded_crypto_keys_detected": True, "hardcoded_crypto_keys_evidence": ["found key"]},
    }
    m1_vulns = _map_m1_credentials(report_m1)
    assert len(m1_vulns) == 2
    assert m1_vulns[0]["owasp_id"] == "M1"
    assert m1_vulns[1]["owasp_id"] == "M1"
    assert "AKIA..." in m1_vulns[0]["evidence"][0]

    # M2: Supply Chain
    report_m2 = {"dependencies": {"exact_versions_found": {"third_party": {}}}}
    m2_vulns = _map_m2_supply_chain(report_m2)
    assert len(m2_vulns) == 0

    # M3: Data storage
    report_m3 = {
        "manifest_audit": {"security_flags": {"allow_backup": True}},
        "bytecode_audit": {"zip_slip_detected": True, "zip_slip_evidence": ["zip slip"]},
    }
    m3_vulns = _map_m3_data_storage(report_m3)
    assert len(m3_vulns) == 2
    assert m3_vulns[0]["owasp_id"] == "M3"
    assert m3_vulns[1]["owasp_id"] == "M3"

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
        "bytecode_audit": {"ssl_bypass_detected": True, "ssl_bypass_evidence": ["ssl bypass"]},
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

    # M5: Platform interaction
    mock_apk = MagicMock()
    # No app elements in mock manifest to prevent audit_exported_components noise here
    mock_apk.get_android_manifest_xml.return_value = None
    report_m5 = {
        "bytecode_audit": {
            "unsafe_webview_settings_detected": True,
            "unsafe_webview_settings_evidence": ["webview unsafe"],
        }
    }
    m5_vulns = _map_m5_platform_interaction(mock_apk, report_m5)
    assert len(m5_vulns) == 1
    assert m5_vulns[0]["owasp_id"] == "M5"

    # M6: Security Controls
    report_m6 = {
        "manifest_audit": {"security_flags": {"debuggable": True}},
        "signatures": {"is_debug_signed": True},
        "bytecode_audit": {
            "dynamic_code_loading_detected": True,
            "dynamic_code_loading_evidence": ["dcl"],
        },
    }
    m6_vulns = _map_m6_security_controls(report_m6)
    assert len(m6_vulns) == 3
    for v in m6_vulns:
        assert v["owasp_id"] == "M6"

    # M7: Binary Protection
    report_m7 = {
        "security_checks": {"rooted_device_detection": {"detection_missing": True}},
        "signatures": {"has_weak_hash": True, "certificates": [{"subject": "CN=test", "hash_algo": "md5"}]},
        "bytecode_audit": {
            "insecure_crypto_mode_detected": True,
            "insecure_crypto_mode_evidence": ["ecb"],
        },
    }
    m7_vulns = _map_m7_binary_protection(report_m7)
    assert len(m7_vulns) == 3
    for v in m7_vulns:
        assert v["owasp_id"] == "M7"

    # M8: Untrusted Inputs
    m8_vulns = _map_m8_untrusted_inputs(mock_apk)
    assert len(m8_vulns) == 0


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
        "secrets": [{"type": "google_api", "pattern": "AIzaSy..."}],
        "security_checks": {"rooted_device_detection": {"detection_missing": True}},
        "dependencies": {},
        "network": {},
    }

    vulns = analyze_vulnerabilities(mock_apk, report)

    ids = [v["owasp_id"] for v in vulns]
    assert "M1" in ids  # Secrets
    assert "M3" in ids  # allowBackup
    assert "M4" in ids  # cleartext
    assert "M6" in ids  # debuggable
    assert "M7" in ids  # no root detection
