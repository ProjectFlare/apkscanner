"""Unit tests for the AndroidManifest.xml security auditing scanner module."""

import xml.etree.ElementTree as ET
from unittest.mock import MagicMock, patch

from scanner.scan_modules.manifest import (
    _find_network_security_config_path,
    _is_true,
    _parse_base_config_element,
    _parse_domain_config_element,
    _parse_single_apk_manifest_flags,
    analyze_manifest_security,
    parse_network_security_config,
    resolve_ref_value,
)


def test_analyze_manifest_security():
    """Verifies manifest security configurations auditing."""
    mock_xml = MagicMock()
    mock_xml.attrib = {}

    mock_application = MagicMock()
    mock_application.attrib = {
        "{http://schemas.android.com/apk/res/android}allowBackup": "false",
        "{http://schemas.android.com/apk/res/android}debuggable": "true",
        "{http://schemas.android.com/apk/res/android}usesCleartextTraffic": "false",
    }

    mock_xml.find.return_value = mock_application
    mock_apk = MagicMock()
    mock_apk.get_android_manifest_xml.return_value = mock_xml
    mock_apk.get_target_sdk_version.return_value = "28"

    result = analyze_manifest_security(mock_apk)

    assert result["security_flags"]["allow_backup"] is False
    assert result["security_flags"]["debuggable"] is True
    assert result["security_flags"]["uses_cleartext_traffic"] is False


def test_manifest_cleartext_default():
    """Verifies usesCleartextTraffic defaults based on targetSdkVersion."""
    # Case 1: targetSdkVersion >= 28 -> default cleartext should be False
    mock_xml_1 = MagicMock()
    mock_app_1 = MagicMock()
    mock_app_1.attrib = {}
    mock_xml_1.find.return_value = mock_app_1

    mock_apk_1 = MagicMock()
    mock_apk_1.get_android_manifest_xml.return_value = mock_xml_1
    mock_apk_1.get_target_sdk_version.return_value = "28"

    result_1 = analyze_manifest_security(mock_apk_1)
    assert result_1["security_flags"]["uses_cleartext_traffic"] is False

    # Case 2: targetSdkVersion < 28 -> default cleartext should be True
    mock_xml_2 = MagicMock()
    mock_app_2 = MagicMock()
    mock_app_2.attrib = {}
    mock_xml_2.find.return_value = mock_app_2

    mock_apk_2 = MagicMock()
    mock_apk_2.get_android_manifest_xml.return_value = mock_xml_2
    mock_apk_2.get_target_sdk_version.return_value = "27"

    result_2 = analyze_manifest_security(mock_apk_2)
    assert result_2["security_flags"]["uses_cleartext_traffic"] is True


def test_parse_network_security_config():
    """Verifies that network security configuration XML file is correctly parsed."""
    mock_apk = MagicMock()
    mock_apk.get_res_value.return_value = "res/xml/network_security_config.xml"

    xml_data = b"""<?xml version="1.0" encoding="utf-8"?>
    <network-security-config>
        <base-config cleartextTrafficPermitted="true">
            <trust-anchors>
                <certificates src="system" />
                <certificates src="user" />
            </trust-anchors>
        </base-config>
        <domain-config cleartextTrafficPermitted="true">
            <domain includeSubdomains="true">example.com</domain>
            <domain>test.org</domain>
        </domain-config>
    </network-security-config>
    """
    mock_apk.get_file.return_value = xml_data

    # Mock AXMLPrinter to just return the plaintext XML
    mock_axml = MagicMock()
    mock_axml.get_buff.return_value = xml_data

    with patch("scanner.scan_modules.manifest.AXMLPrinter", return_value=mock_axml):
        findings = parse_network_security_config(mock_apk, "@7F180004")

    assert findings["global_cleartext"] is True
    assert "example.com" in findings["domain_cleartext_list"]
    assert "test.org" in findings["domain_cleartext_list"]
    assert findings["trusts_user_certs"] is True


def test_resolve_ref_value():
    """Verifies manifest resource resolution works or falls back gracefully."""
    mock_apk = MagicMock()
    mock_apk.get_res_value.return_value = "my-resolved-value"

    # Resolves starting with @
    assert resolve_ref_value(mock_apk, "@7F110516") == "my-resolved-value"
    # Returns raw value if not starting with @
    assert resolve_ref_value(mock_apk, "raw-value") == "raw-value"
    # Falls back to raw value if resolution raises exception
    mock_apk_err = MagicMock()
    mock_apk_err.get_res_value.side_effect = Exception("error")
    assert resolve_ref_value(mock_apk_err, "@7F110516") == "@7F110516"


def test_manifest_internal_helpers():
    """Verifies internal helper functions of manifest parser."""
    # Test _find_network_security_config_path
    mock_apk = MagicMock()

    def get_res_side_effect(val):
        if val == "@7F180004":
            return "res/xml/net_config.xml"
        return None

    mock_apk.get_res_value.side_effect = get_res_side_effect
    assert _find_network_security_config_path(mock_apk, "@7F180004") == "res/xml/net_config.xml"

    mock_apk.get_files.return_value = ["res/xml/custom_config.xml"]
    assert _find_network_security_config_path(mock_apk, "xml/custom_config") == "res/xml/custom_config.xml"

    # Test _parse_base_config_element
    base_xml = ET.fromstring(
        '<base-config cleartextTrafficPermitted="false"><trust-anchors><certificates src="user" /></trust-anchors></base-config>'
    )
    findings = {"global_cleartext": None, "domain_cleartext_list": [], "trusts_user_certs": False}
    _parse_base_config_element(base_xml, findings)
    assert findings["global_cleartext"] is False
    assert findings["trusts_user_certs"] is True

    # Test _parse_domain_config_element
    domain_xml = ET.fromstring(
        '<domain-config cleartextTrafficPermitted="true"><domain>example.com</domain><domain>   test.org  </domain></domain-config>'
    )
    findings = {"global_cleartext": None, "domain_cleartext_list": [], "trusts_user_certs": False}
    _parse_domain_config_element(domain_xml, findings)
    assert "example.com" in findings["domain_cleartext_list"]
    assert "test.org" in findings["domain_cleartext_list"]

    # Test _parse_single_apk_manifest_flags
    mock_apk_flags = MagicMock()
    mock_xml = ET.fromstring(
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android"><application android:allowBackup="false" android:debuggable="true" /></manifest>'
    )
    mock_apk_flags.get_android_manifest_xml.return_value = mock_xml
    mock_apk_flags.get_target_sdk_version.return_value = "28"
    mock_apk_flags.get_res_value.side_effect = lambda x: x  # returns reference value

    android_ns = "{http://schemas.android.com/apk/res/android}"
    findings_apk = _parse_single_apk_manifest_flags(mock_apk_flags, android_ns)
    assert findings_apk is not None
    assert findings_apk["allow_backup"] is False
    assert findings_apk["debuggable"] is True
    assert findings_apk["uses_cleartext_traffic"] is False  # target sdk >= 28 default


def test_manifest_coverage_additional_branches():
    """Test additional branches in manifest.py to achieve 100% coverage."""
    # 1. _is_true coverage: None value and Boolean value
    assert _is_true(None, default=True) is True
    assert _is_true(None, default=False) is False
    assert _is_true(True) is True
    assert _is_true(False) is False

    # 2. _find_network_security_config_path config_path as list
    mock_apk = MagicMock()
    mock_apk.get_res_value.return_value = ["res/xml/net_config_list.xml"]
    assert _find_network_security_config_path(mock_apk, "@7F180004") == "res/xml/net_config_list.xml"

    # 3. parse_network_security_config: not config_path
    mock_apk.get_res_value.return_value = None
    mock_apk.get_files.return_value = []
    assert parse_network_security_config(mock_apk, "@7F180004") == {
        "global_cleartext": None,
        "domain_cleartext_list": [],
        "trusts_user_certs": False,
    }

    # 4. _load_network_security_config_xml: raw_data is None / empty
    mock_apk.get_res_value.return_value = "res/xml/net.xml"
    mock_apk.get_file.return_value = None
    assert parse_network_security_config(mock_apk, "@7F180004") == {
        "global_cleartext": None,
        "domain_cleartext_list": [],
        "trusts_user_certs": False,
    }

    # 5. _load_network_security_config_xml: xml_buff is None / empty
    mock_apk.get_file.return_value = b"some data"
    mock_axml = MagicMock()
    mock_axml.get_buff.return_value = None
    with patch("scanner.scan_modules.manifest.AXMLPrinter", return_value=mock_axml):
        assert parse_network_security_config(mock_apk, "@7F180004") == {
            "global_cleartext": None,
            "domain_cleartext_list": [],
            "trusts_user_certs": False,
        }

    # 6. _parse_domain_config_element with trust-anchors having user certs and recursion
    domain_xml = ET.fromstring(
        """<domain-config>
            <trust-anchors>
                <certificates src="user" />
            </trust-anchors>
            <domain-config cleartextTrafficPermitted="true">
                <domain>recursive.com</domain>
            </domain-config>
        </domain-config>"""
    )
    findings = {"global_cleartext": None, "domain_cleartext_list": [], "trusts_user_certs": False}
    _parse_domain_config_element(domain_xml, findings)
    assert findings["trusts_user_certs"] is True
    assert "recursive.com" in findings["domain_cleartext_list"]

    # 7. parse_network_security_config: exception raised inside try
    mock_apk.get_res_value.side_effect = Exception("error")
    assert parse_network_security_config(mock_apk, "@7F180004") == {
        "global_cleartext": None,
        "domain_cleartext_list": [],
        "trusts_user_certs": False,
    }
    mock_apk.get_res_value.side_effect = None

    # 8. _parse_single_apk_manifest_flags xml_root is None
    mock_apk.get_android_manifest_xml.return_value = None
    assert _parse_single_apk_manifest_flags(mock_apk, "ns") is None

    # 9. _parse_single_apk_manifest_flags app_elem is None
    mock_xml = ET.fromstring("<manifest></manifest>")
    mock_apk.get_android_manifest_xml.return_value = mock_xml
    assert _parse_single_apk_manifest_flags(mock_apk, "ns") is None

    # 10. _parse_single_apk_manifest_flags targetSdkVersion value error
    mock_xml = ET.fromstring("<manifest><application /></manifest>")
    mock_apk.get_android_manifest_xml.return_value = mock_xml
    mock_apk.get_target_sdk_version.return_value = "not_an_int"
    mock_apk.get_res_value.side_effect = lambda x: x
    findings_apk = _parse_single_apk_manifest_flags(mock_apk, "ns")
    assert findings_apk is not None
    assert findings_apk["uses_cleartext_traffic"] is True  # default to True on value error

    # 11. analyze_manifest_security list is empty
    assert analyze_manifest_security([]) == {
        "security_flags": {
            "allow_backup": False,
            "debuggable": False,
            "uses_cleartext_traffic": False,
            "network_security_config_missing": True,
            "request_legacy_external_storage": False,
        },
        "error": "No APK objects provided for manifest analysis.",
    }

    # 12. analyze_manifest_security parse exceptions and parsed_at_least_one is False
    mock_apk_err = MagicMock()
    mock_apk_err.get_android_manifest_xml.side_effect = Exception("manifest parse failed")
    result = analyze_manifest_security([mock_apk_err])
    assert "Failed to retrieve AndroidManifest XML" in result["error"]
    assert "manifest parse failed" in result["error"]

    # 13. analyze_manifest_security network security config found and legacy storage true
    mock_xml_full = ET.fromstring(
        """<manifest xmlns:android="http://schemas.android.com/apk/res/android">
            <application
                android:allowBackup="true"
                android:debuggable="false"
                android:usesCleartextTraffic="true"
                android:networkSecurityConfig="@7F180004"
                android:requestLegacyExternalStorage="true" />
        </manifest>"""
    )
    mock_apk_full = MagicMock()
    mock_apk_full.get_android_manifest_xml.return_value = mock_xml_full
    mock_apk_full.get_target_sdk_version.return_value = "28"
    mock_apk_full.get_res_value.side_effect = lambda x: "res/xml/network_security_config.xml" if x == "@7F180004" else x
    mock_apk_full.get_file.return_value = b"<network-security-config></network-security-config>"

    # Mock AXMLPrinter
    mock_axml = MagicMock()
    mock_axml.get_buff.return_value = b"<network-security-config></network-security-config>"

    with patch("scanner.scan_modules.manifest.AXMLPrinter", return_value=mock_axml):
        res_full = analyze_manifest_security([mock_apk_full])

    assert res_full["security_flags"]["allow_backup"] is True
    assert res_full["security_flags"]["debuggable"] is False
    assert res_full["security_flags"]["uses_cleartext_traffic"] is True
    assert res_full["security_flags"]["network_security_config_missing"] is False
    assert res_full["security_flags"]["request_legacy_external_storage"] is True
    assert "network_security_config" in res_full
