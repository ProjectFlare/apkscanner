# Test suite for APK Scanner.
# Verifies feature extraction, rules classifications, and analysis helpers.

import pytest
from unittest.mock import MagicMock

from scanner.permissions import extract_permissions
from scanner.secrets import extract_secrets
from scanner.domains import extract_domains
from scanner.urls import extract_urls
from scanner.dependencies import extract_dependencies
from scanner.architecture import analyze_ui_framework, analyze_cpu_architecture
from scanner.manifest import analyze_manifest_security
from scanner.security_checks import analyze_security_checks

def test_extract_permissions():
    """Verifies that permissions are classified into correct categories."""
    mock_apk = MagicMock()
    mock_apk.get_permissions.return_value = [
        "android.permission.CAMERA",                 # Dangerous runtime
        "android.permission.INTERNET",               # Normal install-time
        "com.google.android.c2dm.permission.RECEIVE", # System level (but not starting with android.permission. or com.android. so custom/third party)
        "com.custom.app.MY_PERMISSION"               # Custom/Third-party
    ]
    
    result = extract_permissions(mock_apk)
    
    assert "android.permission.CAMERA" in result["runtime_requested"]
    assert "android.permission.INTERNET" in result["install_time_or_system"]
    assert "com.google.android.c2dm.permission.RECEIVE" in result["custom_or_third_party"]
    assert "com.custom.app.MY_PERMISSION" in result["custom_or_third_party"]

def test_extract_secrets():
    """Verifies that secrets are identified from the DEX string pool."""
    mock_string_1 = MagicMock()
    mock_string_1.get_value.return_value = "AIzaSyA1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q" # Google API key
    mock_string_2 = MagicMock()
    mock_string_2.get_value.return_value = "AKIAIOSFODNN7EXAMPLE"                    # AWS key
    mock_string_3 = MagicMock()
    mock_string_3.get_value.return_value = "short_str"                               # Short non-secret
    
    mock_dx = MagicMock()
    mock_dx.get_strings.return_value = [mock_string_1, mock_string_2, mock_string_3]
    
    result = extract_secrets(mock_dx)
    
    types = [secret["type"] for secret in result]
    assert "google_api" in types
    assert "aws_key" in types
    assert len(result) == 2

def test_extract_domains():
    """Verifies domain categorization into cloud, trackers, and other."""
    urls = {
        "com.google.firebase": ["https://myproject.firebaseio.com/path", "https://googleapis.com/v1"],
        "com.mixpanel": ["http://api.mixpanel.com/track"],
        "com.example": ["https://mybackend.org/api", "https://schemas.android.com/apk/res/android"]
    }
    
    result = extract_domains(urls)
    
    assert "myproject.firebaseio.com" in result["cloud_services"]
    assert "googleapis.com" in result["cloud_services"]
    assert "api.mixpanel.com" in result["trackers_and_ads"]
    assert "mybackend.org" in result["other"]
    # Schemas must be ignored/filtered out
    assert not any("schemas.android.com" in d for category in result.values() for d in category)

def test_extract_urls():
    """Verifies URL extraction from string pool and annotations, including host normalization and obfuscation grouping."""
    mock_string_1 = MagicMock()
    mock_string_1.get_value.return_value = "https://my-backend.com/api/v1"
    mock_string_2 = MagicMock()
    mock_string_2.get_value.return_value = "https://my-backend.com/"
    mock_string_3 = MagicMock()
    mock_string_3.get_value.return_value = "https://square.github.io/wire/wire_compiler/#kotlin"
    
    # Mock XREFs to attribute owner
    mock_class_anal = MagicMock()
    mock_class_anal.name = "Lcom/mycompany/app/NetworkHelper;"
    mock_string_1.get_xref_from.return_value = [(mock_class_anal, 0)]
    mock_string_2.get_xref_from.return_value = [(mock_class_anal, 0)]
    
    mock_obf_class = MagicMock()
    mock_obf_class.name = "Lwi/r;"
    mock_string_3.get_xref_from.return_value = [(mock_obf_class, 0)]
    
    mock_dx = MagicMock()
    mock_dx.get_strings.return_value = [mock_string_1, mock_string_2, mock_string_3]
    mock_dx.get_classes.return_value = [] # Empty classes for annotation scanning
    
    result = extract_urls(mock_dx)
    
    assert "com.mycompany.app" in result
    assert "https://my-backend.com/api/v1" in result["com.mycompany.app"]
    # Trailing slash must be stripped for host-only URLs
    assert "https://my-backend.com" in result["com.mycompany.app"]
    assert "https://my-backend.com/" not in result["com.mycompany.app"]
    # Obfuscated package classes must be grouped under a generic key
    assert "obfuscated.classes" in result
    assert "https://square.github.io/wire/wire_compiler/#kotlin" in result["obfuscated.classes"]
    assert "wi.r" not in result

def test_extract_dependencies():
    """Verifies that class dependencies are correctly grouped and deduplicated, and app packages filtered."""
    mock_class_1 = MagicMock()
    mock_class_1.name = "Lcom/google/gson/Gson;"
    mock_class_2 = MagicMock()
    mock_class_2.name = "Lcom/google/gson/internal/ConstructorConstructor;"
    mock_class_3 = MagicMock()
    mock_class_3.name = "Lorg/jsoup/Jsoup;"
    mock_class_4 = MagicMock()
    mock_class_4.name = "Landroid/app/Activity;" # Should be ignored
    mock_class_5 = MagicMock()
    mock_class_5.name = "Lcom/example/app/MainActivity;" # Should be ignored (app package)
    
    mock_dx = MagicMock()
    mock_dx.get_classes.return_value = [mock_class_1, mock_class_2, mock_class_3, mock_class_4, mock_class_5]
    mock_dx.get_strings.return_value = []
    
    mock_apk = MagicMock()
    mock_apk.get_package.return_value = "com.example.app"
    mock_apk.get_files.return_value = ["play-services-base.properties"]
    mock_apk.get_file.return_value = b"version=18.5.0\nclient=play-services-base\n"
    
    result = extract_dependencies(mock_apk, mock_dx)
    
    assert "com.google" in result["external_libraries"]
    assert "gson" in result["external_libraries"]["com.google"]
    assert "org.jsoup" in result["external_libraries"]
    assert "android" not in result["external_libraries"]
    # App package must be ignored
    assert "com.example" not in result["external_libraries"]
    # Version from properties file must be extracted
    assert result["exact_versions_found"]["third_party"]["play-services-base"] == "18.5.0"

def test_analyze_ui_framework():
    """Verifies identification of UI frameworks."""
    mock_apk_flutter = MagicMock()
    mock_apk_flutter.get_files.return_value = ["lib/arm64-v8a/libflutter.so", "assets/flutter_assets/AssetManifest.json"]
    
    mock_dx = MagicMock()
    mock_dx.get_classes.return_value = []
    
    result = analyze_ui_framework(mock_apk_flutter, mock_dx)
    assert result == "Flutter"
    
    mock_apk_compose = MagicMock()
    mock_apk_compose.get_files.return_value = []
    mock_class = MagicMock()
    mock_class.name = "Landroidx/compose/runtime/Composer;"
    mock_dx_compose = MagicMock()
    mock_dx_compose.get_classes.return_value = [mock_class]
    
    result_compose = analyze_ui_framework(mock_apk_compose, mock_dx_compose)
    assert result_compose == "Native (Jetpack Compose)"

def test_analyze_cpu_architecture():
    """Verifies target hardware architecture detection."""
    mock_apk = MagicMock()
    mock_apk.get_files.return_value = [
        "lib/arm64-v8a/libnative.so",
        "lib/armeabi-v7a/libnative.so",
        "assets/images/logo.png"
    ]
    
    result = analyze_cpu_architecture(mock_apk)
    assert result == ["arm64-v8a", "armeabi-v7a"]

def test_analyze_manifest_security():
    """Verifies manifest security configurations auditing."""
    mock_xml = MagicMock()
    mock_xml.attrib = {}
    
    mock_application = MagicMock()
    mock_application.attrib = {
        "{http://schemas.android.com/apk/res/android}allowBackup": "false",
        "{http://schemas.android.com/apk/res/android}debuggable": "true",
        "{http://schemas.android.com/apk/res/android}usesCleartextTraffic": "false"
    }
    
    mock_xml.find.return_value = mock_application
    mock_apk = MagicMock()
    mock_apk.get_android_manifest_xml.return_value = mock_xml
    
    result = analyze_manifest_security(mock_apk)
    
    assert result["security_flags"]["allow_backup"] is False
    assert result["security_flags"]["debuggable"] is True
    assert result["security_flags"]["uses_cleartext_traffic"] is False

def test_analyze_security_checks():
    """Verifies checks for root beer detection classes and packer signatures."""
    mock_class_rootbeer = MagicMock()
    mock_class_rootbeer.name = "Lcom/scottyab/rootbeer/RootBeer;"
    mock_class_packer = MagicMock()
    mock_class_packer.name = "Lcom/qihoo/util/StubApp1;"
    
    mock_dx = MagicMock()
    mock_dx.get_classes.return_value = [mock_class_rootbeer, mock_class_packer]
    mock_dx.get_strings.return_value = []
    
    mock_apk = MagicMock()
    mock_apk.get_files.return_value = ["lib/armeabi-v7a/libjiagu.so"]
    
    result = analyze_security_checks(mock_apk, mock_dx)
    
    assert result["rooted_device_detection"]["detection_missing"] is False
    assert "Scottyab RootBeer library classes detected" in result["rooted_device_detection"]["indicators"]
    assert result["static_analysis"]["analysis_blocked"] is True
    assert "Qihoo" in result["static_analysis"]["packer_detected"]

def test_version_comparison():
    """Verifies that _is_newer_version correctly compares versions semantically."""
    from scanner.dependencies import _is_newer_version
    assert _is_newer_version("1.10.0", "1.9.0") is True
    assert _is_newer_version("1.9.0", "1.10.0") is False
    assert _is_newer_version("2.0.0", "1.10.0") is True
    assert _is_newer_version("1.10-beta", "1.9-alpha") is True

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

def test_extract_domains_edge_cases():
    """Verifies domain extraction handles userinfo, ports, and www prefixes correctly."""
    urls = {
        "com.edge.case": [
            "https://user:password@my-secure-backend.com:8080/path",
            "www.my-web-site.org/index.html",
            "http://localhost:3000/api"
        ]
    }
    result = extract_domains(urls)
    
    assert "my-secure-backend.com" in result["other"]
    assert "my-web-site.org" in result["other"]
    assert "localhost" in result["other"]

def test_resolve_maven_coordinate():
    """Verifies Maven coordinate resolution helper."""
    from scanner.vulnerabilities import resolve_maven_coordinate
    assert resolve_maven_coordinate("okhttp3") == "com.squareup.okhttp3:okhttp"
    assert resolve_maven_coordinate("org.jsoup:jsoup") == "org.jsoup:jsoup"
    assert resolve_maven_coordinate("com.example.lib") == "com.example.lib:lib"

def test_analyze_vulnerabilities_mapping():
    """Verifies mapping of report security issues to OWASP Mobile Top 10 categories."""
    from scanner.vulnerabilities import analyze_vulnerabilities
    
    mock_apk = MagicMock()
    mock_xml = MagicMock()
    mock_apk.get_android_manifest_xml.return_value = mock_xml
    mock_xml.find.return_value = None # No application element to avoid component audit noise
    
    # Mock report with allowBackup=True, debuggable=True, secrets and cleartext
    report = {
        "manifest_audit": {
            "security_flags": {
                "allow_backup": True,
                "debuggable": True,
                "uses_cleartext_traffic": True
            }
        },
        "secrets": [
            {"type": "google_api", "pattern": "AIzaSy..."}
        ],
        "security_checks": {
            "rooted_device_detection": {
                "detection_missing": True
            }
        },
        "dependencies": {},
        "network": {}
    }
    
    vulns = analyze_vulnerabilities(mock_apk, report)
    
    ids = [v["owasp_id"] for v in vulns]
    assert "M1" in ids # Secrets
    assert "M3" in ids # allowBackup
    assert "M4" in ids # cleartext
    assert "M6" in ids # debuggable
    assert "M7" in ids # no root detection

def test_parse_network_security_config():
    """Verifies that network security configuration XML file is correctly parsed."""
    from scanner.manifest import parse_network_security_config
    
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
    
    import unittest.mock as mock
    with mock.patch("scanner.manifest.AXMLPrinter", return_value=mock_axml):
        findings = parse_network_security_config(mock_apk, "@7F180004")
        
    assert findings["global_cleartext"] is True
    assert "example.com" in findings["domain_cleartext_list"]
    assert "test.org" in findings["domain_cleartext_list"]
    assert findings["trusts_user_certs"] is True

def test_audit_signatures():
    """Verifies that audit_signatures correctly parses certificates and sets flags."""
    from scanner.signatures import audit_signatures
    
    mock_cert = MagicMock()
    mock_cert.subject.human_friendly = "CN=Android Debug, O=Android, C=US"
    mock_cert.issuer.human_friendly = "CN=Android Debug, O=Android, C=US"
    mock_cert.serial_number = 12345
    mock_cert.sha256_fingerprint = "AA:BB:CC"
    mock_cert.sha1_fingerprint = "DD:EE"
    mock_cert.signature_algo = "sha256WithRSAEncryption"
    mock_cert.hash_algo = "sha256"
    mock_cert.self_signed = True
    
    mock_apk = MagicMock()
    mock_apk.is_signed_v1.return_value = True
    mock_apk.is_signed_v2.return_value = True
    mock_apk.is_signed_v3.return_value = False
    mock_apk.get_certificates.return_value = [mock_cert]
    
    result = audit_signatures([mock_apk])
    
    assert "v1" in result["scheme_versions"]
    assert "v2" in result["scheme_versions"]
    assert "v3" not in result["scheme_versions"]
    assert result["is_debug_signed"] is True
    assert result["has_weak_hash"] is False
    assert len(result["certificates"]) == 1
    assert result["certificates"][0]["serial_number"] == "12345"

def test_resolve_ref_value():
    """Verifies manifest resource resolution works or falls back gracefully."""
    from scanner.manifest import resolve_ref_value
    
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


def test_split_signatures_alignment():
    """Verifies split APK signature alignment validation logic."""
    from scanner.signatures import audit_signatures
    
    # Case 1: Base + split signed with the same cert
    mock_cert_base = MagicMock()
    mock_cert_base.subject.human_friendly = "CN=App, O=Developer"
    mock_cert_base.issuer.human_friendly = "CN=App, O=Developer"
    mock_cert_base.serial_number = 123
    mock_cert_base.sha256_fingerprint = "AA BB CC"
    mock_cert_base.sha1_fingerprint = "DD EE"
    mock_cert_base.signature_algo = "sha256"
    mock_cert_base.hash_algo = "sha256"
    
    mock_apk_base = MagicMock()
    mock_apk_base.is_signed_v1.return_value = True
    mock_apk_base.is_signed_v2.return_value = False
    mock_apk_base.is_signed_v3.return_value = False
    mock_apk_base.get_certificates.return_value = [mock_cert_base]
    mock_apk_base.filename = "base.apk"
    
    mock_cert_split = MagicMock()
    mock_cert_split.sha256_fingerprint = "AA BB CC"
    mock_apk_split = MagicMock()
    mock_apk_split.is_signed.return_value = True
    mock_apk_split.get_certificates.return_value = [mock_cert_split]
    mock_apk_split.filename = "split_config.apk"
    
    result_aligned = audit_signatures([mock_apk_base, mock_apk_split])
    assert result_aligned["split_signatures_aligned"] is True
    assert len(result_aligned["mismatched_splits"]) == 0
    
    # Case 2: Base + split signed with different cert
    mock_cert_mismatch = MagicMock()
    mock_cert_mismatch.sha256_fingerprint = "XX YY ZZ"
    mock_apk_mismatch = MagicMock()
    mock_apk_mismatch.is_signed.return_value = True
    mock_apk_mismatch.get_certificates.return_value = [mock_cert_mismatch]
    mock_apk_mismatch.filename = "split_mismatch.apk"
    
    result_mismatched = audit_signatures([mock_apk_base, mock_apk_mismatch])
    assert result_mismatched["split_signatures_aligned"] is False
    assert "split_mismatch.apk (signature mismatch)" in result_mismatched["mismatched_splits"]
    
    # Case 3: Base + unsigned split
    mock_apk_unsigned = MagicMock()
    mock_apk_unsigned.is_signed.return_value = False
    mock_apk_unsigned.filename = "split_unsigned.apk"
    
    result_unsigned = audit_signatures([mock_apk_base, mock_apk_unsigned])
    assert result_unsigned["split_signatures_aligned"] is False
    assert "split_unsigned.apk (unsigned)" in result_unsigned["mismatched_splits"]


def test_analyze_bytecode_semantic_checks():
    """Verifies that analyze_bytecode correctly identifies security vulnerabilities in Dalvik bytecode."""
    from scanner.bytecode_audit import analyze_bytecode
    
    # Setup mocks for class and string pool audits
    mock_dx = MagicMock()
    
    # 1. Mock SSL Bypass class
    mock_class_ssl = MagicMock()
    mock_class_ssl.is_external.return_value = False
    mock_class_ssl.name = "Lcom/example/MyTrustManager;"
    mock_vm_class = MagicMock()
    mock_vm_class.get_interfaces.return_value = ["Ljavax/net/ssl/X509TrustManager;"]
    mock_class_ssl.get_vm_class.return_value = mock_vm_class
    
    mock_method_ssl = MagicMock()
    mock_method_ssl.name = "checkServerTrusted"
    mock_enc_method = MagicMock()
    mock_inst = MagicMock()
    mock_inst.get_name.return_value = "return-void"
    mock_enc_method.get_instructions.return_value = [mock_inst]
    mock_method_ssl.get_method.return_value = mock_enc_method
    mock_class_ssl.get_methods.return_value = [mock_method_ssl]
    
    mock_dx.get_classes.return_value = [mock_class_ssl]
    
    # 2. Mock Insecure Cryptography string reference
    mock_string_crypto = MagicMock()
    mock_string_crypto.get_value.return_value = "AES/ECB/PKCS5Padding"
    mock_caller_class = MagicMock()
    mock_caller_class.name = "Lcom/example/CryptoHelper;"
    mock_caller_method = MagicMock()
    mock_caller_method.name = "encrypt"
    mock_string_crypto.get_xref_from.return_value = [(mock_caller_class, mock_caller_method)]
    mock_dx.get_strings.return_value = [mock_string_crypto]
    
    # 3. Mock WebView, DCL, Intent Redirection, Zip Slip method references to be empty
    mock_dx.get_methods.return_value = []
    
    result = analyze_bytecode(mock_dx)
    
    # Assertions
    assert result["ssl_bypass_detected"] is True
    assert any("com.example.MyTrustManager" in evidence for evidence in result["ssl_bypass_evidence"])
    assert result["insecure_crypto_mode_detected"] is True
    assert any("AES/ECB/PKCS5Padding" in evidence for evidence in result["insecure_crypto_mode_evidence"])


def test_ignored_tokens_in_tracker_exclusion():
    """Verifies that developer platform domains containing ignored tokens are not categorized as trackers."""
    from scanner.domains import extract_domains
    
    urls = {
        "com.google.gson": ["https://github.com/google/gson/issues"],
        "com.squareup.okhttp": ["https://squareup.com/help"]
    }
    
    result = extract_domains(urls)
    
    # github.com and squareup.com must NOT be in trackers_and_ads, they should fall to other
    assert "github.com" not in result["trackers_and_ads"]
    assert "squareup.com" not in result["trackers_and_ads"]
    assert "github.com" in result["other"]
    assert "squareup.com" in result["other"]

