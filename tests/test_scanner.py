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
    """Verifies URL extraction from string pool and annotations."""
    mock_string = MagicMock()
    mock_string.get_value.return_value = "https://my-backend.com/api/v1"
    
    # Mock XREFs to attribute owner
    mock_class_anal = MagicMock()
    mock_class_anal.name = "Lcom/mycompany/app/NetworkHelper;"
    mock_string.get_xref_from.return_value = [(mock_class_anal, 0)]
    
    mock_dx = MagicMock()
    mock_dx.get_strings.return_value = [mock_string]
    mock_dx.get_classes.return_value = [] # Emtpy classes for annotation scanning
    
    result = extract_urls(mock_dx)
    
    assert "com.mycompany.app" in result
    assert "https://my-backend.com/api/v1" in result["com.mycompany.app"]

def test_extract_dependencies():
    """Verifies that class dependencies are correctly grouped and deduplicated."""
    mock_class_1 = MagicMock()
    mock_class_1.name = "Lcom/google/gson/Gson;"
    mock_class_2 = MagicMock()
    mock_class_2.name = "Lcom/google/gson/internal/ConstructorConstructor;"
    mock_class_3 = MagicMock()
    mock_class_3.name = "Lorg/jsoup/Jsoup;"
    mock_class_4 = MagicMock()
    mock_class_4.name = "Landroid/app/Activity;" # Should be ignored
    
    mock_dx = MagicMock()
    mock_dx.get_classes.return_value = [mock_class_1, mock_class_2, mock_class_3, mock_class_4]
    mock_dx.get_strings.return_value = []
    
    mock_apk = MagicMock()
    mock_apk.get_files.return_value = []
    
    result = extract_dependencies(mock_apk, mock_dx)
    
    assert "com.google" in result["external_libraries"]
    assert "gson" in result["external_libraries"]["com.google"]
    assert "org.jsoup" in result["external_libraries"]
    assert "android" not in result["external_libraries"]

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
    
    assert result["security_flags"]["allowBackup"] is False
    assert result["security_flags"]["debuggable"] is True
    assert result["security_flags"]["usesCleartextTraffic"] is False

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
    
    assert result["rooted_device_detection"] is True
    assert "Scottyab RootBeer library classes detected" in result["details"]["root_detection_indicators"]
    assert result["allows_static_analysis"] is False
    assert "Qihoo" in result["details"]["packer_detected"]

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
    assert result_1["security_flags"]["usesCleartextTraffic"] is False

    # Case 2: targetSdkVersion < 28 -> default cleartext should be True
    mock_xml_2 = MagicMock()
    mock_app_2 = MagicMock()
    mock_app_2.attrib = {}
    mock_xml_2.find.return_value = mock_app_2
    
    mock_apk_2 = MagicMock()
    mock_apk_2.get_android_manifest_xml.return_value = mock_xml_2
    mock_apk_2.get_target_sdk_version.return_value = "27"
    
    result_2 = analyze_manifest_security(mock_apk_2)
    assert result_2["security_flags"]["usesCleartextTraffic"] is True

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
