"""Unit tests for the software dependency extraction scanner module."""

from unittest.mock import MagicMock

from scanner.scan_modules.dependencies import extract_dependencies


def test_extract_dependencies():
    """Verifies that class dependencies are correctly grouped and deduplicated, and app packages filtered."""
    mock_class_1 = MagicMock()
    mock_class_1.name = "Lcom/google/gson/Gson;"
    mock_class_2 = MagicMock()
    mock_class_2.name = "Lcom/google/gson/internal/ConstructorConstructor;"
    mock_class_3 = MagicMock()
    mock_class_3.name = "Lorg/jsoup/Jsoup;"
    mock_class_4 = MagicMock()
    mock_class_4.name = "Landroid/app/Activity;"  # Should be ignored
    mock_class_5 = MagicMock()
    mock_class_5.name = "Lcom/example/app/MainActivity;"  # Should be ignored (app package)

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


def test_resolve_maven_coordinate():
    """Verifies Maven coordinate resolution helper."""
    from scanner.scan_modules.vulnerabilities import resolve_maven_coordinate

    assert resolve_maven_coordinate("okhttp3") == "com.squareup.okhttp3:okhttp"
    assert resolve_maven_coordinate("org.jsoup:jsoup") == "org.jsoup:jsoup"
    assert resolve_maven_coordinate("com.example.lib") == "com.example.lib:lib"


def test_check_dependencies_osv(monkeypatch):
    """Verifies check_dependencies_osv queries OSV API correctly."""
    from scanner.scan_modules.vulnerabilities import check_dependencies_osv

    # Empty inputs
    assert check_dependencies_osv({}) == []

    # Mock response
    mock_response = MagicMock()
    mock_response.json.return_value = {
        "results": [
            {
                "vulns": [
                    {
                        "id": "GHSA-1234",
                        "summary": "Mocked dependency vuln",
                        "aliases": ["CVE-2026-9999"],
                    }
                ]
            }
        ]
    }

    mock_post = MagicMock(return_value=mock_response)
    monkeypatch.setattr("requests.post", mock_post)

    deps = {"okhttp3": "4.9.1"}
    vulns = check_dependencies_osv(deps)

    assert len(vulns) == 1
    assert vulns[0]["library"] == "com.squareup.okhttp3:okhttp"
    assert vulns[0]["version"] == "4.9.1"
    assert vulns[0]["vuln_id"] == "GHSA-1234"
    assert vulns[0]["cve_id"] == "CVE-2026-9999"

    # Test API error/exception fallback
    mock_post.side_effect = Exception("HTTP timeout")
    assert check_dependencies_osv(deps) == []


def test_dependencies_coverage():
    """Verifies all edge cases and fallback paths in dependencies module."""
    from scanner.scan_modules.dependencies import (
        _build_ignore_prefixes,
        _classify_versions,
        _collect_raw_packages,
        _extract_versions_from_metadata,
        _extract_versions_from_strings,
        _group_packages,
        _is_newer_version,
        _resolve_anonymous_version_files,
        _resolve_app_package,
    )

    # 1. Version key / newer version with Invalid PEP 440 versions
    assert _is_newer_version("abc-1.0", "abc-0.9") is True
    assert _is_newer_version("abc", "def") is False

    # 2. _resolve_app_package exception handling
    mock_apk_err = MagicMock()
    mock_apk_err.get_package.side_effect = Exception("error")
    assert _resolve_app_package([mock_apk_err]) is None

    # 3. _build_ignore_prefixes with 2 segments package name
    assert "Lcom/example/" in _build_ignore_prefixes("com.example")

    # 4. _collect_raw_packages edge cases
    mock_class_1 = MagicMock(name="cls1")
    mock_class_1.name = "Lfoo/Bar;"  # len(parts) < 2
    mock_class_2 = MagicMock(name="cls2")
    mock_class_2.name = "Laa/bb/Cc;"  # len(parts[0]) <= 2 and len(parts[1]) <= 2
    mock_class_3 = MagicMock(name="cls3")
    mock_class_3.name = "Lfoo-bar/baz/Quux;"  # invalid characters
    mock_dx = MagicMock()
    mock_dx.get_classes.return_value = [mock_class_1, mock_class_2, mock_class_3]
    assert len(_collect_raw_packages(mock_dx, ())) == 0

    # 5. _group_packages with obfuscated submodule
    grouped = _group_packages({"com.google.a", "com.google.b"})
    assert grouped["com.google"] == ["core"]

    # 6. _extract_versions_from_metadata with pom.properties, .version and exceptions
    mock_apk = MagicMock()
    mock_apk.get_files.return_value = [
        "META-INF/maven/com.google/gson/pom.properties",
        "META-INF/androidx.core.version",
        "assets/play-services-base.properties",
    ]

    # Setup files returns
    def get_file_side_effect(filename):
        if "pom.properties" in filename:
            return b"version=2.8.6\n"
        elif "androidx.core.version" in filename:
            return b"1.6.0\n"
        elif "play-services-base.properties" in filename:
            raise Exception("read error")  # force exception in _parse_general_properties
        return b""

    mock_apk.get_file.side_effect = get_file_side_effect

    versions = _extract_versions_from_metadata([mock_apk])
    assert versions["com.google:gson"] == "2.8.6"
    assert versions["androidx.core"] == "1.6.0"

    # Test pom.properties exception path
    mock_apk_pom_err = MagicMock()
    mock_apk_pom_err.get_files.return_value = ["META-INF/maven/com.google/gson/pom.properties"]
    mock_apk_pom_err.get_file.side_effect = Exception("pom error")
    assert _extract_versions_from_metadata([mock_apk_pom_err]) == {}

    # Test .version exception path
    mock_apk_ver_err = MagicMock()
    mock_apk_ver_err.get_files.return_value = ["META-INF/androidx.core.version"]
    mock_apk_ver_err.get_file.side_effect = Exception("ver error")
    assert _extract_versions_from_metadata([mock_apk_ver_err]) == {}

    # 7. _extract_versions_from_strings
    mock_str_1 = MagicMock()
    mock_str_1.get_value.return_value = "okhttp/4.9.0"
    mock_str_2 = MagicMock()
    mock_str_2.get_value.return_value = "okhttp/3.12.0"
    mock_dx_str = MagicMock()
    mock_dx_str.get_strings.return_value = [mock_str_1, mock_str_2]

    str_versions = {"okhttp": "4.0.0"}
    _extract_versions_from_strings(mock_dx_str, str_versions)
    assert str_versions["okhttp"] == "4.9.0"

    # 8. _resolve_anonymous_version_files
    mock_yubikey_class = MagicMock()
    mock_yubikey_class.name = "Lcom/yubico/yubikit/YubiKitManager;"
    mock_dx_yubi = MagicMock()
    mock_dx_yubi.get_classes.return_value = [mock_yubikey_class]
    yubi_versions = {"library": "1.0.0"}
    _resolve_anonymous_version_files(mock_dx_yubi, yubi_versions)
    assert yubi_versions["yubikit"] == "1.0.0"

    # 9. _classify_versions unconfirmed
    classified = _classify_versions({"lib1": "unconfirmed", "lib2": "1.0.0"})
    assert "lib1" not in classified["third_party"]
    assert classified["third_party"]["lib2"] == "1.0.0"
