"""Unit tests for the software dependency extraction scanner module."""

from unittest.mock import MagicMock, patch

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
    mock_dx.get_internal_classes.return_value = [mock_class_1, mock_class_2, mock_class_3, mock_class_4, mock_class_5]
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
    # Version from properties file must be extracted, classified under the Google SDK bucket
    assert (
        result["exact_versions_found"]["third_party"]["google_sdk"]["com.google.android.gms:play-services-base"]
        == "18.5.0"
    )


def test_resolve_maven_coordinate():
    """Verifies Maven coordinate resolution helper."""
    from scanner.scan_modules.vulnerabilities import resolve_maven_coordinate

    assert resolve_maven_coordinate("okhttp3") == "com.squareup.okhttp3:okhttp"
    assert resolve_maven_coordinate("org.jsoup:jsoup") == "org.jsoup:jsoup"
    assert resolve_maven_coordinate("com.example.lib") == "com.example.lib:lib"
    # Google maven .properties keys ("<groupId>_<artifactId>") resolve to real coordinates.
    assert resolve_maven_coordinate("androidx.activity_activity-compose") == "androidx.activity:activity-compose"
    assert resolve_maven_coordinate("com.google.android.material_material") == "com.google.android.material:material"
    # Names without a dotted group skip the underscore split and use explicit mappings instead.
    assert resolve_maven_coordinate("kotlinx_coroutines_core") == "org.jetbrains.kotlinx:kotlinx-coroutines-core"
    assert resolve_maven_coordinate("text-recognition-korean") == "com.google.mlkit:text-recognition-korean"


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
    assert "lib1" not in classified["third_party"]["independent"]
    assert classified["third_party"]["independent"]["lib2"] == "1.0.0"


def test_classify_versions_splits_google_sdk_from_independent():
    """Third-party deps are split into google_sdk (Play services/Firebase/ML Kit/Play Core) and independent."""
    from scanner.scan_modules.dependencies import _classify_versions

    classified = _classify_versions(
        {
            "androidx.core": "1.9.0",
            "play-services-base": "18.10.0",
            "firebase-encoders": "17.0.0",
            "datatransport": "3.3.0",
            "review": "2.0.2",
            "crashlytics android sdk": "20.0.6",
            "okhttp": "5.3.2",
            "com.google.dagger_dagger": "2.59",
            "gson": "2.13.1",
        }
    )
    assert classified["system"] == {"androidx.core": "1.9.0"}
    # Bare Google names resolve to their canonical MAVEN_MAPPING coordinates, so the AI
    # report and OSV lookups always work with an unambiguous group:artifact.
    assert set(classified["third_party"]["google_sdk"]) == {
        "com.google.android.gms:play-services-base",
        "com.google.firebase:firebase-encoders",
        "com.google.android.datatransport:transport-api",
        "com.google.android.play:review",
        "com.google.firebase:firebase-crashlytics",
    }
    assert set(classified["third_party"]["independent"]) == {"okhttp", "com.google.dagger_dagger", "gson"}


def test_flatten_third_party_merges_both_buckets():
    """flatten_third_party merges google_sdk and independent into one name-to-version mapping."""
    from scanner.scan_modules.dependencies import flatten_third_party

    third_party = {
        "google_sdk": {"play-services-base": "18.10.0"},
        "independent": {"okhttp": "5.3.2"},
    }
    assert flatten_third_party(third_party) == {"play-services-base": "18.10.0", "okhttp": "5.3.2"}
    assert flatten_third_party({}) == {}


def test_resolve_latest_versions_prefetches_third_party_only():
    """Latest versions are resolved once at scan time for every third-party dependency, so the
    report model does not have to call lookup_maven_version per entry. Names that cannot be
    resolved are omitted, which keeps 'never looked up' distinguishable from 'unknown'."""
    from scanner.scan_modules.dependencies import resolve_latest_versions

    third_party = {
        "google_sdk": {"play-services-base": "18.10.0"},
        "independent": {"okhttp": "5.3.2", "totally-unresolvable-name": "1.0"},
    }

    def fake_resolve(group, artifact):
        if artifact == "okhttp":
            return "5.4.0", "https://mvnrepository.com/artifact/com.squareup.okhttp3/okhttp"
        if artifact == "play-services-base":
            return "18.10.0", "https://maven.google.com/x"
        return None

    with patch("scanner.web.lookups.resolve_latest_version", side_effect=fake_resolve):
        resolved = resolve_latest_versions(third_party)

    assert resolved["okhttp"]["latest_version"] == "5.4.0"
    assert resolved["okhttp"]["source_url"].endswith("okhttp")
    assert resolved["play-services-base"]["latest_version"] == "18.10.0"
    assert "totally-unresolvable-name" not in resolved

    # A lookup that raises must not abort the whole prefetch.
    with patch("scanner.web.lookups.resolve_latest_version", side_effect=RuntimeError("network down")):
        assert resolve_latest_versions(third_party) == {}

    assert resolve_latest_versions({}) == {}


def test_flatten_for_osv_includes_system_bucket():
    """flatten_for_osv merges system libraries with both third-party buckets so the OSV CVE
    check also covers AndroidX/Play Services entries; third-party wins on name collisions."""
    from scanner.scan_modules.dependencies import flatten_for_osv

    exact_versions = {
        "system": {"androidx.activity_activity": "1.13.0", "shared-name": "1.0"},
        "third_party": {
            "google_sdk": {"play-services-base": "18.10.0"},
            "independent": {"okhttp": "5.3.2", "shared-name": "2.0"},
        },
    }
    flat = flatten_for_osv(exact_versions)
    assert flat["androidx.activity_activity"] == "1.13.0"
    assert flat["play-services-base"] == "18.10.0"
    assert flat["okhttp"] == "5.3.2"
    assert flat["shared-name"] == "2.0"
    assert flatten_for_osv({}) == {}


def test_find_unversioned_third_party_drops_libraries_with_a_resolved_version():
    """Libraries already covered by an exact version (even under a differently-spelled key,
    e.g. okhttp3 vs okhttp) are excluded from the unversioned set."""
    from scanner.scan_modules.dependencies import find_unversioned_third_party

    external_libraries = {
        "okhttp3": ["internal"],
        "com.google": ["dagger"],
        "io.ktor": ["client", "http"],
        "org.bouncycastle": ["jsse"],
    }
    third_party = {
        "google_sdk": {"play-services-base": "18.10.0"},
        "independent": {"okhttp": "5.3.2", "com.google.dagger_dagger": "2.59"},
    }
    result = find_unversioned_third_party(external_libraries, third_party)
    assert result == {"io.ktor": ["client", "http"], "org.bouncycastle": ["jsse"]}


def test_find_unversioned_third_party_empty_inputs():
    """No external libraries or no third-party versions both yield an empty/complete result."""
    from scanner.scan_modules.dependencies import find_unversioned_third_party

    assert find_unversioned_third_party({}, {"independent": {"okhttp": "5.3.2"}}) == {}
    assert find_unversioned_third_party({"leakcanary": ["internal"]}, {}) == {"leakcanary": ["internal"]}


def test_parse_version_file_keeps_names_containing_version_substring():
    """Only the trailing '.version' extension is stripped, so a name like
    'androidx.versionedparcelable_versionedparcelable' survives intact and keeps its
    'androidx.' prefix for correct system classification."""
    from scanner.scan_modules.dependencies import _parse_version_file

    mock_apk = MagicMock()
    mock_apk.get_file.return_value = b"1.1.1"
    versions: dict = {}
    _parse_version_file(mock_apk, "META-INF/androidx.versionedparcelable_versionedparcelable.version", versions)
    assert versions == {"androidx.versionedparcelable_versionedparcelable": "1.1.1"}


def test_parse_general_properties_maps_bare_google_names_to_coordinates():
    """Google-format properties files (a 'client=' line) with bare, ambiguous artifact names
    are attributed to their verified full Maven coordinates."""
    from scanner.scan_modules.dependencies import _parse_general_properties

    contents = {
        "common.properties": b"version=18.11.0\nclient=common\n",
        "core-common.properties": b"version=2.0.4\nclient=core-common\n",
        "image.properties": b"version=1.0.0-beta1\nclient=image\n",
        # No Google fingerprint: the bare name must NOT be attributed to Google.
        "vendor/common.properties": b"version=9.9.9\n",
    }
    mock_apk = MagicMock()
    versions: dict = {}
    for filename, data in contents.items():
        mock_apk.get_file.return_value = data
        _parse_general_properties(mock_apk, filename, versions)

    assert versions["com.google.mlkit:common"] == "18.11.0"
    assert versions["com.google.android.play:core-common"] == "2.0.4"
    assert versions["com.google.android.odml:image"] == "1.0.0-beta1"
    assert versions["common"] == "9.9.9"


def test_classify_versions_buckets_mapped_google_coordinates_as_google_sdk():
    """Mapped Google coordinates land in google_sdk even when they match a system prefix,
    while unattributed bare names stay independent."""
    from scanner.scan_modules.dependencies import _classify_versions

    classified = _classify_versions(
        {
            "com.google.mlkit:common": "18.11.0",
            "com.google.android.play:core-common": "2.0.4",
            "com.google.android.odml:image": "1.0.0-beta1",
            "com.google.android.material_material": "1.12.0",
            "common": "9.9.9",
        }
    )
    google_sdk = classified["third_party"]["google_sdk"]
    assert google_sdk["com.google.mlkit:common"] == "18.11.0"
    assert google_sdk["com.google.android.play:core-common"] == "2.0.4"
    assert google_sdk["com.google.android.odml:image"] == "1.0.0-beta1"
    assert "com.google.android.material_material" in classified["system"]
    assert classified["third_party"]["independent"]["common"] == "9.9.9"


def test_classify_versions_expands_google_prefix_families_to_full_coordinates():
    """Artifacts classified as Google SDKs get their family's well-known group attached, so
    the AI report cannot resolve them against a wrong group. Unknown Google names stay as-is."""
    from scanner.scan_modules.dependencies import _classify_versions

    classified = _classify_versions(
        {
            "play-services-mlkit-barcode-scanning": "18.3.0",
            "play-services-mlkit-text-recognition": "19.0.1",
            "firebase-crashlytics": "20.0.6",
            "transport-runtime": "3.3.0",
            "review-ktx": "2.0.2",
            "crashlytics android sdk": "20.0.6",
        }
    )
    google_sdk = classified["third_party"]["google_sdk"]
    assert google_sdk["com.google.android.gms:play-services-mlkit-barcode-scanning"] == "18.3.0"
    assert google_sdk["com.google.android.gms:play-services-mlkit-text-recognition"] == "19.0.1"
    assert google_sdk["com.google.android.datatransport:transport-runtime"] == "3.3.0"
    assert google_sdk["com.google.android.play:review-ktx"] == "2.0.2"
    # Both crashlytics spellings resolve to the same canonical coordinate and merge into one
    # entry, so the report never lists the same artifact twice under two names.
    assert google_sdk["com.google.firebase:firebase-crashlytics"] == "20.0.6"
    assert "crashlytics android sdk" not in google_sdk


def test_classify_versions_deduplicates_google_coordinates_across_sources():
    """A full Google SDK coordinate (e.g. from pom.properties) is classified as google_sdk,
    never independent or system, and merges with the same artifact extracted from a Google
    .properties file, keeping the highest version. Non-SDK Google OSS stays independent."""
    from scanner.scan_modules.dependencies import _classify_versions

    classified = _classify_versions(
        {
            "com.google.firebase:firebase-iid-interop": "17.1.0",
            "firebase-iid-interop": "17.0.0",
            "com.google.android.gms:play-services-base": "18.5.0",
            "com.android.billingclient:billing": "7.1.1",
            "com.google.dagger:dagger": "2.52",
        }
    )
    google_sdk = classified["third_party"]["google_sdk"]
    assert google_sdk["com.google.firebase:firebase-iid-interop"] == "17.1.0"
    assert google_sdk["com.google.android.gms:play-services-base"] == "18.5.0"
    assert google_sdk["com.android.billingclient:billing"] == "7.1.1"
    assert "firebase-iid-interop" not in google_sdk
    assert classified["system"] == {}
    # Dagger is Google OSS but an independent developer choice, not a Play/Firebase SDK.
    assert classified["third_party"]["independent"] == {"com.google.dagger:dagger": "2.52"}


def test_assemble_dependencies():
    """Verifies assembling unified third_party and android_default dictionaries with attached facts."""
    from scanner.scan_modules.dependencies import assemble_dependencies

    raw_deps = {
        "system": {"androidx.appcompat:appcompat": "1.6.1"},
        "third_party": {
            "com.android.billingclient:billing": "7.1.1",
            "okhttp": "4.9.0",
        },
        "unversioned": {"io.branch": ["referral"]},
    }
    osv_findings = [
        {
            "library": "com.android.billingclient:billing",
            "version": "7.1.1",
            "cve_id": "CVE-2024-0001",
            "summary": "Sample CVE",
            "details_url": "https://osv.dev/sample",
        }
    ]
    maven_latest = {
        "com.android.billingclient:billing": {
            "latest_version": "9.1.0",
            "source_url": "https://maven.google.com/sample",
        },
        "okhttp": {
            "latest_version": "5.0.0",
            "source_url": "https://mvnrepository.com/sample",
        },
    }

    result = assemble_dependencies(raw_deps, osv_findings, maven_latest)

    assert "third_party" in result
    assert "android_default" in result

    tp = result["third_party"]
    assert tp["com.android.billingclient:billing"]["version_used"] == "7.1.1"
    assert tp["com.android.billingclient:billing"]["latest_version"] == "9.1.0"
    assert len(tp["com.android.billingclient:billing"]["osv_findings"]) == 1
    assert tp["com.android.billingclient:billing"]["osv_findings"][0]["cve_id"] == "CVE-2024-0001"

    assert tp["okhttp"]["version_used"] == "4.9.0"
    assert tp["okhttp"]["latest_version"] == "5.0.0"
    assert tp["okhttp"]["osv_findings"] == []

    assert tp["io.branch:referral"]["version_used"] is None
    assert tp["io.branch:referral"]["latest_version"] is None
    assert tp["io.branch:referral"]["osv_findings"] == []

    ad = result["android_default"]
    assert ad["androidx.appcompat:appcompat"]["version_used"] == "1.6.1"
    assert ad["androidx.appcompat:appcompat"]["osv_findings"] == []
