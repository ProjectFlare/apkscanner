"""Unit tests for the permissions extraction scanner module."""

from unittest.mock import MagicMock

from scanner.scan_modules.permissions import (
    _attribute_call_sites,
    _find_declared_but_unused,
    _get_package_name,
    extract_permissions,
)


def test_extract_permissions():
    """Verifies that permissions are classified into correct categories."""
    mock_apk = MagicMock()
    mock_apk.get_package.return_value = "com.example"
    mock_apk.get_permissions.return_value = [
        "android.permission.CAMERA",  # Dangerous runtime
        "android.permission.INTERNET",  # Normal install-time (OS-level)
        "android.permission.GET_ACCOUNTS",  # Dangerous runtime (unused)
        "android.permission.BLUETOOTH",  # Install-time (unused)
        "com.google.android.c2dm.permission.RECEIVE",  # System level (OS-level)
        "com.custom.app.MY_PERMISSION",  # Custom/Third-party
    ]

    result = extract_permissions(mock_apk)

    assert "android.permission.CAMERA" in result["runtime_requested"]
    assert "android.permission.INTERNET" in result["install_time_or_system"]
    assert "com.google.android.c2dm.permission.RECEIVE" in result["custom_or_third_party"]
    assert "com.custom.app.MY_PERMISSION" in result["custom_or_third_party"]

    # Test exception fallback inside loop
    mock_apk_err = MagicMock()
    mock_apk_err.get_permissions.side_effect = Exception("failed to get permissions")
    result_err = extract_permissions([mock_apk, mock_apk_err])
    assert "android.permission.CAMERA" in result_err["runtime_requested"]

    # Test dx bytecode references and SDK attribution
    mock_string_camera = MagicMock()
    mock_string_camera.get_value.return_value = "android.permission.CAMERA"

    mock_class_internal = MagicMock()
    mock_class_internal.name = "Lcom/example/ui/CameraActivity;"
    mock_method_internal = MagicMock()
    mock_method_internal.name = "openCamera"

    mock_class_sdk = MagicMock()
    mock_class_sdk.name = "Lcom/google/android/gms/ads/AdView;"
    mock_method_sdk = MagicMock()
    mock_method_sdk.name = "init"

    mock_string_camera.get_xref_from.return_value = [
        (mock_class_internal, mock_method_internal),
        (mock_class_sdk, mock_method_sdk),
    ]

    mock_dx = MagicMock()
    mock_dx.get_strings.return_value = [mock_string_camera]

    result_dx = extract_permissions(mock_apk, mock_dx)
    refs_camera = result_dx["references"]["android.permission.CAMERA"]
    assert "com.example.ui.CameraActivity->openCamera" in refs_camera["app_internal"]
    assert "com.google.android.gms.ads.AdView->init" in refs_camera["third_party"]

    # Verify declared_but_unused
    dormant_names = result_dx["declared_but_unused"]
    assert "android.permission.GET_ACCOUNTS" in dormant_names
    assert "android.permission.BLUETOOTH" in dormant_names
    assert "android.permission.CAMERA" not in dormant_names
    assert "android.permission.INTERNET" not in dormant_names  # Excluded OS-level permission
    assert "com.google.android.c2dm.permission.RECEIVE" not in dormant_names  # Excluded OS-level permission


def test_get_package_name():
    """Verifies retrieval of package name across normal and error conditions."""
    mock_apk_good = MagicMock()
    mock_apk_good.get_package.return_value = "com.test.app"
    mock_apk_err = MagicMock()
    mock_apk_err.get_package.side_effect = Exception("failed")

    assert _get_package_name([mock_apk_err, mock_apk_good]) == "com.test.app"
    assert _get_package_name([mock_apk_err]) == ""


def test_attribute_call_sites():
    """Verifies call site segmentation into app-internal and third-party SDK prefixes."""
    call_sites = [
        "com.mycompany.app.MainActivity->onCreate",
        "com.google.android.gms.maps.MapView->load",
        "io.branch.referral.Branch->init",
        "shortpkg.Class->run",
        "SingleClass->test",
    ]
    res = _attribute_call_sites("com.mycompany.app", call_sites)
    assert res["app_internal"] == ["com.mycompany.app.MainActivity->onCreate"]
    assert "com.google.android.gms.maps.MapView->load" in res["third_party"]
    assert "io.branch.referral.Branch->init" in res["third_party"]
    assert "shortpkg.Class->run" in res["third_party"]
    assert "SingleClass->test" in res["third_party"]


def test_find_declared_but_unused():
    """Verifies that unused permissions are correctly extracted as a list of strings."""
    sorted_perms = [
        "android.permission.CAMERA",
        "android.permission.INTERNET",
        "android.permission.NFC",
        "android.permission.READ_CONTACTS",
        "com.custom.UNUSED_PERM",
    ]
    referenced = {"android.permission.CAMERA"}

    dormant = _find_declared_but_unused(sorted_perms, referenced)

    assert "android.permission.CAMERA" not in dormant
    assert "android.permission.INTERNET" not in dormant
    assert "android.permission.READ_CONTACTS" in dormant
    assert "android.permission.NFC" in dormant
    assert "com.custom.UNUSED_PERM" in dormant
