"""Unit tests for the permissions extraction scanner module."""

from unittest.mock import MagicMock

from scanner.scan_modules.permissions import extract_permissions


def test_extract_permissions():
    """Verifies that permissions are classified into correct categories."""
    mock_apk = MagicMock()
    mock_apk.get_permissions.return_value = [
        "android.permission.CAMERA",  # Dangerous runtime
        "android.permission.INTERNET",  # Normal install-time
        "com.google.android.c2dm.permission.RECEIVE",  # System level
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

    # Test dx bytecode references
    mock_string = MagicMock()
    mock_string.get_value.return_value = "android.permission.CAMERA"

    mock_class_ana = MagicMock()
    mock_class_ana.name = "Lcom/example/MyClass;"

    mock_method_ana = MagicMock()
    mock_method_ana.name = "myMethod"

    mock_string.get_xref_from.return_value = [(mock_class_ana, mock_method_ana)]

    mock_dx = MagicMock()
    mock_dx.get_strings.return_value = [mock_string]

    result_dx = extract_permissions(mock_apk, mock_dx)
    assert "com.example.MyClass->myMethod" in result_dx["references"]["android.permission.CAMERA"]
