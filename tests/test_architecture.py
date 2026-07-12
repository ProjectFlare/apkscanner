"""Unit tests for the CPU architecture and UI framework scanner module."""

from unittest.mock import MagicMock

from scanner.scan_modules.architecture import analyze_cpu_architecture, analyze_ui_framework


def test_analyze_ui_framework():
    """Verifies identification of UI frameworks."""
    mock_apk_flutter = MagicMock()
    mock_apk_flutter.get_files.return_value = [
        "lib/arm64-v8a/libflutter.so",
        "assets/flutter_assets/AssetManifest.json",
    ]

    mock_dx = MagicMock()
    mock_dx.get_classes.return_value = []

    result = analyze_ui_framework(mock_apk_flutter, mock_dx)
    assert result == "Flutter"

    mock_apk_react = MagicMock()
    mock_apk_react.get_files.return_value = [
        "lib/arm64-v8a/libreactnativejni.so",
    ]
    result_react = analyze_ui_framework(mock_apk_react, mock_dx)
    assert result_react == "React Native"

    mock_apk_compose = MagicMock()
    mock_apk_compose.get_files.return_value = []
    mock_class = MagicMock()
    mock_class.name = "Landroidx/compose/runtime/Composer;"
    mock_dx_compose = MagicMock()
    mock_dx_compose.get_classes.return_value = [mock_class]

    result_compose = analyze_ui_framework(mock_apk_compose, mock_dx_compose)
    assert result_compose == "Native (Jetpack Compose)"

    result_standard = analyze_ui_framework(mock_apk_compose, mock_dx)
    assert result_standard == "Native (Standard Views)"


def test_analyze_cpu_architecture():
    """Verifies target hardware architecture detection."""
    mock_apk = MagicMock()
    mock_apk.get_files.return_value = [
        "lib/arm64-v8a/libnative.so",
        "lib/armeabi-v7a/libnative.so",
        "assets/images/logo.png",
    ]

    result = analyze_cpu_architecture(mock_apk)
    assert result == ["arm64-v8a", "armeabi-v7a"]
