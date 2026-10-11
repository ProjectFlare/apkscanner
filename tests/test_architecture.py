"""Unit tests for the CPU architecture and UI framework scanner module."""

from unittest.mock import MagicMock

from scanner.scan_modules.architecture import analyze_cpu_architecture, analyze_ui_framework


def test_analyze_ui_framework():
    """Verifies identification of UI frameworks."""
    # Flutter via libflutter.so
    mock_apk_flutter = MagicMock()
    mock_apk_flutter.get_files.return_value = [
        "lib/arm64-v8a/libflutter.so",
        "assets/flutter_assets/AssetManifest.json",
    ]
    mock_dx = MagicMock()
    mock_dx.get_classes.return_value = []
    assert analyze_ui_framework(mock_apk_flutter, mock_dx) == "Flutter"

    # Flutter via asset folder only
    mock_apk_flutter_asset = MagicMock()
    mock_apk_flutter_asset.get_files.return_value = ["assets/flutter_assets/kernel_blob.bin"]
    assert analyze_ui_framework(mock_apk_flutter_asset, mock_dx) == "Flutter"

    # React Native legacy via libreactnativejni.so
    mock_apk_react_legacy = MagicMock()
    mock_apk_react_legacy.get_files.return_value = ["lib/arm64-v8a/libreactnativejni.so"]
    assert analyze_ui_framework(mock_apk_react_legacy, mock_dx) == "React Native"

    # Modern React Native via libreactnative.so
    mock_apk_react_modern = MagicMock()
    mock_apk_react_modern.get_files.return_value = ["lib/arm64-v8a/libreactnative.so"]
    assert analyze_ui_framework(mock_apk_react_modern, mock_dx) == "React Native"

    # React Native via Hermes engine
    mock_apk_hermes = MagicMock()
    mock_apk_hermes.get_files.return_value = ["lib/arm64-v8a/libhermes.so"]
    assert analyze_ui_framework(mock_apk_hermes, mock_dx) == "React Native"

    # React Native / Expo via libexpo-modules-core.so
    mock_apk_expo = MagicMock()
    mock_apk_expo.get_files.return_value = ["lib/arm64-v8a/libexpo-modules-core.so"]
    assert analyze_ui_framework(mock_apk_expo, mock_dx) == "React Native"

    # React Native via index.android.bundle asset
    mock_apk_bundle = MagicMock()
    mock_apk_bundle.get_files.return_value = ["assets/index.android.bundle"]
    assert analyze_ui_framework(mock_apk_bundle, mock_dx) == "React Native"

    # React Native via DEX bytecode class taking precedence over transitive Jetpack Compose
    mock_apk_empty = MagicMock()
    mock_apk_empty.get_files.return_value = []
    mock_cls_rn = MagicMock()
    mock_cls_rn.name = "Lcom/facebook/react/ReactApplication;"
    mock_cls_compose = MagicMock()
    mock_cls_compose.name = "Landroidx/compose/runtime/Composer;"
    mock_dx_hybrid = MagicMock()
    mock_dx_hybrid.get_classes.return_value = [mock_cls_rn, mock_cls_compose]
    assert analyze_ui_framework(mock_apk_empty, mock_dx_hybrid) == "React Native"

    # Pure native Jetpack Compose
    mock_dx_compose = MagicMock()
    mock_dx_compose.get_classes.return_value = [mock_cls_compose]
    assert analyze_ui_framework(mock_apk_empty, mock_dx_compose) == "Native (Jetpack Compose)"

    # Native Standard Views fallback
    assert analyze_ui_framework(mock_apk_empty, mock_dx) == "Native (Standard Views)"

    # Broken get_files or get_classes handling
    mock_apk_broken = MagicMock()
    mock_apk_broken.get_files.side_effect = Exception("corrupt apk")
    mock_dx_broken = MagicMock()
    mock_dx_broken.get_classes.side_effect = Exception("corrupt dex")
    assert analyze_ui_framework(mock_apk_broken, mock_dx_broken) == "Native (Standard Views)"


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
