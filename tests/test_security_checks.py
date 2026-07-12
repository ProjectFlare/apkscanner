"""Unit tests for the security checks scanner module (packer and root detection)."""

from unittest.mock import MagicMock

from scanner.scan_modules.security_checks import analyze_security_checks


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


def test_analyze_security_checks_helpers():
    """Verifies internal helper functions of the security checks module.

    Tests error handling, edge cases, and distinct detection methods in the security
    checks helper functions to ensure complete code coverage.
    """
    from scanner.scan_modules.security_checks import (
        _check_rootbeer_classes,
        _detect_packer_via_classes,
        _detect_packer_via_libs,
        _scan_string_pool_for_root,
        analyze_security_checks,
    )

    # 1. Test when dx is None
    assert _check_rootbeer_classes(None) is False
    assert _scan_string_pool_for_root(None) == set()
    assert _detect_packer_via_classes(None) is None

    # 2. Test analyze_security_checks when dx is None
    mock_apk = MagicMock()
    result_none = analyze_security_checks(mock_apk, None)
    assert result_none["static_analysis"]["analysis_blocked"] is True
    assert "No DEX files or classes could be parsed" in result_none["static_analysis"]["packer_detected"]

    # 3. Test exceptions handling in helpers
    mock_dx_error = MagicMock()
    mock_dx_error.get_classes.side_effect = Exception("DEX class error")
    mock_dx_error.get_strings.side_effect = Exception("DEX string error")

    assert _check_rootbeer_classes(mock_dx_error) is False
    assert _scan_string_pool_for_root(mock_dx_error) == set()
    assert _detect_packer_via_classes(mock_dx_error) is None

    mock_apk_error = MagicMock()
    mock_apk_error.get_files.side_effect = Exception("APK files error")
    assert _detect_packer_via_libs([mock_apk_error]) is None

    # 4. Test string pool root detection
    mock_string_val = MagicMock()
    mock_string_val.get_value.return_value = "Checking for /system/xbin/su binary"
    mock_dx_strings = MagicMock()
    mock_dx_strings.get_strings.return_value = [mock_string_val]

    root_sigs = _scan_string_pool_for_root(mock_dx_strings)
    assert len(root_sigs) == 1
    assert "Root-related string signature found: '/system/xbin/su'" in root_sigs

    # 5. Test packer detection via class
    mock_class_other = MagicMock()
    mock_class_other.name = "Lcom/example/MyClass;"
    mock_class_bangcle = MagicMock()
    mock_class_bangcle.name = "Lcom/bangcle/MainActivity;"
    mock_dx_packer = MagicMock()
    mock_dx_packer.get_classes.return_value = [mock_class_other, mock_class_bangcle]

    packer_cls = _detect_packer_via_classes(mock_dx_packer)
    assert packer_cls is not None
    assert "Bangcle" in packer_cls

    # 6. Test _detect_packer fallback via classes
    from scanner.scan_modules.security_checks import _detect_packer

    mock_apk_no_lib = MagicMock()
    mock_apk_no_lib.get_files.return_value = []
    packer_fallback = _detect_packer([mock_apk_no_lib], mock_dx_packer)
    assert packer_fallback is not None
    assert "Bangcle" in packer_fallback
