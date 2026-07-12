"""Unit tests for the deobfuscator scanner module."""

from unittest.mock import MagicMock

from scanner.scan_modules.deobfuscator import Deobfuscator


def test_deobfuscator():
    """Verifies that Deobfuscator correctly resolves obfuscated classes/packages based on string heuristics."""
    # Mock Androguard's DEX Analysis and StringAnalysis
    mock_class_b8_h = MagicMock()
    mock_class_b8_h.name = "LB8/h;"

    mock_string_1 = MagicMock()
    mock_string_1.get_value.return_value = "com.pslocks.blelocks.ACTION_GATT_CONNECTED"
    mock_string_1.get_xref_from.return_value = [(mock_class_b8_h, None)]

    mock_class_v4_d = MagicMock()
    mock_class_v4_d.name = "LV4/d;"

    mock_string_2 = MagicMock()
    mock_string_2.get_value.return_value = "ActionPickUpOrdersOverviewFragmentToPickUpDetailsFragment2"
    mock_string_2.get_xref_from.return_value = [(mock_class_v4_d, None)]

    mock_class_og_o = MagicMock()
    mock_class_og_o.name = "LOg/o;"

    mock_string_3 = MagicMock()
    mock_string_3.get_value.return_value = "Can not use AES-CMAC in FIPS-mode."
    mock_string_3.get_xref_from.return_value = [(mock_class_og_o, None)]

    # Mock methods and called APIs for method call deobfuscation context
    mock_method_b = MagicMock()
    mock_method_b.name = "b"
    mock_cipher_cls = MagicMock()
    mock_cipher_cls.name = "Ljavax/crypto/Cipher;"
    mock_dofinal_method = MagicMock()
    mock_dofinal_method.name = "doFinal"
    mock_method_b.get_xref_to.return_value = [(mock_cipher_cls, mock_dofinal_method, 0)]
    mock_class_b8_h.get_methods.return_value = [mock_method_b]

    mock_method_onclick = MagicMock()
    mock_method_onclick.name = "onClick"
    mock_loc_cls = MagicMock()
    mock_loc_cls.name = "Landroid/location/LocationManager;"
    mock_isprovider_method = MagicMock()
    mock_isprovider_method.name = "isProviderEnabled"
    mock_method_onclick.get_xref_to.return_value = [(mock_loc_cls, mock_isprovider_method, 0)]
    mock_class_v4_d.get_methods.return_value = [mock_method_onclick]

    mock_dx = MagicMock()
    mock_dx.classes = {"LB8/h;": mock_class_b8_h, "LV4/d;": mock_class_v4_d, "LOg/o;": mock_class_og_o}
    mock_dx.get_strings.return_value = [mock_string_1, mock_string_2, mock_string_3]

    deobf = Deobfuscator(mock_dx, "de.muenchen.appcenter.helpme")

    # Class-level deobfuscation resolution
    assert deobf.deobfuscate_class("B8.h") == "B8.h [com.pslocks.blelocks | com.pslocks.sdk]"
    assert deobf.deobfuscate_class("V4.d") == "V4.d [PickUpDetailsFragment | PickUpOrdersOverviewFragment]"
    assert deobf.deobfuscate_class("Og.o") == "Og.o [com.google.crypto.tink]"

    # Report deobfuscation resolution
    report = {
        "permissions": {"references": {"android.permission.ACCESS_COARSE_LOCATION": ["V4.d->onClick"]}},
        "bytecode_audit": {
            "insecure_crypto_mode_evidence": [
                "Insecure crypto algorithm/mode 'AES/ECB/NoPadding' referenced in class 'B8.h' method 'b'."
            ]
        },
    }

    deobf.deobfuscate_report(report)

    assert report["permissions"]["references"]["android.permission.ACCESS_COARSE_LOCATION"] == [
        "V4.d [PickUpDetailsFragment | PickUpOrdersOverviewFragment]->onClick (calls LocationManager.isProviderEnabled)"
    ]
    assert report["bytecode_audit"]["insecure_crypto_mode_evidence"] == [
        "Insecure crypto algorithm/mode 'AES/ECB/NoPadding' referenced in class 'B8.h [com.pslocks.blelocks | com.pslocks.sdk]' method 'b (calls Cipher.doFinal)'."
    ]


def test_deobfuscator_coverage():
    """Verifies all branches and fallback paths in Deobfuscator."""
    mock_dx = MagicMock()
    mock_class_no_strings = MagicMock()
    mock_class_no_strings.get_methods.return_value = []

    mock_dx.classes = {"Lno/strings/Cls;": mock_class_no_strings}
    mock_dx.get_strings.return_value = []

    deobf = Deobfuscator(mock_dx, "com.example")

    # 1. deobfuscate_class with L prefix
    assert deobf.deobfuscate_class("Lno/strings/Cls;") == "Lno/strings/Cls;"

    # 2. deobfuscate_class for non-existent class
    assert deobf.deobfuscate_class("Lnon/existent/Cls;") == "Lnon/existent/Cls;"

    # 3. _get_method_api_calls fallback when class not found
    assert deobf._get_method_api_calls("Lnon/existent/Cls;", "method") == ""

    # 4. _get_package_strings and package-level extraction
    mock_class_pkg = MagicMock()
    mock_class_pkg.name = "Lpkg/MyClass;"

    mock_class_other = MagicMock()
    mock_class_other.name = "Lpkg/OtherClass;"

    mock_string = MagicMock()
    mock_string.get_value.return_value = "MyDataClass(title=Hello)"
    mock_string.get_xref_from.return_value = [(mock_class_other, None)]

    mock_dx.classes["Lpkg/MyClass;"] = mock_class_pkg
    mock_dx.get_strings.return_value = [mock_string]

    assert "MyDataClass" in deobf.deobfuscate_class("Lpkg/MyClass;")

    # Test last_slash <= 1 in _get_package_strings
    mock_class_root = MagicMock()
    mock_class_root.name = "LRootClass;"
    mock_dx.classes["LRootClass;"] = mock_class_root
    deobf.classifier.cache.clear()
    assert deobf.deobfuscate_class("LRootClass;") == "LRootClass;"

    # 5. Component contexts with Args/Directions suffixes
    deobf.classifier.cache.clear()
    mock_string_args = MagicMock()
    mock_string_args.get_value.return_value = "MyFragmentArgs"
    mock_string_args.get_xref_from.return_value = [(mock_class_root, None)]
    mock_dx.get_strings.return_value = [mock_string_args]
    assert "MyFragment" in deobf.deobfuscate_class("LRootClass;")

    deobf.classifier.cache.clear()
    mock_string_dirs = MagicMock()
    mock_string_dirs.get_value.return_value = "MyFeatureDirectionsArgs"
    mock_string_dirs.get_xref_from.return_value = [(mock_class_root, None)]
    mock_dx.get_strings.return_value = [mock_string_dirs]
    assert "MyFeature" in deobf.deobfuscate_class("LRootClass;")

    # 6. Java package context with short length or no ignore prefix
    deobf.classifier.cache.clear()
    mock_string_pkg = MagicMock()
    mock_string_pkg.get_value.return_value = "com.pslocks.some"
    mock_string_pkg.get_xref_from.return_value = [(mock_class_root, None)]
    mock_dx.get_strings.return_value = [mock_string_pkg]
    assert "com.pslocks.some" in deobf.deobfuscate_class("LRootClass;")

    # 7. deobfuscate_report edge cases
    report_no_perms = {}
    deobf.deobfuscate_report(report_no_perms)

    report_ref_no_arrow = {"permissions": {"references": {"android.permission.CAMERA": ["InvalidRefFormat"]}}}
    deobf.deobfuscate_report(report_ref_no_arrow)
    assert report_ref_no_arrow["permissions"]["references"]["android.permission.CAMERA"] == ["InvalidRefFormat"]
