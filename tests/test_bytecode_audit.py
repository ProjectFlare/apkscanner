"""Unit tests for the bytecode security audit scanner module."""

from unittest.mock import MagicMock

from scanner.scan_modules.bytecode_audit import (
    _find_hardcoded_key_reference,
    _has_path_traversal_check,
    _is_trust_bypass,
    _is_verify_bypass,
    analyze_bytecode,
)


def test_analyze_bytecode_semantic_checks():
    """Verifies that analyze_bytecode correctly identifies security vulnerabilities in Dalvik bytecode."""
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


def test_bytecode_audit_helpers():
    """Verifies the behavior of the helper functions extracted during bytecode audit refactoring."""
    # Test _is_verify_bypass
    mock_inst_const = MagicMock()
    mock_inst_const.get_name.return_value = "const/4"
    mock_inst_const.get_output.return_value = "v0, 1"

    mock_inst_return = MagicMock()
    mock_inst_return.get_name.return_value = "return"
    mock_inst_return.get_output.return_value = "v0"

    assert _is_verify_bypass([mock_inst_const, mock_inst_return]) == (True, "returns true unconditionally")
    assert _is_verify_bypass([mock_inst_return]) == (False, "")

    # Test _is_trust_bypass
    mock_inst_void = MagicMock()
    mock_inst_void.get_name.return_value = "return-void"
    assert _is_trust_bypass([mock_inst_void]) == (True, "contains empty/no-op implementation")
    assert _is_trust_bypass([mock_inst_return]) == (False, "")

    # Test _find_hardcoded_key_reference
    mock_class_analysis = MagicMock()
    mock_method_analysis = MagicMock()
    mock_method_analysis.name = "someMethod"

    mock_string_ref = MagicMock()
    mock_string_ref.get_value.return_value = "secretkey12345678"
    mock_string_ref.get_xref_from.return_value = [(mock_class_analysis, mock_method_analysis)]

    mock_dx_internal = MagicMock()
    mock_dx_internal.get_strings.return_value = [mock_string_ref]

    assert _find_hardcoded_key_reference(mock_dx_internal, mock_class_analysis, "someMethod") == "secretkey12345678"
    assert _find_hardcoded_key_reference(mock_dx_internal, mock_class_analysis, "otherMethod") is None

    # Test _has_path_traversal_check
    mock_string_traversal = MagicMock()
    mock_string_traversal.get_value.return_value = "../escaped"
    mock_string_traversal.get_xref_from.return_value = [(mock_class_analysis,)]

    mock_dx_internal.get_strings.return_value = [mock_string_traversal]
    assert _has_path_traversal_check(mock_dx_internal, mock_class_analysis) is True

    mock_string_safe = MagicMock()
    mock_string_safe.get_value.return_value = "safe_path"
    mock_string_safe.get_xref_from.return_value = [(mock_class_analysis,)]

    mock_dx_internal.get_strings.return_value = [mock_string_safe]
    assert _has_path_traversal_check(mock_dx_internal, mock_class_analysis) is False


def test_bytecode_audit_coverage():
    """Verifies all security checks, fallback cases, and exceptions in bytecode_audit module."""
    from scanner.scan_modules.bytecode_audit import (
        _audit_dynamic_code_loading,
        _audit_hardcoded_keys,
        _audit_insecure_cryptography,
        _audit_ssl_bypass,
        _audit_unsafe_webviews,
        _audit_zip_slip,
    )

    # 1. Test verify/trust bypass helpers
    inst_const_true = MagicMock()
    inst_const_true.get_name.return_value = "const/4"
    inst_const_true.get_output.return_value = "v0, 1"
    inst_return_v0 = MagicMock()
    inst_return_v0.get_name.return_value = "return"
    inst_return_v0.get_output.return_value = "v0"

    assert _is_verify_bypass([inst_const_true, inst_return_v0])[0] is True

    # 2. Test SSL bypass exception path
    mock_dx_err = MagicMock()
    mock_dx_err.get_classes.side_effect = Exception("classes error")
    report = {"ssl_bypass_detected": False, "ssl_bypass_evidence": []}
    _audit_ssl_bypass(mock_dx_err, report)

    mock_cls_ext = MagicMock()
    mock_cls_ext.is_external.return_value = True
    mock_cls_ext.name = "Lcom/example/ExternalClass;"

    mock_cls_no_vm = MagicMock()
    mock_cls_no_vm.is_external.return_value = False
    mock_cls_no_vm.name = "Lcom/example/NoVMClass;"
    mock_cls_no_vm.get_vm_class.return_value = None

    mock_dx_vm = MagicMock()
    mock_dx_vm.get_classes.return_value = [mock_cls_ext, mock_cls_no_vm]
    _audit_ssl_bypass(mock_dx_vm, report)

    # 3. WebView setting audit with dangerous configurations
    mock_method_js = MagicMock()
    mock_method_js.class_name = "Landroid/webkit/WebSettings;"
    mock_method_js.name = "setJavaScriptEnabled"
    mock_caller_class = MagicMock()
    mock_caller_class.name = "Lcom/example/MyWebViewActivity;"
    mock_method_js.get_xref_from.return_value = [(mock_caller_class,)]

    mock_method_file = MagicMock()
    mock_method_file.class_name = "Landroid/webkit/WebSettings;"
    mock_method_file.name = "setAllowFileAccess"
    mock_caller_method = MagicMock()
    mock_caller_method.name = "initWebView"
    mock_method_file.get_xref_from.return_value = [(mock_caller_class, mock_caller_method)]

    mock_dx_web = MagicMock()
    mock_dx_web.get_methods.return_value = [mock_method_js, mock_method_file]

    report_web = {"unsafe_webview_settings_detected": False, "unsafe_webview_settings_evidence": []}
    _audit_unsafe_webviews(mock_dx_web, report_web)
    assert report_web["unsafe_webview_settings_detected"] is True

    # 4. Insecure cryptography exception path
    mock_dx_crypto_err = MagicMock()
    mock_dx_crypto_err.get_strings.side_effect = Exception("strings error")
    report_crypto = {"insecure_crypto_mode_detected": False, "insecure_crypto_mode_evidence": []}
    _audit_insecure_cryptography(mock_dx_crypto_err, report_crypto)

    # 5. Hardcoded keys audit
    mock_method_spec = MagicMock()
    mock_method_spec.class_name = "Ljavax/crypto/spec/SecretKeySpec;"
    mock_method_spec.name = "<init>"

    mock_class_anal = MagicMock()
    mock_class_anal.name = "Lcom/example/KeyActivity;"

    mock_method_anal = MagicMock()
    mock_method_anal.name = "generate"

    mock_method_spec.get_xref_from.return_value = [(mock_class_anal, mock_method_anal)]

    mock_string_ref = MagicMock()
    mock_string_ref.get_value.return_value = "c3VwZXJzZWNyZXRrZXk="
    mock_string_ref.get_xref_from.return_value = [(mock_class_anal, mock_method_anal)]

    mock_dx_keys = MagicMock()
    mock_dx_keys.get_methods.return_value = [mock_method_spec]
    mock_dx_keys.get_strings.return_value = [mock_string_ref]

    report_keys = {"hardcoded_crypto_keys_detected": False, "hardcoded_crypto_keys_evidence": []}
    _audit_hardcoded_keys(mock_dx_keys, report_keys)
    assert report_keys["hardcoded_crypto_keys_detected"] is True

    # 6. Dynamic Code Loading audit
    mock_method_dcl = MagicMock()
    mock_method_dcl.class_name = "Ldalvik/system/DexClassLoader;"
    mock_method_dcl.name = "<init>"
    mock_method_dcl.get_xref_from.return_value = [(mock_caller_class, mock_caller_method)]

    mock_dx_dcl = MagicMock()
    mock_dx_dcl.get_methods.return_value = [mock_method_dcl]

    report_dcl = {"dynamic_code_loading_detected": False, "dynamic_code_loading_evidence": []}
    _audit_dynamic_code_loading(mock_dx_dcl, report_dcl)
    assert report_dcl["dynamic_code_loading_detected"] is True

    # 7. Zip Slip audit
    mock_method_zip = MagicMock()
    mock_method_zip.class_name = "Ljava/util/zip/ZipEntry;"
    mock_method_zip.name = "getName"
    mock_method_zip.get_xref_from.return_value = [(mock_caller_class,)]

    mock_method_fos = MagicMock()
    mock_method_fos.class_name = "Ljava/io/FileOutputStream;"
    mock_method_fos.name = "<init>"
    mock_method_fos.get_xref_from.return_value = [(mock_caller_class, mock_caller_method)]

    mock_dx_zip = MagicMock()
    mock_dx_zip.get_methods.return_value = [mock_method_zip, mock_method_fos]
    mock_dx_zip.get_strings.return_value = []

    report_zip = {"zip_slip_detected": False, "zip_slip_evidence": []}
    _audit_zip_slip(mock_dx_zip, report_zip)
    assert report_zip["zip_slip_detected"] is True

    assert analyze_bytecode(None) == {
        "ssl_bypass_detected": False,
        "ssl_bypass_evidence": [],
        "unsafe_webview_settings_detected": False,
        "unsafe_webview_settings_evidence": [],
        "insecure_crypto_mode_detected": False,
        "insecure_crypto_mode_evidence": [],
        "hardcoded_crypto_keys_detected": False,
        "hardcoded_crypto_keys_evidence": [],
        "dynamic_code_loading_detected": False,
        "dynamic_code_loading_evidence": [],
        "zip_slip_detected": False,
        "zip_slip_evidence": [],
    }
