"""Unit tests for the bytecode security audit scanner module."""

from unittest.mock import MagicMock

from scanner.scan_modules.bytecode_audit import (
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
    assert len(result["ssl_bypass"]) > 0
    assert any("com.example.MyTrustManager" in evidence for evidence in result["ssl_bypass"])
    assert len(result["insecure_crypto_mode"]) > 0
    assert any("AES/ECB/PKCS5Padding" in evidence for evidence in result["insecure_crypto_mode"])


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

    # Test _has_path_traversal_check
    mock_dx_internal = MagicMock()
    mock_class_analysis = MagicMock()
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
    report = {"ssl_bypass": []}
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

    mock_method_univ = MagicMock()
    mock_method_univ.class_name = "Landroid/webkit/WebSettings;"
    mock_method_univ.name = "setAllowUniversalAccessFromFileURLs"
    mock_method_univ.get_xref_from.return_value = [(mock_caller_class, mock_caller_method)]

    mock_dx_web = MagicMock()
    mock_dx_web.get_methods.return_value = [mock_method_js, mock_method_file, mock_method_univ]

    report_web = {"unsafe_webview_settings": [], "permissive_webview_file_access": []}
    _audit_unsafe_webviews(mock_dx_web, report_web)
    assert len(report_web["unsafe_webview_settings"]) > 0

    # Test local-only file access goes to permissive_webview_file_access
    mock_dx_web_local = MagicMock()
    mock_caller_local = MagicMock()
    mock_caller_local.name = "Lcom/example/LocalOnlyActivity;"
    mock_method_js_local = MagicMock()
    mock_method_js_local.class_name = "Landroid/webkit/WebSettings;"
    mock_method_js_local.name = "setJavaScriptEnabled"
    mock_method_js_local.get_xref_from.return_value = [(mock_caller_local,)]
    mock_method_file_local = MagicMock()
    mock_method_file_local.class_name = "Landroid/webkit/WebSettings;"
    mock_method_file_local.name = "setAllowFileAccess"
    mock_method_file_local.get_xref_from.return_value = [(mock_caller_local, mock_caller_method)]
    mock_dx_web_local.get_methods.return_value = [mock_method_js_local, mock_method_file_local]
    report_local = {"unsafe_webview_settings": [], "permissive_webview_file_access": []}
    _audit_unsafe_webviews(mock_dx_web_local, report_local)
    assert len(report_local["permissive_webview_file_access"]) > 0
    assert len(report_local["unsafe_webview_settings"]) == 0

    # 4. Insecure cryptography exception path
    mock_dx_crypto_err = MagicMock()
    mock_dx_crypto_err.get_strings.side_effect = Exception("strings error")
    report_crypto = {"insecure_crypto_mode": []}
    _audit_insecure_cryptography(mock_dx_crypto_err, report_crypto)

    # 5. Dynamic Code Loading audit
    mock_method_dcl = MagicMock()
    mock_method_dcl.class_name = "Ldalvik/system/DexClassLoader;"
    mock_method_dcl.name = "<init>"
    mock_method_dcl.get_xref_from.return_value = [(mock_caller_class, mock_caller_method)]

    mock_dx_dcl = MagicMock()
    mock_dx_dcl.get_methods.return_value = [mock_method_dcl]

    report_dcl = {"dynamic_code_loading": []}
    _audit_dynamic_code_loading(mock_dx_dcl, report_dcl)
    assert len(report_dcl["dynamic_code_loading"]) > 0

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

    report_zip = {"zip_slip": []}
    _audit_zip_slip(mock_dx_zip, report_zip)
    assert len(report_zip["zip_slip"]) > 0

    assert analyze_bytecode(None) == {
        "ssl_bypass": [],
        "unsafe_webview_settings": [],
        "permissive_webview_file_access": [],
        "insecure_crypto_mode": [],
        "unpadded_ecb_primitive": [],
        "deprecated_cipher_algorithm": [],
        "hardcoded_crypto_keys": [],
        "dynamic_code_loading": [],
        "zip_slip": [],
    }


def test_audit_insecure_cryptography_des_and_unpadded_ecb():
    """Verifies that DES is placed in deprecated_cipher_algorithm, NoPadding in unpadded_ecb_primitive, and PKCS5Padding in insecure_crypto_mode."""
    from scanner.scan_modules.bytecode_audit import _audit_insecure_cryptography

    mock_dx = MagicMock()

    # DES string reference in NTLMEngine
    mock_str_des = MagicMock()
    mock_str_des.get_value.return_value = "DES"
    mock_class_ntlm = MagicMock()
    mock_class_ntlm.name = "Lcom/example/http/NTLMEngineImpl;"
    mock_method_des = MagicMock()
    mock_method_des.name = "createDESKey"
    mock_str_des.get_xref_from.return_value = [(mock_class_ntlm, mock_method_des)]

    # AES/ECB/NoPadding (single-block primitive)
    mock_str_ecb_nopad = MagicMock()
    mock_str_ecb_nopad.get_value.return_value = "AES/ECB/NoPadding"
    mock_class_tink = MagicMock()
    mock_class_tink.name = "Lcom/example/ObfuscatedClass;"
    mock_method_ecb = MagicMock()
    mock_method_ecb.name = "<init>"
    mock_str_ecb_nopad.get_xref_from.return_value = [(mock_class_tink, mock_method_ecb)]

    # AES/ECB/PKCS5Padding (insecure multi-block mode)
    mock_str_pkcs5 = MagicMock()
    mock_str_pkcs5.get_value.return_value = "AES/ECB/PKCS5Padding"
    mock_class_app = MagicMock()
    mock_class_app.name = "Lcom/example/app/SecretManager;"
    mock_method_pkcs5 = MagicMock()
    mock_method_pkcs5.name = "encrypt"
    mock_str_pkcs5.get_xref_from.return_value = [(mock_class_app, mock_method_pkcs5)]

    mock_dx.get_strings.return_value = [mock_str_des, mock_str_ecb_nopad, mock_str_pkcs5]

    report = {"insecure_crypto_mode": [], "unpadded_ecb_primitive": [], "deprecated_cipher_algorithm": []}
    _audit_insecure_cryptography(mock_dx, report)

    # DES should be in deprecated_cipher_algorithm
    assert len(report["deprecated_cipher_algorithm"]) == 1
    assert "DES" in report["deprecated_cipher_algorithm"][0]

    # AES/ECB/NoPadding should be in unpadded_ecb_primitive
    assert len(report["unpadded_ecb_primitive"]) == 1
    assert "AES/ECB/NoPadding" in report["unpadded_ecb_primitive"][0]

    # AES/ECB/PKCS5Padding must be in insecure_crypto_mode
    assert len(report["insecure_crypto_mode"]) == 1
    assert "AES/ECB/PKCS5Padding" in report["insecure_crypto_mode"][0]
