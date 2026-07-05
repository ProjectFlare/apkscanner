# Bytecode audit module for static APK security checking.
# Performs semantic static audits on Dalvik executable bytecode (DEX) using Androguard XREFs.

import re
from loguru import logger

from scanner.rules import TRUSTED_PACKAGE_PREFIXES

# Package prefixes of trusted libraries and SDKs to ignore during auditing
IGNORE_PREFIXES = tuple(TRUSTED_PACKAGE_PREFIXES)

def _audit_ssl_bypass(dx, report):
    """Audits bytecode for custom TrustManager or HostnameVerifier implementations that bypass SSL/TLS verification.

    Args:
        dx (androguard.core.analysis.analysis.Analysis): Multi-DEX analysis context.
        report (dict): Target bytecode report dictionary to write findings to.
    """
    ssl_interfaces = {
        "Ljavax/net/ssl/X509TrustManager;": ("checkClientTrusted", "checkServerTrusted"),
        "Ljavax/net/ssl/HostnameVerifier;": ("verify",)
    }

    try:
        for cls in dx.get_classes():
            if cls.is_external() or cls.name.startswith(IGNORE_PREFIXES):
                continue
            
            vm_class = cls.get_vm_class()
            if not vm_class:
                continue

            interfaces = vm_class.get_interfaces()
            matched_interface = None
            for interface in interfaces:
                if interface in ssl_interfaces:
                    matched_interface = interface
                    break

            if not matched_interface:
                continue

            methods_to_check = ssl_interfaces[matched_interface]
            for method in cls.get_methods():
                method_name = method.name
                if method_name in methods_to_check:
                    enc_method = method.get_method()
                    if not enc_method:
                        continue

                    # Count Dalvik instructions to evaluate if implementation is trivial
                    instructions = list(enc_method.get_instructions())
                    inst_count = len(instructions)

                    is_bypass = False
                    reason = ""
                    
                    if method_name == "verify" and inst_count <= 4:
                        # Check if it returns true unconditionally (const/4 vx, 1 followed by return)
                        has_const_one = False
                        for inst in instructions:
                            op = inst.get_name().lower()
                            out = inst.get_output().lower()
                            if "const" in op and "1" in out:
                                has_const_one = True
                            if "return" in op and has_const_one:
                                is_bypass = True
                                reason = "returns true unconditionally"
                                break
                    elif method_name in ("checkClientTrusted", "checkServerTrusted") and inst_count <= 2:
                        # Empty implementation of void-returning checks (often just a return-void instruction)
                        for inst in instructions:
                            if "return-void" in inst.get_name().lower():
                                is_bypass = True
                                reason = "contains empty/no-op implementation"
                                break

                    if is_bypass:
                        class_name = cls.name.replace("/", ".").strip("L;")
                        evidence = f"Class '{class_name}' implements {matched_interface.strip('L;')} -> {method_name} ({reason})."
                        report["ssl_bypass_detected"] = True
                        report["ssl_bypass_evidence"].append(evidence)

    except Exception as e:
        logger.error(f"Error executing SSL bypass bytecode audit: {str(e)}")


def _audit_unsafe_webviews(dx, report):
    """Audits bytecode for WebViews enabling JavaScript alongside file access APIs.

    Args:
        dx (androguard.core.analysis.analysis.Analysis): Multi-DEX analysis context.
        report (dict): Target bytecode report dictionary to write findings to.
    """
    webview_settings_class = "Landroid/webkit/WebSettings;"
    dangerous_file_methods = {
        "setAllowFileAccess",
        "setAllowUniversalAccessFromFileURLs",
        "setAllowFileAccessFromFileURLs"
    }

    try:
        # Map method name to set of classes/methods invoking it
        js_enabled_callers = set()
        file_access_callers = {}

        for method in dx.get_methods():
            if method.class_name == webview_settings_class:
                method_name = method.name
                
                if method_name == "setJavaScriptEnabled":
                    xrefs = method.get_xref_from()
                    for xref in xrefs:
                        caller_class = xref[0].name
                        if not caller_class.startswith(IGNORE_PREFIXES):
                            js_enabled_callers.add(caller_class)
                
                elif method_name in dangerous_file_methods:
                    xrefs = method.get_xref_from()
                    for xref in xrefs:
                        caller_class = xref[0].name
                        if caller_class.startswith(IGNORE_PREFIXES):
                            continue
                        caller_method = xref[1].name
                        if caller_class not in file_access_callers:
                            file_access_callers[caller_class] = []
                        file_access_callers[caller_class].append((method_name, caller_method))

        # Flag if a class enables JS and configures file access rules
        for class_name, methods in file_access_callers.items():
            if class_name in js_enabled_callers:
                clean_class = class_name.replace("/", ".").strip("L;")
                for method_name, caller_method in methods:
                    evidence = f"Class '{clean_class}' in method '{caller_method}' calls {method_name} while JavaScript is enabled."
                    report["unsafe_webview_settings_detected"] = True
                    report["unsafe_webview_settings_evidence"].append(evidence)

    except Exception as e:
        logger.error(f"Error executing Webview settings bytecode audit: {str(e)}")


def _audit_insecure_cryptography(dx, report):
    """Audits bytecode for usage of insecure symmetric key modes (AES ECB) or weak algorithms.

    Args:
        dx (androguard.core.analysis.analysis.Analysis): Multi-DEX analysis context.
        report (dict): Target bytecode report dictionary to write findings to.
    """
    insecure_modes = {
        "AES/ECB/PKCS5Padding", "AES/ECB/NoPadding", "DES", "DESede"
    }

    try:
        for string_val in dx.get_strings():
            val = string_val.get_value().strip()
            if val in insecure_modes:
                xrefs = string_val.get_xref_from()
                for xref in xrefs:
                    caller_class_name = xref[0].name
                    if caller_class_name.startswith(IGNORE_PREFIXES):
                        continue
                    caller_class = caller_class_name.replace("/", ".").strip("L;")
                    caller_method = xref[1].name
                    evidence = f"Insecure crypto algorithm/mode '{val}' referenced in class '{caller_class}' method '{caller_method}'."
                    report["insecure_crypto_mode_detected"] = True
                    report["insecure_crypto_mode_evidence"].append(evidence)

    except Exception as e:
        logger.error(f"Error executing insecure cryptography bytecode audit: {str(e)}")


def _audit_hardcoded_keys(dx, report):
    """Audits bytecode for potential hardcoded cryptographic keys passed directly to SecretKeySpec.

    Args:
        dx (androguard.core.analysis.analysis.Analysis): Multi-DEX analysis context.
        report (dict): Target bytecode report dictionary to write findings to.
    """
    secret_key_spec = "Ljavax/crypto/spec/SecretKeySpec;"

    try:
        for method in dx.get_methods():
            if method.class_name == secret_key_spec and method.name == "<init>":
                xrefs = method.get_xref_from()
                for xref in xrefs:
                    class_analysis = xref[0]
                    if class_analysis.name.startswith(IGNORE_PREFIXES):
                        continue
                    method_analysis = xref[1]
                    
                    # Inspect string pool dependencies referenced in the same method
                    has_static_string = False
                    for string_ref in class_analysis.get_strings():
                        # Verify if the string is referenced in the specific calling method
                        for str_xref in string_ref.get_xref_from():
                            if str_xref[1].name == method_analysis.name:
                                val = string_ref.get_value().strip()
                                # Common heuristic for hardcoded key entropy and format
                                if len(val) >= 8 and re.match(r"^[A-Za-z0-9+/=_-]+$", val):
                                    has_static_string = True
                                    break
                        if has_static_string:
                            break

                    if has_static_string:
                        clean_class = class_analysis.name.replace("/", ".").strip("L;")
                        evidence = f"SecretKeySpec constructor called in class '{clean_class}' method '{method_analysis.name}' alongside a hardcoded string parameter."
                        report["hardcoded_crypto_keys_detected"] = True
                        report["hardcoded_crypto_keys_evidence"].append(evidence)

    except Exception as e:
        logger.error(f"Error executing hardcoded keys bytecode audit: {str(e)}")


def _audit_dynamic_code_loading(dx, report):
    """Audits bytecode for dynamic loading of external code (DexClassLoader/PathClassLoader).

    Args:
        dx (androguard.core.analysis.analysis.Analysis): Multi-DEX analysis context.
        report (dict): Target bytecode report dictionary to write findings to.
    """
    dcl_classes = {
        "Ldalvik/system/DexClassLoader;",
        "Ldalvik/system/PathClassLoader;"
    }

    try:
        for method in dx.get_methods():
            if method.class_name in dcl_classes and method.name == "<init>":
                xrefs = method.get_xref_from()
                for xref in xrefs:
                    caller_class_name = xref[0].name
                    if caller_class_name.startswith(IGNORE_PREFIXES):
                        continue
                    caller_class = caller_class_name.replace("/", ".").strip("L;")
                    caller_method = xref[1].name
                    clean_dcl = method.class_name.strip("L;")
                    evidence = f"Dynamic code loading instantiated ({clean_dcl}) in class '{caller_class}' method '{caller_method}'."
                    report["dynamic_code_loading_detected"] = True
                    report["dynamic_code_loading_evidence"].append(evidence)

    except Exception as e:
        logger.error(f"Error executing dynamic code loading bytecode audit: {str(e)}")


def _audit_zip_slip(dx, report):
    """Audits bytecode for Zip Slip directory traversal vulnerabilities in custom extraction code.

    Args:
        dx (androguard.core.analysis.analysis.Analysis): Multi-DEX analysis context.
        report (dict): Target bytecode report dictionary to write findings to.
    """
    zip_entry = "Ljava/util/zip/ZipEntry;"
    file_output_stream = "Ljava/io/FileOutputStream;"

    try:
        # Classes that extract names from zip entries
        entry_name_readers = set()
        for method in dx.get_methods():
            if method.class_name == zip_entry and method.name == "getName":
                xrefs = method.get_xref_from()
                for xref in xrefs:
                    caller_class = xref[0].name
                    if not caller_class.startswith(IGNORE_PREFIXES):
                        entry_name_readers.add(caller_class)

        # Check if the same classes instantiate output file streams without path sanitization checks
        for method in dx.get_methods():
            if method.class_name == file_output_stream and method.name == "<init>":
                xrefs = method.get_xref_from()
                for xref in xrefs:
                    caller_class = xref[0].name
                    if caller_class.startswith(IGNORE_PREFIXES):
                        continue
                    if caller_class in entry_name_readers:
                        class_anal = xref[0]
                        # Look for strings associated with path traversal checks (like "..")
                        has_traversal_check = False
                        for string_ref in class_anal.get_strings():
                            val = string_ref.get_value()
                            if ".." in val or "canonicalpath" in val.lower():
                                has_traversal_check = True
                                break

                        if not has_traversal_check:
                            clean_class = class_anal.name.replace("/", ".").strip("L;")
                            caller_method = xref[1].name
                            evidence = f"Class '{clean_class}' method '{caller_method}' extracts ZipEntry paths and writes files without apparent traversal validations ('..')."
                            report["zip_slip_detected"] = True
                            report["zip_slip_evidence"].append(evidence)

    except Exception as e:
        logger.error(f"Error executing Zip Slip bytecode audit: {str(e)}")


def analyze_bytecode(dx):
    """Performs semantic Dalvik bytecode audits mapping key indicators to LLM-friendly schemas.

    Args:
        dx (androguard.core.analysis.analysis.Analysis): Multi-DEX analysis context.

    Returns:
        dict: A structured report containing:
            - ssl_bypass_detected (bool)
            - ssl_bypass_evidence (list[str])
            - unsafe_webview_settings_detected (bool)
            - unsafe_webview_settings_evidence (list[str])
            - insecure_crypto_mode_detected (bool)
            - insecure_crypto_mode_evidence (list[str])
            - hardcoded_crypto_keys_detected (bool)
            - hardcoded_crypto_keys_evidence (list[str])
            - dynamic_code_loading_detected (bool)
            - dynamic_code_loading_evidence (list[str])
            - zip_slip_detected (bool)
            - zip_slip_evidence (list[str])
    """
    report = {
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
        "zip_slip_evidence": []
    }

    if not dx or not dx.get_classes():
        return report

    _audit_ssl_bypass(dx, report)
    _audit_unsafe_webviews(dx, report)
    _audit_insecure_cryptography(dx, report)
    _audit_hardcoded_keys(dx, report)
    _audit_dynamic_code_loading(dx, report)
    _audit_zip_slip(dx, report)

    # Deduplicate evidences
    for key in report:
        if isinstance(report[key], list):
            report[key] = sorted(set(report[key]))

    return report
