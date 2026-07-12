"""Bytecode audit module for static APK security checking.

Performs semantic static audits on Dalvik executable bytecode (DEX) using Androguard XREFs to detect security concerns and vulnerabilities.
"""

import re

from loguru import logger

from scanner.util.rules import TRUSTED_PACKAGE_PREFIXES

# Package prefixes of trusted libraries and SDKs to ignore during auditing
IGNORE_PREFIXES = tuple(TRUSTED_PACKAGE_PREFIXES)


def _is_verify_bypass(instructions) -> tuple[bool, str]:
    """Checks if HostnameVerifier.verify returns true unconditionally.

    Args:
        instructions (list): Dalvik instructions of the method.

    Returns:
        tuple[bool, str]: A tuple of (is_bypass, reason).
    """
    has_const_one = False
    for inst in instructions:
        op = inst.get_name().lower()
        out = inst.get_output().lower()
        if "const" in op and "1" in out:
            has_const_one = True
        if "return" in op and has_const_one:
            return True, "returns true unconditionally"
    return False, ""


def _is_trust_bypass(instructions) -> tuple[bool, str]:
    """Checks if trust-manager implementation is an empty/no-op void check.

    Args:
        instructions (list): Dalvik instructions of the method.

    Returns:
        tuple[bool, str]: A tuple of (is_bypass, reason).
    """
    for inst in instructions:
        if "return-void" in inst.get_name().lower():
            return True, "contains empty/no-op implementation"
    return False, ""


def _audit_ssl_bypass(dx, report):
    """Audits bytecode for custom TrustManager or HostnameVerifier implementations that bypass SSL/TLS verification.

    Args:
        dx (androguard.core.analysis.analysis.Analysis): Multi-DEX analysis context.
        report (dict): Target bytecode report dictionary to write findings to.
    """
    ssl_interfaces = {
        "Ljavax/net/ssl/X509TrustManager;": ("checkClientTrusted", "checkServerTrusted"),
        "Ljavax/net/ssl/HostnameVerifier;": ("verify",),
    }

    try:
        for cls in dx.get_classes():
            if cls.is_external() or cls.name.startswith(IGNORE_PREFIXES):
                continue

            vm_class = cls.get_vm_class()
            if not vm_class:
                continue

            interfaces = vm_class.get_interfaces()
            matched_interface = next((interface for interface in interfaces if interface in ssl_interfaces), None)

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
                        is_bypass, reason = _is_verify_bypass(instructions)
                    elif method_name in ("checkClientTrusted", "checkServerTrusted") and inst_count <= 2:
                        is_bypass, reason = _is_trust_bypass(instructions)

                    if is_bypass:
                        class_name = cls.name.replace("/", ".").strip("L;")
                        evidence = f"Class '{class_name}' implements {matched_interface.strip('L;')} -> {method_name} ({reason})."
                        report["ssl_bypass_detected"] = True
                        report["ssl_bypass_evidence"].append(evidence)

    except Exception as e:
        logger.error(f"Error executing SSL bypass bytecode audit: {e!s}")


def _collect_js_enabled_callers(dx, webview_settings_class) -> set:
    """Collects classes that enable JavaScript on WebViews.

    Args:
        dx (androguard.core.analysis.analysis.Analysis): Multi-DEX analysis context.
        webview_settings_class (str): WebView settings class identifier.

    Returns:
        set: A set of caller class names.
    """
    js_enabled_callers = set()
    for method in dx.get_methods():
        if method.class_name == webview_settings_class and method.name == "setJavaScriptEnabled":
            xrefs = method.get_xref_from()
            for xref in xrefs:
                caller_class = xref[0].name
                if not caller_class.startswith(IGNORE_PREFIXES):
                    js_enabled_callers.add(caller_class)
    return js_enabled_callers


def _collect_file_access_callers(dx, webview_settings_class, dangerous_file_methods) -> dict:
    """Collects classes and methods that invoke dangerous WebView file access methods.

    Args:
        dx (androguard.core.analysis.analysis.Analysis): Multi-DEX analysis context.
        webview_settings_class (str): WebView settings class identifier.
        dangerous_file_methods (set): Set of dangerous method names.

    Returns:
        dict: A dictionary mapping caller class names to lists of (method_name, caller_method).
    """
    file_access_callers = {}
    for method in dx.get_methods():
        if method.class_name == webview_settings_class and method.name in dangerous_file_methods:
            method_name = method.name
            xrefs = method.get_xref_from()
            for xref in xrefs:
                caller_class = xref[0].name
                if caller_class.startswith(IGNORE_PREFIXES):
                    continue
                caller_method = xref[1].name
                if caller_class not in file_access_callers:
                    file_access_callers[caller_class] = []
                file_access_callers[caller_class].append((method_name, caller_method))
    return file_access_callers


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
        "setAllowFileAccessFromFileURLs",
    }

    try:
        # Map method name to set of classes/methods invoking it
        js_enabled_callers = _collect_js_enabled_callers(dx, webview_settings_class)
        file_access_callers = _collect_file_access_callers(dx, webview_settings_class, dangerous_file_methods)

        # Flag if a class enables JS and configures file access rules
        for class_name, methods in file_access_callers.items():
            if class_name in js_enabled_callers:
                clean_class = class_name.replace("/", ".").strip("L;")
                for method_name, caller_method in methods:
                    evidence = f"Class '{clean_class}' in method '{caller_method}' calls {method_name} while JavaScript is enabled."
                    report["unsafe_webview_settings_detected"] = True
                    report["unsafe_webview_settings_evidence"].append(evidence)

    except Exception as e:
        logger.error(f"Error executing Webview settings bytecode audit: {e!s}")


def _audit_insecure_cryptography(dx, report):
    """Audits bytecode for usage of insecure symmetric key modes (AES ECB) or weak algorithms.

    Args:
        dx (androguard.core.analysis.analysis.Analysis): Multi-DEX analysis context.
        report (dict): Target bytecode report dictionary to write findings to.
    """
    insecure_modes = {"AES/ECB/PKCS5Padding", "AES/ECB/NoPadding", "DES", "DESede"}

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
        logger.error(f"Error executing insecure cryptography bytecode audit: {e!s}")


def _find_hardcoded_key_reference(dx, class_analysis, calling_method_name) -> str | None:
    """Checks if the class analysis contains a static hardcoded key string referenced in the given calling method.

    Args:
        dx (androguard.core.analysis.analysis.Analysis): Androguard multi-DEX analysis context.
        class_analysis (androguard.core.analysis.analysis.ClassAnalysis): Androguard class analysis.
        calling_method_name (str): Name of the method referencing the SecretKeySpec constructor.

    Returns:
        str | None: The matched hardcoded string value if found, or None.
    """
    for string_ref in dx.get_strings():
        for str_xref in string_ref.get_xref_from():
            if str_xref[0] == class_analysis and str_xref[1].name == calling_method_name:
                val = string_ref.get_value().strip()
                # Key heuristic: minimum 16 characters for cryptographic keys, base64/hex characters.
                # Avoid matching URLs, package names, file paths, or common class references (no dots or slashes).
                if len(val) >= 16 and re.match(r"^[A-Za-z0-9+/=_-]+$", val):
                    if "." not in val and "/" not in val and not val.startswith("android."):
                        return val
    return None


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

                    matched_key = _find_hardcoded_key_reference(dx, class_analysis, method_analysis.name)
                    if matched_key:
                        clean_class = class_analysis.name.replace("/", ".").strip("L;")
                        evidence = f"SecretKeySpec constructor called in class '{clean_class}' method '{method_analysis.name}' alongside a hardcoded string parameter: '{matched_key}'."
                        report["hardcoded_crypto_keys_detected"] = True
                        report["hardcoded_crypto_keys_evidence"].append(evidence)

    except Exception as e:
        logger.error(f"Error executing hardcoded keys bytecode audit: {e!s}")


def _audit_dynamic_code_loading(dx, report):
    """Audits bytecode for dynamic loading of external code (DexClassLoader/PathClassLoader).

    Args:
        dx (androguard.core.analysis.analysis.Analysis): Multi-DEX analysis context.
        report (dict): Target bytecode report dictionary to write findings to.
    """
    dcl_classes = {"Ldalvik/system/DexClassLoader;", "Ldalvik/system/PathClassLoader;"}

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
        logger.error(f"Error executing dynamic code loading bytecode audit: {e!s}")


def _collect_zip_entry_readers(dx, zip_entry_class) -> set:
    """Collects class names that extract names from ZipEntry.

    Args:
        dx (androguard.core.analysis.analysis.Analysis): Multi-DEX analysis context.
        zip_entry_class (str): ZipEntry class identifier.

    Returns:
        set: A set of caller class names.
    """
    entry_name_readers = set()
    for method in dx.get_methods():
        if method.class_name == zip_entry_class and method.name == "getName":
            xrefs = method.get_xref_from()
            for xref in xrefs:
                caller_class = xref[0].name
                if not caller_class.startswith(IGNORE_PREFIXES):
                    entry_name_readers.add(caller_class)
    return entry_name_readers


def _has_path_traversal_check(dx, class_analysis) -> bool:
    """Checks if a class has strings indicating path traversal checks.

    Args:
        dx (androguard.core.analysis.analysis.Analysis): Androguard multi-DEX analysis context.
        class_analysis (androguard.core.analysis.analysis.ClassAnalysis): Androguard class analysis.

    Returns:
        bool: True if path traversal checks are detected in class strings, False otherwise.
    """
    for string_ref in dx.get_strings():
        val = string_ref.get_value()
        if ".." in val or "canonicalpath" in val.lower():
            for str_xref in string_ref.get_xref_from():
                if str_xref[0] == class_analysis:
                    return True
    return False


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
        entry_name_readers = _collect_zip_entry_readers(dx, zip_entry)

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
                        if not _has_path_traversal_check(dx, class_anal):
                            clean_class = class_anal.name.replace("/", ".").strip("L;")
                            caller_method = xref[1].name
                            evidence = f"Class '{clean_class}' method '{caller_method}' extracts ZipEntry paths and writes files without apparent traversal validations ('..')."
                            report["zip_slip_detected"] = True
                            report["zip_slip_evidence"].append(evidence)

    except Exception as e:
        logger.error(f"Error executing Zip Slip bytecode audit: {e!s}")


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
        "zip_slip_evidence": [],
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
