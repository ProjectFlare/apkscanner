"""Module for parsing AndroidManifest.xml and evaluating security-critical configuration flags.

Includes resolving and parsing Network Security Configuration XML policies.
"""

import xml.etree.ElementTree as ET
from collections.abc import Sequence
from typing import Any

from androguard.core.axml import AXMLPrinter


def resolve_ref_value(apk: Any, value: Any) -> Any:
    """Resolves a resource reference (e.g. @7F110516) to its actual string/bool value.

    Args:
        apk (androguard.core.apk.APK): The parsed APK object to resolve from.
        value (str): The resource reference string.

    Returns:
        any: The resolved resource value, or the original value if resolution fails.
    """
    if not value or not isinstance(value, str) or not value.startswith("@"):
        return value
    try:
        resolved = apk.get_res_value(value)
        if resolved is not None:
            return resolved
    except Exception:
        pass
    return value


def _is_true(val: Any, default: bool = False) -> bool:
    """Safely checks if a manifest attribute value represents a boolean True."""
    if val is None:
        return default
    if isinstance(val, bool):
        return val
    val_str = str(val).strip().lower()
    return val_str in ("true", "1")


def _find_network_security_config_path(apk: Any, net_config_res: str) -> str | None:
    """Resolves and searches for the Network Security Configuration XML file path within the APK.

    Args:
        apk (androguard.core.apk.APK): The parsed APK object.
        net_config_res (str): The network security configuration resource string or name.

    Returns:
        str or None: The path to the network security configuration file within the APK,
            or None if not found.
    """
    config_path = None
    if net_config_res.startswith("@"):
        config_path = apk.get_res_value(net_config_res)
    else:
        res_name = net_config_res.replace("@xml/", "")
        for f in apk.get_files():
            if f.endswith(f"/{res_name}.xml") and "res/xml" in f:
                config_path = f
                break

    # If it returned a list of paths, pick the first one
    if isinstance(config_path, list) and config_path:
        config_path = config_path[0]
    return config_path if isinstance(config_path, str) else None


def _load_network_security_config_xml(apk: Any, config_path: str) -> ET.Element | None:
    """Retrieves and parses the binary AXML network security config into an ElementTree.Element.

    Args:
        apk (androguard.core.apk.APK): The parsed APK object.
        config_path (str): The path to the configuration file within the APK.

    Returns:
        xml.etree.ElementTree.Element or None: The parsed root element of the XML configuration,
            or None if retrieval or parsing fails.
    """
    raw_data = apk.get_file(config_path)
    if not raw_data:
        return None

    axml = AXMLPrinter(raw_data)
    xml_buff = axml.get_buff()
    if not xml_buff:
        return None

    return ET.fromstring(xml_buff)


def _parse_base_config_element(base_config: ET.Element, findings: dict[str, Any]) -> None:
    """Parses base-config element and updates the findings dictionary.

    Args:
        base_config (xml.etree.ElementTree.Element): The base-config XML element.
        findings (dict): The findings dictionary to update in-place.
    """
    cleartext_attr = base_config.attrib.get("cleartextTrafficPermitted")
    if cleartext_attr:
        findings["global_cleartext"] = cleartext_attr.lower() == "true"

    # Check for trusted user certificates in base-config
    trust_anchors = base_config.find("trust-anchors")
    if trust_anchors is not None:
        for cert in trust_anchors.findall("certificates"):
            if cert.attrib.get("src") == "user":
                findings["trusts_user_certs"] = True


def _parse_domain_config_element(elem: ET.Element, findings: dict[str, Any]) -> None:
    """Recursively parses a domain-config element and updates the findings dictionary.

    Args:
        elem (xml.etree.ElementTree.Element): The domain-config XML element.
        findings (dict): The findings dictionary to update in-place.
    """
    cleartext_attr = elem.attrib.get("cleartextTrafficPermitted")
    is_cleartext_permitted = cleartext_attr.lower() == "true" if cleartext_attr else False

    if is_cleartext_permitted:
        for domain in elem.findall("domain"):
            domain_text = domain.text
            if domain_text:
                findings["domain_cleartext_list"].append(domain_text.strip())

    # Check for trusted user certificates in domain-config
    trust_anchors = elem.find("trust-anchors")
    if trust_anchors is not None:
        for cert in trust_anchors.findall("certificates"):
            if cert.attrib.get("src") == "user":
                findings["trusts_user_certs"] = True

    for child in elem.findall("domain-config"):
        _parse_domain_config_element(child, findings)


def parse_network_security_config(apk: Any, net_config_res: str) -> dict[str, Any]:
    """Parses binary Network Security Configuration XML file.

    Extracts rules regarding global cleartext traffic, domain-specific cleartext exceptions,
    and trusted user certificate anchors in production.

    Args:
        apk (androguard.core.apk.APK): The parsed APK object.
        net_config_res (str): The network security configuration resource string (e.g. '@7F180004').

    Returns:
        dict: A dictionary of parsed findings:
            - global_cleartext (bool or None): True if cleartext traffic is permitted globally.
            - domain_cleartext_list (list[str]): List of domains where cleartext is permitted.
            - trusts_user_certs (bool): True if user certificates are trusted in production config.
    """
    findings: dict[str, Any] = {"global_cleartext": None, "domain_cleartext_list": [], "trusts_user_certs": False}

    try:
        config_path = _find_network_security_config_path(apk, net_config_res)
        if not config_path:
            return findings

        root = _load_network_security_config_xml(apk, config_path)
        if root is None:
            return findings

        # Check base-config
        base_config = root.find("base-config")
        if base_config is not None:
            _parse_base_config_element(base_config, findings)

        # Check all domain-config elements
        for domain_config in root.findall("domain-config"):
            _parse_domain_config_element(domain_config, findings)

    except Exception:
        pass

    return findings


def _parse_single_apk_manifest_flags(apk: Any, android_ns: str) -> dict[str, Any] | None:
    """Parses application-level security attributes from a single APK's manifest.

    Args:
        apk (androguard.core.apk.APK): The parsed APK object.
        android_ns (str): The namespace prefix for Android resource attributes.

    Returns:
        dict or None: A dictionary containing:
            - allow_backup (bool): True if allowed.
            - debuggable (bool): True if debuggable.
            - uses_cleartext_traffic (bool): True if cleartext traffic is permitted.
            - network_security_config (dict or None): Parsed network security config findings if present.
            - request_legacy_external_storage (bool): True if legacy external storage is requested.
            Returns None if the manifest or application element is missing.
    """
    xml_root = apk.get_android_manifest_xml()
    if xml_root is None:
        return None

    app_elem = xml_root.find("application")
    if app_elem is None:
        return None

    attribs = app_elem.attrib
    findings: dict[str, Any] = {
        "allow_backup": False,
        "debuggable": False,
        "uses_cleartext_traffic": False,
        "network_security_config": None,
        "request_legacy_external_storage": False,
    }

    # Determine default value of usesCleartextTraffic based on targetSdkVersion
    target_sdk = apk.get_target_sdk_version()
    default_cleartext = True
    if target_sdk:
        try:
            if int(target_sdk) >= 28:
                default_cleartext = False
        except ValueError:
            pass

    # Resolve allowed backup: default is True if not specified
    allow_backup_raw = resolve_ref_value(apk, attribs.get(f"{android_ns}allowBackup", "true"))
    findings["allow_backup"] = _is_true(allow_backup_raw, default=True)

    # Resolve debuggable: default is False
    debuggable_raw = resolve_ref_value(apk, attribs.get(f"{android_ns}debuggable", "false"))
    findings["debuggable"] = _is_true(debuggable_raw, default=False)

    # Resolve usesCleartextTraffic
    default_cleartext_str = "true" if default_cleartext else "false"
    cleartext_raw = resolve_ref_value(apk, attribs.get(f"{android_ns}usesCleartextTraffic", default_cleartext_str))
    findings["uses_cleartext_traffic"] = _is_true(cleartext_raw, default=default_cleartext)

    # Resolve networkSecurityConfig
    net_config = attribs.get(f"{android_ns}networkSecurityConfig")
    if net_config:
        resolved_net_config = resolve_ref_value(apk, net_config)
        findings["network_security_config"] = parse_network_security_config(apk, resolved_net_config)

    # Resolve requestLegacyExternalStorage
    legacy_storage_raw = resolve_ref_value(apk, attribs.get(f"{android_ns}requestLegacyExternalStorage", "false"))
    findings["request_legacy_external_storage"] = _is_true(legacy_storage_raw, default=False)

    return findings


def _is_base_apk(apk: Any) -> bool:
    """Checks whether an APK is the base APK of a split APK set.

    Configuration splits declare a ``split`` attribute on the manifest root element,
    whereas the base APK does not. A standalone (non-split) APK is therefore also
    treated as a base APK.

    Args:
        apk (androguard.core.apk.APK): The parsed APK object.

    Returns:
        bool: True if the APK is the base APK, False for configuration splits or
            when the manifest cannot be read.
    """
    xml_root = apk.get_android_manifest_xml()
    if xml_root is None:
        return False
    return xml_root.attrib.get("split") is None


def _select_base_apk(apks: Sequence[Any]) -> tuple[Any, list[str]]:
    """Selects the base APK from a list of split APKs.

    Args:
        apks (Sequence[Any]): List of parsed APK objects.

    Returns:
        tuple: A ``(base_apk, errors)`` pair where ``base_apk`` is the base APK object
            or None if none could be identified, and ``errors`` is a list of parse
            error strings encountered while inspecting the manifests.
    """
    errors: list[str] = []
    for apk in apks:
        try:
            if _is_base_apk(apk):
                return apk, errors
        except Exception as e:
            errors.append(str(e))
    return None, errors


def analyze_manifest_security(apks: Any) -> dict[str, Any]:
    """Parses AndroidManifest.xml and evaluates security configurations.

    Checks the application manifest for critical security flags such as allowBackup,
    debuggable, usesCleartextTraffic, and requestLegacyExternalStorage.

    Application-level security attributes are read exclusively from the base APK.
    Configuration splits ship a stub ``<application>`` element that omits these
    attributes entirely, so applying the Android platform defaults to a split would
    fabricate flag values that the split never declared. Only the base manifest
    declares these attributes for the merged application.

    Args:
        apks (APK or list): A single parsed APK object or a list of split APK objects.

    Returns:
        dict: A structured report containing:
            - security_flags (dict): Dictionary of evaluated Boolean security-critical attributes.
            - network_security_config (dict, optional): Parsed network security config findings.
            - error (str, optional): Parsing error message if retrieval fails.
    """
    manifest_report: dict[str, Any] = {
        "security_flags": {
            "allow_backup": False,
            "debuggable": False,
            "uses_cleartext_traffic": False,
            "network_security_config_missing": True,
            "request_legacy_external_storage": False,
        }
    }

    if not isinstance(apks, list):
        apks = [apks]

    if not apks:
        manifest_report["error"] = "No APK objects provided for manifest analysis."
        return manifest_report

    android_ns = "{http://schemas.android.com/apk/res/android}"

    base_apk, errors = _select_base_apk(apks)

    if base_apk is None:
        manifest_report["error"] = f"Failed to retrieve AndroidManifest XML from any APK: {'; '.join(errors)}"
        return manifest_report

    try:
        findings = _parse_single_apk_manifest_flags(base_apk, android_ns)
    except Exception as e:
        manifest_report["error"] = f"Failed to retrieve AndroidManifest XML from any APK: {e}"
        return manifest_report

    if findings is None:
        manifest_report["error"] = (
            "Failed to retrieve AndroidManifest XML from any APK: base manifest has no application element."
        )
        return manifest_report

    net_config = findings["network_security_config"]
    if net_config is not None:
        manifest_report["network_security_config"] = net_config

    manifest_report["security_flags"]["allow_backup"] = findings["allow_backup"]
    manifest_report["security_flags"]["debuggable"] = findings["debuggable"]
    manifest_report["security_flags"]["uses_cleartext_traffic"] = findings["uses_cleartext_traffic"]
    manifest_report["security_flags"]["network_security_config_missing"] = net_config is None
    manifest_report["security_flags"]["request_legacy_external_storage"] = findings["request_legacy_external_storage"]

    return manifest_report
