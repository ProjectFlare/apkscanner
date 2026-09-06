"""Vulnerability analyzer module mapping APK static findings to OWASP Mobile Top 10.

Integrates OSV.dev API queries and manifest component exposure reviews.
"""

from collections.abc import Sequence
from typing import Any

import requests
from loguru import logger

from scanner.scan_modules.dependencies import flatten_for_osv
from scanner.util.rules import (
    CRYPTO_PACKAGE_PATTERNS,
    DANGEROUS_DOMAINS,
    JANUS_MIN_SECURE_SDK,
    MASVS_RULES,
    MAVEN_MAPPING,
    MAVEN_PREFIXES,
    TRUSTED_CRYPTO_LIBRARIES,
)

# OSV.dev vulnerability database API endpoints
OSV_API_URL = "https://api.osv.dev/v1/querybatch"
OSV_DETAILS_URL_BASE = "https://osv.dev/vulnerability/"


def resolve_maven_coordinate(lib_name: str) -> str | None:
    """Resolves a library name or coordinate to standard Maven coordinate.

    Args:
        lib_name (str): The library name or partial coordinate.

    Returns:
        str | None: Resolved groupId:artifactId or None.
    """
    if ":" in lib_name:
        return lib_name

    # Check direct mapping
    if lib_name in MAVEN_MAPPING:
        return MAVEN_MAPPING[lib_name]

    # Dynamic prefix-based mappings
    for prefix, group in MAVEN_PREFIXES.items():
        if lib_name.startswith(prefix):
            return f"{group}:{lib_name}"

    # Google maven .properties keys concatenate "<groupId>_<artifactId>", e.g.
    # "androidx.activity_activity-compose" is androidx.activity:activity-compose. The dotted
    # group requirement keeps names like "kotlinx_coroutines_core" out of this branch.
    group, sep, artifact = lib_name.partition("_")
    if sep and artifact and "." in group:
        return f"{group}:{artifact}"

    # Fallback heuristics for packages resembling coordinates
    parts = lib_name.split(".")
    if len(parts) >= 2:
        return f"{lib_name}:{parts[-1]}"

    return None


def _build_osv_queries(
    third_party_deps: dict[str, str],
) -> tuple[list[dict[str, Any]], list[tuple[str, str]]]:
    """Builds OSV.dev API query payloads and metadata maps.

    Args:
        third_party_deps (dict[str, str]): Mapping of library name/package to version string.

    Returns:
        tuple[list[dict[str, Any]], list[tuple[str, str]]]: Queries and metadata map.
    """
    queries: list[dict[str, Any]] = []
    metadata_map: list[tuple[str, str]] = []

    for lib, version in third_party_deps.items():
        coordinate = resolve_maven_coordinate(lib)
        if not coordinate:
            continue

        queries.append({"package": {"name": coordinate, "ecosystem": "Maven"}, "version": version})
        metadata_map.append((coordinate, version))

    return queries, metadata_map


def _parse_osv_results(results: list[dict[str, Any]], metadata_map: list[tuple[str, str]]) -> list[dict[str, str]]:
    """Parses raw OSV.dev API results and maps them to vulnerability metadata.

    Args:
        results (list[dict[str, Any]]): Raw results array from OSV response.
        metadata_map (list[tuple[str, str]]): List of (coordinate, version) pairs.

    Returns:
        list[dict[str, str]]: Extracted vulnerabilities.
    """
    vulnerabilities: list[dict[str, str]] = []
    for i, res in enumerate(results):
        vulns = res.get("vulns", [])
        if not vulns:
            continue

        coord, ver = metadata_map[i]
        for vuln in vulns:
            vuln_id = vuln.get("id", "Unknown")
            summary = vuln.get("summary", "No summary provided")
            aliases = vuln.get("aliases", [])
            cve_id = next((a for a in aliases if a.startswith("CVE-")), vuln_id)

            vulnerabilities.append(
                {
                    "library": coord,
                    "version": ver,
                    "vuln_id": vuln_id,
                    "cve_id": cve_id,
                    "summary": summary,
                    "details_url": f"{OSV_DETAILS_URL_BASE}{vuln_id}",
                }
            )
    return vulnerabilities


def check_dependencies_osv(third_party_deps: dict[str, str]) -> list[dict[str, str]]:
    """Queries OSV.dev API to discover vulnerabilities in third-party dependencies.

    Args:
        third_party_deps (dict[str, str]): Mapping of library name/package to version string.

    Returns:
        list[dict[str, str]]: List of identified vulnerabilities with metadata.
    """
    if not third_party_deps:
        return []

    queries, metadata_map = _build_osv_queries(third_party_deps)
    if not queries:
        return []

    logger.info(f"Querying OSV.dev API for {len(queries)} dependencies...")
    try:
        response = requests.post(OSV_API_URL, json={"queries": queries}, timeout=10)
        response.raise_for_status()
        results = response.json().get("results", [])
        return _parse_osv_results(results, metadata_map)
    except Exception as e:
        logger.warning(f"OSV.dev vulnerability query failed (running offline?): {e}")
        return []


def _is_launcher_activity(elem: Any, android_ns: str) -> bool:
    """Checks if an activity element has MAIN and LAUNCHER intent filter.

    Args:
        elem: XML element of the activity.
        android_ns (str): Android XML namespace.

    Returns:
        bool: True if it is a launcher activity, False otherwise.
    """
    for filter_elem in elem.findall("intent-filter"):
        actions = [a.attrib.get(f"{android_ns}name") for a in filter_elem.findall("action")]
        categories = [c.attrib.get(f"{android_ns}name") for c in filter_elem.findall("category")]
        if "android.intent.action.MAIN" in actions and "android.intent.category.LAUNCHER" in categories:
            return True
    return False


def _audit_apk_manifest_components(apk: Any, android_ns: str, component_tags: Sequence[str]) -> list[dict[str, str]]:
    """Audits components inside a single APK manifest.

    Args:
        apk: Parsed APK object.
        android_ns (str): Android XML namespace.
        component_tags (Sequence[str]): Tags to audit.

    Returns:
        list[dict[str, str]]: List of exposed components from this APK.
    """
    from .manifest import _is_true, resolve_ref_value

    exposed: list[dict[str, str]] = []
    try:
        root = apk.get_android_manifest_xml()
        if root is None:
            return []
    except Exception:
        return []

    app_elem = root.find("application")
    if app_elem is None:
        return []

    for tag in component_tags:
        for elem in app_elem.findall(tag):
            name = elem.attrib.get(f"{android_ns}name")
            exported_attr = elem.attrib.get(f"{android_ns}exported")
            permission = elem.attrib.get(f"{android_ns}permission")

            # Check if intent filters are present, which affects default exportation
            has_intent_filter = elem.find("intent-filter") is not None

            is_exported = False
            if exported_attr:
                resolved_exported = resolve_ref_value(apk, exported_attr)
                is_exported = _is_true(resolved_exported, default=False)
            elif has_intent_filter:
                # Default exported on API < 31 if it has intent-filters and exported is not specified
                is_exported = True

            # Check if this activity is a launcher activity (which must be exported by design)
            is_launcher = False
            if tag == "activity":
                is_launcher = _is_launcher_activity(elem, android_ns)

            if is_exported and not permission and not is_launcher:
                resolved_name = resolve_ref_value(apk, name)
                # Flag as exposed since it is exported and has no guarding permission
                exposed.append({"type": tag, "name": str(resolved_name)})

    return exposed


def audit_exported_components(apks: Any) -> list[dict[str, str]]:
    """Audits AndroidManifest.xml files across all APKs for insecurely exported components.

    Args:
        apks (APK or list): A single parsed APK object or a list of split APK objects.

    Returns:
        list[dict[str, str]]: List of exposed/exported components lacking permissions.
    """
    exposed: list[dict[str, str]] = []
    if not isinstance(apks, list):
        apks = [apks]

    android_ns = "{http://schemas.android.com/apk/res/android}"
    component_tags = ["activity", "service", "receiver", "provider"]

    for apk in apks:
        exposed.extend(_audit_apk_manifest_components(apk, android_ns, component_tags))

    return exposed


def _audit_apk_intent_schemas(apk: Any, android_ns: str) -> list[dict[str, Any]]:
    """Audits custom schemes in a single APK manifest.

    Args:
        apk: Parsed APK object.
        android_ns (str): Android XML namespace.

    Returns:
        list[dict[str, Any]]: Custom schemes identified in this APK.
    """
    from .manifest import resolve_ref_value

    custom_schemes: list[dict[str, Any]] = []
    try:
        root = apk.get_android_manifest_xml()
        if root is None:
            return []
    except Exception:
        return []

    app_elem = root.find("application")
    if app_elem is None:
        return []

    for activity in app_elem.findall("activity"):
        name = activity.attrib.get(f"{android_ns}name")
        resolved_name = resolve_ref_value(apk, name)
        for filter_elem in activity.findall("intent-filter"):
            for data in filter_elem.findall("data"):
                scheme = data.attrib.get(f"{android_ns}scheme")
                host = data.attrib.get(f"{android_ns}host")

                resolved_scheme = resolve_ref_value(apk, scheme)
                resolved_host = resolve_ref_value(apk, host)

                if resolved_scheme and resolved_scheme not in ["http", "https", "file", "content"]:
                    custom_schemes.append(
                        {
                            "activity": str(resolved_name) if resolved_name is not None else "",
                            "scheme": str(resolved_scheme),
                            "host": str(resolved_host) if resolved_host is not None else None,
                        }
                    )
    return custom_schemes


def audit_intent_schemas(apks: Any) -> list[dict[str, Any]]:
    """Audits AndroidManifest.xml files across all APKs for custom scheme intent filters.

    Args:
        apks (APK or list): A single parsed APK object or a list of split APK objects.

    Returns:
        list[dict[str, Any]]: List of components accepting custom scheme data inputs.
    """
    custom_schemes: list[dict[str, Any]] = []
    if not isinstance(apks, list):
        apks = [apks]

    android_ns = "{http://schemas.android.com/apk/res/android}"

    for apk in apks:
        custom_schemes.extend(_audit_apk_intent_schemas(apk, android_ns))

    return custom_schemes


def _create_finding(
    rule_id: str,
    evidence: list[str],
    severity_override: str | None = None,
) -> dict[str, Any]:
    """Builds a standardized finding dictionary populated from database-backed MASVS rules.

    Args:
        rule_id (str): Internal identifier in MASVS_RULES.
        evidence (list[str]): List of concrete evidence strings.
        severity_override (str | None): Optional severity override.

    Returns:
        dict[str, Any]: Finding dictionary aligned to OWASP MASVS and Mobile Top 10.
    """
    rule = MASVS_RULES.get(rule_id, {})
    return {
        "owasp_id": rule.get("owasp_mobile_id", "M0"),
        "masvs_id": rule.get("masvs_id", "MASVS-GENERIC"),
        "masvs_category": rule.get("masvs_category", "MASVS-GENERIC"),
        "mastg_id": rule.get("mastg_id", "MASTG-GENERIC"),
        "category": rule.get("category_name", "General Security"),
        "title": rule.get("title", "Security Finding"),
        "severity": severity_override or rule.get("default_severity", "MEDIUM"),
        "evidence": evidence,
    }


def _map_m1_credentials(report: dict[str, Any]) -> list[dict[str, Any]]:  # noqa: ARG001
    """Maps credential-related findings to OWASP M1 and MASVS-STORAGE-1 / MASVS-CRYPTO-1.

    Hardcoded secrets, keys, and credentials discovered via regex matching are audited
    and contextualized within the dedicated Secrets module and report section rather than
    classified as confirmed high-severity M1 vulnerabilities without runtime verification.

    Args:
        report (dict[str, Any]): The generated intermediate scanner report.

    Returns:
        list[dict[str, Any]]: List of identified M1/MASVS vulnerabilities.
    """
    return []


def _map_m2_supply_chain(report: dict[str, Any]) -> list[dict[str, Any]]:
    """Maps supply chain related findings to OWASP M2 and MASVS-CODE-4.

    Args:
        report (dict[str, Any]): The generated intermediate scanner report.

    Returns:
        list[dict[str, Any]]: List of identified M2/MASVS vulnerabilities.
    """
    vulnerabilities: list[dict[str, Any]] = []
    deps_block = report.get("dependencies", {})
    osv_vulns: list[dict[str, Any]] = []

    # Unified schema support
    if "third_party" in deps_block or "android_default" in deps_block:
        for group in ("third_party", "android_default"):
            for lib_name, details in deps_block.get(group, {}).items():
                if isinstance(details, dict):
                    for finding in details.get("osv_findings", []):
                        osv_vulns.append(
                            {
                                "library": finding.get("library", lib_name),
                                "version": finding.get("version", details.get("version_used")),
                                "cve_id": finding.get("cve_id"),
                                "summary": finding.get("summary"),
                            }
                        )
    else:
        # Legacy fallback
        raw_osv = deps_block.get("osv_findings")
        if raw_osv is None:
            raw_osv = check_dependencies_osv(flatten_for_osv(deps_block.get("exact_versions_found", {})))
        osv_vulns = raw_osv or []

    if osv_vulns:
        vulnerabilities.append(
            _create_finding(
                "vulnerable_dependencies",
                evidence=[
                    f"{v.get('library', 'unknown')}@{v.get('version', 'unknown')} -> {v.get('cve_id', '')} ({v.get('summary', '')})"
                    for v in osv_vulns
                ],
            )
        )
    return vulnerabilities


def _map_m3_data_storage(report: dict[str, Any]) -> list[dict[str, Any]]:
    """Maps data storage findings to OWASP M3 and MASVS-STORAGE-1/2.

    Args:
        report (dict[str, Any]): The generated intermediate scanner report.

    Returns:
        list[dict[str, Any]]: List of identified M3/MASVS vulnerabilities.
    """
    vulnerabilities: list[dict[str, Any]] = []
    allow_backup = report.get("manifest_audit", {}).get("security_flags", {}).get("allow_backup", True)
    if allow_backup:
        vulnerabilities.append(
            _create_finding(
                "allow_backup",
                evidence=["android:allowBackup=true in application manifest"],
            )
        )
    return vulnerabilities


def _map_m4_communication(report: dict[str, Any]) -> list[dict[str, Any]]:
    """Maps communication-related findings to OWASP M4 and MASVS-NETWORK-1/2.

    Args:
        report (dict[str, Any]): The generated intermediate scanner report.

    Returns:
        list[dict[str, Any]]: List of identified M4/MASVS vulnerabilities.
    """
    vulnerabilities: list[dict[str, Any]] = []
    sec_flags = report.get("manifest_audit", {}).get("security_flags", {})
    net_config = report.get("manifest_audit", {}).get("network_security_config", {})

    cleartext_allowed = sec_flags.get("uses_cleartext_traffic", False)
    net_global_cleartext = net_config.get("global_cleartext", False)
    net_domain_cleartext = set(net_config.get("domain_cleartext_list", []))

    evidence_comm = []
    if cleartext_allowed:
        evidence_comm.append("android:usesCleartextTraffic=true in application manifest")

    # Plain http URLs in code are only active vulnerabilities if cleartext traffic is permitted
    # by manifest or network security configuration; otherwise Android blocks them at runtime.
    urls = report.get("network", {}).get("attributed_urls", {})
    http_urls = []
    for owner, url_list in urls.items():
        for url in url_list:
            if url.startswith("http://"):
                domain_part = url[7:].split("/", 1)[0].split(":", 1)[0]
                if cleartext_allowed or net_global_cleartext or domain_part in net_domain_cleartext:
                    http_urls.append(f"{url} (referenced by {owner})")

    if http_urls:
        evidence_comm.extend([f"HTTP URL reference: {u}" for u in http_urls[:10]])
        if len(http_urls) > 10:
            evidence_comm.append(f"... and {len(http_urls) - 10} more plain HTTP URL references found in code.")

    # Check for connections to known malicious domains
    domains = report.get("network", {}).get("categorized_domains", {})
    all_domains = []
    for cat in domains.values():
        all_domains.extend(cat)

    malicious_domains_found = [d for d in all_domains if d in DANGEROUS_DOMAINS]
    if malicious_domains_found:
        evidence_comm.append(f"Connection references to dangerous domains: {', '.join(malicious_domains_found)}")

    if evidence_comm:
        vulnerabilities.append(
            _create_finding(
                "cleartext_traffic",
                evidence=evidence_comm,
                severity_override="HIGH" if (cleartext_allowed or malicious_domains_found) else "MEDIUM",
            )
        )

    if net_global_cleartext:
        vulnerabilities.append(
            _create_finding(
                "net_global_cleartext",
                evidence=['networkSecurityConfig allows cleartextTrafficPermitted="true" globally in base-config'],
            )
        )

    if net_domain_cleartext:
        vulnerabilities.append(
            _create_finding(
                "net_domain_cleartext",
                evidence=[f"Cleartext permitted for domain: {d}" for d in sorted(net_domain_cleartext)],
            )
        )

    if net_config.get("trusts_user_certs", False):
        vulnerabilities.append(
            _create_finding(
                "net_user_certs",
                evidence=['<certificates src="user" /> found in production base-config or domain-config'],
            )
        )

    # Bytecode SSL/TLS bypass check
    bytecode_audit = report.get("bytecode_audit", {})
    ssl_bypass_ev = bytecode_audit.get("ssl_bypass") or bytecode_audit.get("ssl_bypass_evidence")
    if ssl_bypass_ev:
        vulnerabilities.append(
            _create_finding(
                "ssl_bypass",
                evidence=ssl_bypass_ev,
            )
        )

    return vulnerabilities


def _map_m5_platform_interaction(report: dict[str, Any]) -> list[dict[str, Any]]:
    """Maps platform interaction findings to OWASP M5 and MASVS-PLATFORM-2.

    Exported components are intentionally NOT reported here: their mere presence is attack
    surface, not a confirmed weakness, so they are surfaced as informational posture via
    :func:`analyze_security_posture` instead of penalising the security score.

    Args:
        report (dict[str, Any]): The generated intermediate scanner report.

    Returns:
        list[dict[str, Any]]: List of identified M5/MASVS vulnerabilities.
    """
    vulnerabilities: list[dict[str, Any]] = []
    bytecode_audit = report.get("bytecode_audit", {})
    raw_unsafe = (
        bytecode_audit.get("unsafe_webview_settings") or bytecode_audit.get("unsafe_webview_settings_evidence") or []
    )
    permissive_webviews = list(bytecode_audit.get("permissive_webview_file_access") or [])

    # Tier into universal cross-origin access (HIGH) vs local file access (MEDIUM)
    universal_webviews = []
    for ev in raw_unsafe:
        ev_lower = ev.lower()
        if "setallowuniversalaccessfromfileurls" in ev_lower or "setallowfileaccessfromfileurls" in ev_lower:
            universal_webviews.append(ev)
        else:
            permissive_webviews.append(ev)

    if universal_webviews:
        vulnerabilities.append(
            _create_finding(
                "unsafe_webview",
                evidence=sorted(set(universal_webviews)),
            )
        )
    if permissive_webviews:
        vulnerabilities.append(
            _create_finding(
                "permissive_webview_file_access",
                evidence=sorted(set(permissive_webviews)),
            )
        )
    return vulnerabilities


def _map_m6_security_controls(report: dict[str, Any]) -> list[dict[str, Any]]:
    """Maps security controls findings to OWASP M6 and MASVS-CODE-1/2.

    Args:
        report (dict[str, Any]): The generated intermediate scanner report.

    Returns:
        list[dict[str, Any]]: List of identified M6/MASVS vulnerabilities.
    """
    vulnerabilities: list[dict[str, Any]] = []
    sec_flags = report.get("manifest_audit", {}).get("security_flags", {})
    debuggable = sec_flags.get("debuggable", False)
    if debuggable:
        vulnerabilities.append(
            _create_finding(
                "debuggable",
                evidence=["android:debuggable=true in application manifest"],
            )
        )

    # Audit debug signing
    sigs = report.get("signatures", {})
    if sigs.get("is_debug_signed"):
        vulnerabilities.append(
            _create_finding(
                "debug_signed",
                evidence=["Signed with CN=Android Debug or self-signed debug signature."],
            )
        )

    # Dynamic code loading is intentionally NOT scored here: PathClassLoader is Android's
    # default class loader, so this detection is highly false-positive-prone and cannot confirm
    # that code is loaded from an untrusted source. It is surfaced as informational posture via
    # analyze_security_posture instead.
    return vulnerabilities


def _map_m7_binary_protection(report: dict[str, Any]) -> list[dict[str, Any]]:
    """Maps binary protection findings to OWASP M7, MASVS-CODE-1, and MASVS-CRYPTO-1.

    Args:
        report (dict[str, Any]): The generated intermediate scanner report.

    Returns:
        list[dict[str, Any]]: List of identified M7/MASVS vulnerabilities.
    """
    vulnerabilities: list[dict[str, Any]] = []
    sigs = report.get("signatures", {})
    schemes = [str(s).lower() for s in sigs.get("scheme_versions", [])]
    has_modern_scheme = any("v2" in s or "v3" in s or "v4" in s for s in schemes)
    # Weak hash algorithm is ONLY reported if the APK is strictly v1-only (lacks modern v2/v3/v4 schemes).
    # Modern signature schemes enforce full-file SHA-256 integrity, making legacy cert hashes irrelevant.
    if sigs.get("has_weak_hash") and (sigs.get("v1_only_signature") or not has_modern_scheme):
        vulnerabilities.append(
            _create_finding(
                "weak_hash",
                evidence=[
                    f"Weak hash algorithm detected: {c.get('hash_algo')} for cert {c.get('subject')}"
                    for c in sigs.get("certificates", [])
                    if c.get("hash_algo", "").lower() in ["md5", "sha1"]
                ],
            )
        )

    # Janus (CVE-2017-13156) is exploitable on Android 5.0-8.1 (API 21-27).
    # If minSdkVersion >= JANUS_MIN_SECURE_SDK, the app cannot be installed on Janus-vulnerable OS builds.
    if sigs.get("v1_only_signature"):
        min_sdk = str(report.get("apk_metadata", {}).get("min_sdk_version") or "")
        is_janus_vulnerable = not (min_sdk.isdigit() and int(min_sdk) >= JANUS_MIN_SECURE_SDK)
        if is_janus_vulnerable:
            evidence = [
                f"Active signature schemes: {', '.join(sigs.get('scheme_versions', [])) or 'none'}",
                f"minSdkVersion {min_sdk or 'unknown'}: installable on Janus-vulnerable Android 5.0-8.1 devices",
            ]
            vulnerabilities.append(
                _create_finding(
                    "v1_only_signature",
                    evidence=evidence,
                )
            )

    # Bytecode unsafe crypto checks (filters out trusted crypto libraries, generic crypto packages, and SDK primitives)
    bytecode_audit = report.get("bytecode_audit", {})
    deprecated_ciphers_ev = list(bytecode_audit.get("deprecated_cipher_algorithm") or [])
    unpadded_ecb_ev = list(bytecode_audit.get("unpadded_ecb_primitive") or [])
    raw_evidence = (
        bytecode_audit.get("insecure_crypto_mode") or bytecode_audit.get("insecure_crypto_mode_evidence") or []
    )
    if raw_evidence or deprecated_ciphers_ev or unpadded_ecb_ev:
        filtered_evidence = []
        for e in raw_evidence:
            e_lower = e.lower()
            if any(lib.lower() in e_lower for lib in TRUSTED_CRYPTO_LIBRARIES):
                continue
            if any(pat in e_lower for pat in CRYPTO_PACKAGE_PATTERNS):
                continue
            if "'des'" in e_lower or "'desede'" in e_lower:
                deprecated_ciphers_ev.append(e)
                continue
            if "aes/ecb/nopadding" in e_lower:
                unpadded_ecb_ev.append(e)
                continue
            filtered_evidence.append(e)

        unpadded_ecb_ev = [
            e
            for e in unpadded_ecb_ev
            if not any(lib.lower() in e.lower() for lib in TRUSTED_CRYPTO_LIBRARIES)
            and not any(pat in e.lower() for pat in CRYPTO_PACKAGE_PATTERNS)
        ]

        if deprecated_ciphers_ev:
            vulnerabilities.append(
                _create_finding(
                    "deprecated_cipher_algorithm",
                    evidence=sorted(set(deprecated_ciphers_ev)),
                )
            )

        if unpadded_ecb_ev:
            vulnerabilities.append(
                _create_finding(
                    "unpadded_ecb_primitive",
                    evidence=sorted(set(unpadded_ecb_ev)),
                )
            )

        if filtered_evidence:
            vulnerabilities.append(
                _create_finding(
                    "insecure_crypto_mode",
                    evidence=sorted(set(filtered_evidence)),
                )
            )
    return vulnerabilities


def analyze_security_posture(apks: Any, report: dict[str, Any]) -> list[dict[str, Any]]:
    """Collects informational security-posture observations that do NOT affect the score.

    Only facts that are actually PRESENT are returned, so the section never fills up with
    "not found" entries. These are either attack-surface facts that static analysis cannot
    confirm are exploitable (exported components, custom deep-link schemes, dynamic code loading)
    or a defensive feature that was detected (rooted-device detection, packer / binary
    protection, legacy v1 signature hardening). Dedicated sections cover secrets (Section 6) and
    bytecode audits (Section 7); those items are omitted here to avoid duplication.
    Each carries the concrete evidence, with no severity and no score impact; the
    human-readable explanation is written by the AI report layer, not stored here.

    Args:
        apks (APK or list): A single parsed APK object or a list of split APK objects.
        report (dict[str, Any]): The generated intermediate scanner report.

    Returns:
        list[dict[str, Any]]: List of present informational observations, each with ``type``, ``title``,
            ``masvs_id``, ``mastg_id``, and ``evidence``.
    """
    items: list[dict[str, Any]] = []

    exposed_components = audit_exported_components(apks)
    if exposed_components:
        rule = MASVS_RULES.get("exported_components", {})
        items.append(
            {
                "type": "exported_components",
                "title": rule.get("title", "Exported Components"),
                "masvs_id": rule.get("masvs_id", "MASVS-PLATFORM-1"),
                "mastg_id": rule.get("mastg_id", "MASTG-PLATFORM-1"),
                "evidence": [f"{c['type'].capitalize()}: {c['name']}" for c in exposed_components[:10]],
            }
        )

    custom_filters = audit_intent_schemas(apks)
    if custom_filters:
        rule = MASVS_RULES.get("custom_scheme_intents", {})
        items.append(
            {
                "type": "custom_scheme_intents",
                "title": rule.get("title", "Custom Scheme Deep Links"),
                "masvs_id": rule.get("masvs_id", "MASVS-PLATFORM-1"),
                "mastg_id": rule.get("mastg_id", "MASTG-PLATFORM-1"),
                "evidence": [f"{cf['scheme']}://{cf['host'] or ''} in {cf['activity']}" for cf in custom_filters],
            }
        )

    root_indicators = report.get("security_checks", {}).get("rooted_device_detection", [])
    if isinstance(root_indicators, dict):
        root_indicators = root_indicators.get("indicators", [])
    if root_indicators:
        rule = MASVS_RULES.get("root_detection", {})
        items.append(
            {
                "type": "root_detection",
                "title": rule.get("title", "Rooted-Device Detection"),
                "masvs_id": rule.get("masvs_id", "MASVS-RESILIENCE-1"),
                "mastg_id": rule.get("mastg_id", "MASTG-RESILIENCE-1"),
                "evidence": root_indicators,
            }
        )

    packer = report.get("security_checks", {}).get("static_analysis", {}).get("packer_detected")
    if packer:
        rule = MASVS_RULES.get("packer", {})
        items.append(
            {
                "type": "packer",
                "title": rule.get("title", "Packer / Binary Protection"),
                "masvs_id": rule.get("masvs_id", "MASVS-RESILIENCE-2"),
                "mastg_id": rule.get("mastg_id", "MASTG-RESILIENCE-2"),
                "evidence": [f"Packer or protector detected: {packer}"],
            }
        )

    bytecode_audit = report.get("bytecode_audit", {})
    dcl_ev = bytecode_audit.get("dynamic_code_loading") or bytecode_audit.get("dynamic_code_loading_evidence")
    if dcl_ev:
        rule = MASVS_RULES.get("dynamic_code_loading", {})
        items.append(
            {
                "type": "dynamic_code_loading",
                "title": rule.get("title", "Dynamic Code Loading"),
                "masvs_id": rule.get("masvs_id", "MASVS-CODE-3"),
                "mastg_id": rule.get("mastg_id", "MASTG-CODE-3"),
                "evidence": dcl_ev,
            }
        )

    # Legacy v1-only signing when mitigated by minSdkVersion >= JANUS_MIN_SECURE_SDK
    sigs = report.get("signatures", {})
    min_sdk = str(report.get("apk_metadata", {}).get("min_sdk_version") or "")
    if sigs.get("v1_only_signature") and min_sdk.isdigit() and int(min_sdk) >= JANUS_MIN_SECURE_SDK:
        rule = MASVS_RULES.get("v1_only_signature_hardened", {})
        items.append(
            {
                "type": "v1_only_signature",
                "title": rule.get("title", "Legacy v1 Signature Scheme (Hardened by MinSDK)"),
                "masvs_id": rule.get("masvs_id", "MASVS-CODE-1"),
                "mastg_id": rule.get("mastg_id", "MASTG-CODE-1"),
                "evidence": [
                    f"Signed with legacy v1 scheme only, but minSdkVersion={min_sdk} prevents installation on Janus-vulnerable devices (API <= {JANUS_MIN_SECURE_SDK - 1})."
                ],
            }
        )

    return items


def analyze_vulnerabilities(report: dict[str, Any]) -> list[dict[str, Any]]:
    """Maps general APK report results to OWASP MASVS v2.0 and Mobile Top 10 vulnerability categories.

    Only confirmed, evidence-backed weaknesses that should affect the security score are
    returned here. Attack-surface and defensive-posture observations are produced separately
    by :func:`analyze_security_posture` and carry no score penalty.

    Args:
        report (dict[str, Any]): The generated intermediate scanner report.

    Returns:
        list[dict[str, Any]]: List of identified vulnerabilities aligned to OWASP MASVS and Mobile Top 10.
    """
    vulnerabilities: list[dict[str, Any]] = []

    # Map findings for each OWASP category
    vulnerabilities.extend(_map_m1_credentials(report))
    vulnerabilities.extend(_map_m2_supply_chain(report))
    vulnerabilities.extend(_map_m3_data_storage(report))
    vulnerabilities.extend(_map_m4_communication(report))
    vulnerabilities.extend(_map_m5_platform_interaction(report))
    vulnerabilities.extend(_map_m6_security_controls(report))
    vulnerabilities.extend(_map_m7_binary_protection(report))

    return vulnerabilities
