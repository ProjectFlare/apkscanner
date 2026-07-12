"""Vulnerability analyzer module mapping APK static findings to OWASP Mobile Top 10.

Integrates OSV.dev API queries and manifest component exposure reviews.
"""

import requests
from loguru import logger

from scanner.util.rules import DANGEROUS_DOMAINS, MAVEN_MAPPING, MAVEN_PREFIXES

# OSV.dev vulnerability database API endpoints.
OSV_API_URL = "https://api.osv.dev/v1/querybatch"
OSV_DETAILS_URL_BASE = "https://osv.dev/vulnerability/"


def resolve_maven_coordinate(lib_name):
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

    # Fallback heuristics for packages resembling coordinates
    parts = lib_name.split(".")
    if len(parts) >= 2:
        return f"{lib_name}:{parts[-1]}"

    return None


def _build_osv_queries(third_party_deps):
    """Builds OSV.dev API query payloads and metadata maps.

    Args:
        third_party_deps (dict): Mapping of library name/package to version string.

    Returns:
        tuple[list[dict], list[tuple[str, str]]]: Queries and metadata map.
    """
    queries = []
    metadata_map = []

    for lib, version in third_party_deps.items():
        coordinate = resolve_maven_coordinate(lib)
        if not coordinate:
            continue

        queries.append({"package": {"name": coordinate, "ecosystem": "Maven"}, "version": version})
        metadata_map.append((coordinate, version))

    return queries, metadata_map


def _parse_osv_results(results, metadata_map):
    """Parses raw OSV.dev API results and maps them to vulnerability metadata.

    Args:
        results (list[dict]): Raw results array from OSV response.
        metadata_map (list[tuple[str, str]]): List of (coordinate, version) pairs.

    Returns:
        list[dict]: Extracted vulnerabilities.
    """
    vulnerabilities = []
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


def check_dependencies_osv(third_party_deps):
    """Queries OSV.dev API to discover vulnerabilities in third-party dependencies.

    Args:
        third_party_deps (dict): Mapping of library name/package to version string.

    Returns:
        list[dict]: List of identified vulnerabilities with metadata.
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


def _is_launcher_activity(elem, android_ns):
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


def _audit_apk_manifest_components(apk, android_ns, component_tags):
    """Audits components inside a single APK manifest.

    Args:
        apk: Parsed APK object.
        android_ns (str): Android XML namespace.
        component_tags (list[str]): Tags to audit.

    Returns:
        list[dict]: List of exposed components from this APK.
    """
    from .manifest import _is_true, resolve_ref_value

    exposed = []
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
                exposed.append({"type": tag, "name": resolved_name, "has_intent_filter": has_intent_filter})

    return exposed


def audit_exported_components(apks):
    """Audits AndroidManifest.xml files across all APKs for insecurely exported components.

    Args:
        apks (APK or list): A single parsed APK object or a list of split APK objects.

    Returns:
        list[dict]: List of exposed/exported components lacking permissions.
    """
    exposed = []
    if not isinstance(apks, list):
        apks = [apks]

    android_ns = "{http://schemas.android.com/apk/res/android}"
    component_tags = ["activity", "service", "receiver", "provider"]

    for apk in apks:
        exposed.extend(_audit_apk_manifest_components(apk, android_ns, component_tags))

    return exposed


def _audit_apk_intent_schemas(apk, android_ns):
    """Audits custom schemes in a single APK manifest.

    Args:
        apk: Parsed APK object.
        android_ns (str): Android XML namespace.

    Returns:
        list[dict]: Custom schemes identified in this APK.
    """
    from .manifest import resolve_ref_value

    custom_schemes = []
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
                    custom_schemes.append({"activity": resolved_name, "scheme": resolved_scheme, "host": resolved_host})
    return custom_schemes


def audit_intent_schemas(apks):
    """Audits AndroidManifest.xml files across all APKs for custom scheme intent filters.

    Args:
        apks (APK or list): A single parsed APK object or a list of split APK objects.

    Returns:
        list[dict]: List of components accepting custom scheme data inputs.
    """
    custom_schemes = []
    if not isinstance(apks, list):
        apks = [apks]

    android_ns = "{http://schemas.android.com/apk/res/android}"

    for apk in apks:
        custom_schemes.extend(_audit_apk_intent_schemas(apk, android_ns))

    return custom_schemes


def _map_m1_credentials(report):
    """Maps credential-related findings to OWASP M1: Improper Credential Usage.

    Args:
        report (dict): The generated intermediate scanner report.

    Returns:
        list[dict]: List of identified M1 vulnerabilities.
    """
    vulnerabilities = []
    secrets = report.get("secrets", [])
    if secrets:
        vulnerabilities.append(
            {
                "owasp_id": "M1",
                "category": "Improper Credential Usage",
                "severity": "HIGH",
                "description": "Hardcoded secrets and API keys detected in DEX string pool or raw resource/assets.",
                "evidence": [f"Type: {s['type']}, Value: {s.get('value', s.get('pattern', ''))}" for s in secrets],
                "remediation": "Move sensitive credentials out of compiled code to a secure backend or use keystore systems.",
            }
        )

    bytecode_audit = report.get("bytecode_audit", {})
    if bytecode_audit.get("hardcoded_crypto_keys_detected"):
        vulnerabilities.append(
            {
                "owasp_id": "M1",
                "category": "Improper Credential Usage",
                "severity": "HIGH",
                "description": (
                    "Potential hardcoded symmetric encryption keys initialized with SecretKeySpec "
                    "found in Dalvik bytecode."
                ),
                "evidence": bytecode_audit.get("hardcoded_crypto_keys_evidence", []),
                "remediation": (
                    "Never store cryptographic keys in bytecode or resource strings. Use Android Keystore "
                    "System or retrieve keys dynamically from a secure API endpoint."
                ),
            }
        )
    return vulnerabilities


def _map_m2_supply_chain(report):
    """Maps supply chain related findings to OWASP M2: Inadequate Supply Chain Security.

    Args:
        report (dict): The generated intermediate scanner report.

    Returns:
        list[dict]: List of identified M2 vulnerabilities.
    """
    vulnerabilities = []
    third_party_deps = report.get("dependencies", {}).get("exact_versions_found", {}).get("third_party", {})
    osv_vulns = check_dependencies_osv(third_party_deps)
    if osv_vulns:
        vulnerabilities.append(
            {
                "owasp_id": "M2",
                "category": "Inadequate Supply Chain Security",
                "severity": "HIGH",
                "description": "Third-party libraries with known vulnerabilities (CVEs) detected.",
                "evidence": [f"{v['library']}@{v['version']} -> {v['cve_id']} ({v['summary']})" for v in osv_vulns],
                "remediation": "Upgrade vulnerable packages to versions where the listed CVEs are resolved.",
            }
        )
    return vulnerabilities


def _map_m3_data_storage(report):
    """Maps data storage findings to OWASP M3: Insecure Data Storage.

    Args:
        report (dict): The generated intermediate scanner report.

    Returns:
        list[dict]: List of identified M3 vulnerabilities.
    """
    vulnerabilities = []
    allow_backup = report.get("manifest_audit", {}).get("security_flags", {}).get("allow_backup", True)
    if allow_backup:
        vulnerabilities.append(
            {
                "owasp_id": "M3",
                "category": "Insecure Data Storage",
                "severity": "MEDIUM",
                "description": "Application data backup is enabled ('allowBackup=true').",
                "evidence": ["android:allowBackup=true in application manifest"],
                "remediation": (
                    'Set android:allowBackup="false" in AndroidManifest.xml to prevent copying app private data.'
                ),
            }
        )

    bytecode_audit = report.get("bytecode_audit", {})
    if bytecode_audit.get("zip_slip_detected"):
        vulnerabilities.append(
            {
                "owasp_id": "M3",
                "category": "Insecure Data Storage",
                "severity": "HIGH",
                "description": (
                    "Zip Slip path traversal vulnerability (extracting files from ZipEntry without "
                    "validating path limits) detected in bytecode."
                ),
                "evidence": bytecode_audit.get("zip_slip_evidence", []),
                "remediation": (
                    "Always validate the destination path when extracting archives. Ensure that "
                    "the canonical path of the output file starts with the target directory prefix."
                ),
            }
        )
    return vulnerabilities


def _map_m4_communication(report):
    """Maps communication-related findings to OWASP M4: Insecure Communication.

    Args:
        report (dict): The generated intermediate scanner report.

    Returns:
        list[dict]: List of identified M4 vulnerabilities.
    """
    vulnerabilities = []
    sec_flags = report.get("manifest_audit", {}).get("security_flags", {})
    cleartext_allowed = sec_flags.get("uses_cleartext_traffic", False)

    evidence_comm = []
    if cleartext_allowed:
        evidence_comm.append("android:usesCleartextTraffic=true in application manifest")

    # Check for plain http URLs in code
    urls = report.get("network", {}).get("attributed_urls", {})
    http_urls = []
    for owner, url_list in urls.items():
        for url in url_list:
            if url.startswith("http://"):
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
            {
                "owasp_id": "M4",
                "category": "Insecure Communication",
                "severity": "HIGH" if (cleartext_allowed or malicious_domains_found) else "MEDIUM",
                "description": (
                    "Cleartext traffic configuration, plain HTTP URLs, or malicious domain references identified."
                ),
                "evidence": evidence_comm,
                "remediation": (
                    'Enforce HTTPS connection rules, set android:usesCleartextTraffic="false", '
                    "and avoid insecure hosts."
                ),
            }
        )

    # Network Security Configuration specific audits
    net_config = report.get("manifest_audit", {}).get("network_security_config", {})
    net_global_cleartext = net_config.get("global_cleartext")
    net_domain_cleartext = net_config.get("domain_cleartext_list", [])
    net_user_certs = net_config.get("trusts_user_certs", False)

    if net_global_cleartext:
        vulnerabilities.append(
            {
                "owasp_id": "M4",
                "category": "Insecure Communication",
                "severity": "HIGH",
                "description": "Network Security Configuration permits cleartext traffic globally.",
                "evidence": ['networkSecurityConfig allows cleartextTrafficPermitted="true" globally in base-config'],
                "remediation": (
                    'Set cleartextTrafficPermitted="false" globally in base-config and restrict '
                    "cleartext to specific domains if absolutely necessary."
                ),
            }
        )

    if net_domain_cleartext:
        vulnerabilities.append(
            {
                "owasp_id": "M4",
                "category": "Insecure Communication",
                "severity": "MEDIUM",
                "description": "Network Security Configuration permits cleartext traffic for specific domains.",
                "evidence": [f"Cleartext permitted for domain: {d}" for d in net_domain_cleartext],
                "remediation": "Enforce HTTPS/TLS for all domain communications and avoid cleartext exceptions.",
            }
        )

    if net_user_certs:
        vulnerabilities.append(
            {
                "owasp_id": "M4",
                "category": "Insecure Communication",
                "severity": "HIGH",
                "description": "Network Security Configuration trusts user-installed certificates in production.",
                "evidence": ['<certificates src="user" /> found in production base-config or domain-config'],
                "remediation": (
                    "Remove user-installed CA certificates from the production trust anchors. "
                    "Only trust system/CA certificates."
                ),
            }
        )

    # Bytecode SSL/TLS bypass check
    bytecode_audit = report.get("bytecode_audit", {})
    if bytecode_audit.get("ssl_bypass_detected"):
        vulnerabilities.append(
            {
                "owasp_id": "M4",
                "category": "Insecure Communication",
                "severity": "HIGH",
                "description": "Insecure custom SSL/TLS trust validation bypass found in Dalvik bytecode.",
                "evidence": bytecode_audit.get("ssl_bypass_evidence", []),
                "remediation": (
                    "Do not bypass certificate/hostname checks. Avoid empty TrustManager implementations "
                    "and use default system trust verification or standard certificate pinning configurations."
                ),
            }
        )

    return vulnerabilities


def _map_m5_platform_interaction(apks, report):
    """Maps platform interaction findings to OWASP M5: Inadequate Platform Interaction.

    Args:
        apks (APK or list): A single parsed APK object or a list of split APK objects.
        report (dict): The generated intermediate scanner report.

    Returns:
        list[dict]: List of identified M5 vulnerabilities.
    """
    vulnerabilities = []
    exposed_components = audit_exported_components(apks)
    if exposed_components:
        vulnerabilities.append(
            {
                "owasp_id": "M5",
                "category": "Inadequate Platform Interaction",
                "severity": "MEDIUM",
                "description": "AndroidManifest.xml contains exported components unprotected by permissions.",
                "evidence": [f"{c['type'].capitalize()}: {c['name']}" for c in exposed_components[:10]],
                "remediation": (
                    'Set android:exported="false" unless component must be accessed externally. '
                    "Guard exported elements with permission attributes."
                ),
            }
        )

    bytecode_audit = report.get("bytecode_audit", {})
    if bytecode_audit.get("unsafe_webview_settings_detected"):
        vulnerabilities.append(
            {
                "owasp_id": "M5",
                "category": "Inadequate Platform Interaction",
                "severity": "HIGH",
                "description": "Unsafe WebView settings allowing file access with JavaScript enabled detected in bytecode.",
                "evidence": bytecode_audit.get("unsafe_webview_settings_evidence", []),
                "remediation": (
                    "Ensure WebView configuration restricts file access: setAllowFileAccess(false), "
                    "setAllowFileAccessFromFileURLs(false), and setAllowUniversalAccessFromFileURLs(false)."
                ),
            }
        )
    return vulnerabilities


def _map_m6_security_controls(report):
    """Maps security controls findings to OWASP M6: Inadequate Security Controls.

    Args:
        report (dict): The generated intermediate scanner report.

    Returns:
        list[dict]: List of identified M6 vulnerabilities.
    """
    vulnerabilities = []
    sec_flags = report.get("manifest_audit", {}).get("security_flags", {})
    debuggable = sec_flags.get("debuggable", False)
    if debuggable:
        vulnerabilities.append(
            {
                "owasp_id": "M6",
                "category": "Inadequate Security Controls",
                "severity": "HIGH",
                "description": "Application compiles in debug mode ('debuggable=true').",
                "evidence": ["android:debuggable=true in application manifest"],
                "remediation": 'Set android:debuggable="false" for production and release builds.',
            }
        )

    # Audit debug signing
    sigs = report.get("signatures", {})
    if sigs.get("is_debug_signed"):
        vulnerabilities.append(
            {
                "owasp_id": "M6",
                "category": "Inadequate Security Controls",
                "severity": "HIGH",
                "description": "Application signed with a developer/debug certificate.",
                "evidence": ["Signed with CN=Android Debug or self-signed debug signature."],
                "remediation": (
                    "Sign release builds with a valid production certificate and ensure debug signing is restricted."
                ),
            }
        )

    # Bytecode Dynamic Code Loading check
    bytecode_audit = report.get("bytecode_audit", {})
    if bytecode_audit.get("dynamic_code_loading_detected"):
        vulnerabilities.append(
            {
                "owasp_id": "M6",
                "category": "Inadequate Security Controls",
                "severity": "MEDIUM",
                "description": (
                    "Dynamic code execution or class loading (DexClassLoader/PathClassLoader) detected in bytecode."
                ),
                "evidence": bytecode_audit.get("dynamic_code_loading_evidence", []),
                "remediation": (
                    "Avoid loading dynamic byte arrays or DEX files from writable directories. "
                    "If code loading is necessary, verify signature integrity of loaded files first."
                ),
            }
        )
    return vulnerabilities


def _map_m7_binary_protection(report):
    """Maps binary protection findings to OWASP M7: Insufficient Binary Protection.

    Args:
        report (dict): The generated intermediate scanner report.

    Returns:
        list[dict]: List of identified M7 vulnerabilities.
    """
    vulnerabilities = []
    sec_checks = report.get("security_checks", {})
    root_detection_missing = sec_checks.get("rooted_device_detection", {}).get("detection_missing", True)
    if root_detection_missing:
        vulnerabilities.append(
            {
                "owasp_id": "M7",
                "category": "Insufficient Binary Protection",
                "severity": "LOW",
                "description": "No rooted device detection mechanism found in classes or string references.",
                "evidence": [
                    "No root detection libraries (like Scottyab RootBeer) or common root signatures (like "
                    "'/system/bin/su') were found in the application bytecode or string pool."
                ],
                "remediation": (
                    "Implement system root/jailbreak checks (e.g. Scottyab RootBeer library) to "
                    "detect runtime environments."
                ),
            }
        )

    sigs = report.get("signatures", {})
    if sigs.get("has_weak_hash"):
        vulnerabilities.append(
            {
                "owasp_id": "M7",
                "category": "Insufficient Binary Protection",
                "severity": "MEDIUM",
                "description": "Developer signing certificate uses a weak hash algorithm (MD5/SHA-1).",
                "evidence": [
                    f"Weak hash algorithm detected: {c.get('hash_algo')} for cert {c.get('subject')}"
                    for c in sigs.get("certificates", [])
                    if c.get("hash_algo", "").lower() in ["md5", "sha1"]
                ],
                "remediation": (
                    "Re-sign the application using a certificate generated with a strong hash algorithm like SHA-256."
                ),
            }
        )

    # Bytecode unsafe crypto checks
    bytecode_audit = report.get("bytecode_audit", {})
    if bytecode_audit.get("insecure_crypto_mode_detected"):
        vulnerabilities.append(
            {
                "owasp_id": "M7",
                "category": "Insufficient Binary Protection",
                "severity": "MEDIUM",
                "description": (
                    "Use of insecure symmetric encryption modes (ECB) or weak cryptographic "
                    "algorithms (DES/3DES) detected."
                ),
                "evidence": bytecode_audit.get("insecure_crypto_mode_evidence", []),
                "remediation": (
                    "Re-architect cryptography logic to use AES in a secure mode such as GCM or "
                    "CBC with a randomized Initialization Vector (IV)."
                ),
            }
        )
    return vulnerabilities


def _map_m8_untrusted_inputs(apks):
    """Maps custom schemes findings to OWASP M8: Security Decisions via Untrusted Inputs.

    Args:
        apks (APK or list): A single parsed APK object or a list of split APK objects.

    Returns:
        list[dict]: List of identified M8 vulnerabilities.
    """
    vulnerabilities = []
    custom_filters = audit_intent_schemas(apks)
    if custom_filters:
        vulnerabilities.append(
            {
                "owasp_id": "M8",
                "category": "Security Decisions Via Untrusted Inputs",
                "severity": "MEDIUM",
                "description": (
                    "Activity components registered to accept custom scheme intents (potential deep link hijacking)."
                ),
                "evidence": [f"found {cf['scheme']}://{cf['host'] or ''} in {cf['activity']}" for cf in custom_filters],
                "remediation": "Sanitize and validate all incoming intent data parameters and enforce signature verification.",
            }
        )
    return vulnerabilities


def analyze_vulnerabilities(apks, report):
    """Maps general APK report results to OWASP Mobile Top 10 vulnerability categories.

    Args:
        apks (APK or list): A single parsed APK object or a list of split APK objects.
        report (dict): The generated intermediate scanner report.

    Returns:
        list[dict]: List of identified vulnerabilities aligned to OWASP Mobile Top 10.
    """
    vulnerabilities = []

    # Map findings for each OWASP category
    vulnerabilities.extend(_map_m1_credentials(report))
    vulnerabilities.extend(_map_m2_supply_chain(report))
    vulnerabilities.extend(_map_m3_data_storage(report))
    vulnerabilities.extend(_map_m4_communication(report))
    vulnerabilities.extend(_map_m5_platform_interaction(apks, report))
    vulnerabilities.extend(_map_m6_security_controls(report))
    vulnerabilities.extend(_map_m7_binary_protection(report))
    vulnerabilities.extend(_map_m8_untrusted_inputs(apks))

    return vulnerabilities
