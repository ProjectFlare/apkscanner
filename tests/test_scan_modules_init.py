"""Unit tests for scanner.scan_modules package exports.

Verifies that __all__ defines all public scan module entry points and that they are directly
accessible from the scanner.scan_modules namespace.
"""

import scanner.scan_modules


def test_scan_modules_package_exports():
    """scanner.scan_modules exports all primary scan functions and classes in __all__."""
    expected_exports = [
        "Deobfuscator",
        "analyze_bytecode",
        "analyze_cpu_architecture",
        "analyze_manifest_security",
        "analyze_security_checks",
        "analyze_security_posture",
        "analyze_ui_framework",
        "analyze_vulnerabilities",
        "audit_signatures",
        "extract_dependencies",
        "extract_domains",
        "extract_permissions",
        "extract_secrets",
        "extract_urls",
        "find_unversioned_third_party",
        "flatten_for_osv",
        "flatten_third_party",
        "is_tracker_domain",
        "parse_network_security_config",
        "resolve_latest_versions",
        "resolve_maven_coordinate",
        "resolve_ref_value",
    ]
    for export in expected_exports:
        assert export in scanner.scan_modules.__all__
        assert hasattr(scanner.scan_modules, export)
        assert getattr(scanner.scan_modules, export) is not None
