"""Static analysis scan modules for APK component and bytecode inspection.

Groups specialized scanning submodules for analyzing Android architectures,
Dalvik bytecode, obfuscation translation, third-party dependencies, network domains,
manifest configurations, permissions, secrets, security checks, signatures, and vulnerabilities.
"""

from scanner.scan_modules.architecture import analyze_cpu_architecture, analyze_ui_framework
from scanner.scan_modules.bytecode_audit import analyze_bytecode
from scanner.scan_modules.deobfuscator import Deobfuscator
from scanner.scan_modules.dependencies import (
    extract_dependencies,
    find_unversioned_third_party,
    flatten_for_osv,
    flatten_third_party,
    resolve_latest_versions,
)
from scanner.scan_modules.domains import extract_domains, is_tracker_domain, normalize_domain_from_url
from scanner.scan_modules.manifest import (
    analyze_manifest_security,
    parse_network_security_config,
    resolve_ref_value,
)
from scanner.scan_modules.permissions import extract_permissions
from scanner.scan_modules.secrets import extract_secrets
from scanner.scan_modules.security_checks import analyze_security_checks
from scanner.scan_modules.signatures import audit_signatures
from scanner.scan_modules.urls import extract_urls
from scanner.scan_modules.vulnerabilities import (
    analyze_security_posture,
    analyze_vulnerabilities,
    resolve_maven_coordinate,
)

__all__ = [
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
    "normalize_domain_from_url",
    "parse_network_security_config",
    "resolve_latest_versions",
    "resolve_maven_coordinate",
    "resolve_ref_value",
]
