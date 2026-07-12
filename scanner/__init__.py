"""Initialization module for the static analysis package.

Exports all core static scanning and metadata extraction functions.
"""

from .scan_modules.architecture import analyze_cpu_architecture, analyze_ui_framework
from .scan_modules.bytecode_audit import analyze_bytecode
from .scan_modules.deobfuscator import Deobfuscator
from .scan_modules.dependencies import extract_dependencies
from .scan_modules.domains import extract_domains
from .scan_modules.manifest import analyze_manifest_security
from .scan_modules.permissions import extract_permissions
from .scan_modules.secrets import extract_secrets
from .scan_modules.security_checks import analyze_security_checks
from .scan_modules.signatures import audit_signatures
from .scan_modules.urls import extract_urls
from .scan_modules.vulnerabilities import analyze_vulnerabilities
from .util.ai_report import generate_ai_report
from .util.split_apks import parse_split_apks
from .util.update_rules import update_rules_db

__all__ = [
    "Deobfuscator",
    "analyze_bytecode",
    "analyze_cpu_architecture",
    "analyze_manifest_security",
    "analyze_security_checks",
    "analyze_ui_framework",
    "analyze_vulnerabilities",
    "audit_signatures",
    "extract_dependencies",
    "extract_domains",
    "extract_permissions",
    "extract_secrets",
    "extract_urls",
    "generate_ai_report",
    "parse_split_apks",
    "update_rules_db",
]
