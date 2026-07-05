# Initialization module for the static analysis package.
# Exports all core static scanning and metadata extraction functions.

from .dependencies import extract_dependencies
from .permissions import extract_permissions
from .secrets import extract_secrets
from .urls import extract_urls
from .domains import extract_domains
from .architecture import analyze_ui_framework, analyze_cpu_architecture
from .manifest import analyze_manifest_security
from .security_checks import analyze_security_checks
from .split_apks import parse_split_apks
from .vulnerabilities import analyze_vulnerabilities
from .update_rules import update_rules_db
from .signatures import audit_signatures
from .bytecode_audit import analyze_bytecode

__all__ = [
    "extract_dependencies",
    "extract_permissions",
    "extract_secrets",
    "extract_urls",
    "extract_domains",
    "analyze_ui_framework",
    "analyze_cpu_architecture",
    "analyze_manifest_security",
    "analyze_security_checks",
    "parse_split_apks",
    "analyze_vulnerabilities",
    "update_rules_db",
    "audit_signatures",
    "analyze_bytecode"
]