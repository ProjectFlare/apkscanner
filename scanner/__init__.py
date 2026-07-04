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
    "parse_split_apks"
]