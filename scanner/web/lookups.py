"""Structured registry lookups for the AI report generator (facade module).

Re-exports version and vulnerability lookup functions from dedicated submodules
(`scanner.web.maven`, `scanner.web.osv`, `scanner.web.nvd`) for backwards compatibility.
"""

from scanner.web.maven import lookup_maven_version, resolve_latest_version
from scanner.web.nvd import lookup_nvd_cve
from scanner.web.osv import lookup_osv_vulnerabilities

__all__ = [
    "lookup_maven_version",
    "lookup_nvd_cve",
    "lookup_osv_vulnerabilities",
    "resolve_latest_version",
]
