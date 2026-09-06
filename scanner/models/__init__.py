"""Database models package initialization.

Exports the declarative SQLModel classes for dynamic threat intelligence tables in rules.db.
"""

from scanner.models.ai_report import (
    AppContextModel,
    BaseReportModel,
    DependenciesSectionModel,
    DependencyItem,
    FindingItem,
    FindingsSectionModel,
    InformationalItem,
    InformationalSectionModel,
    NetworkDomainItem,
    NetworkSectionModel,
    PermissionItem,
    PermissionsSectionModel,
    SecurityIncident,
    SourceItem,
    VulnerabilitiesSectionModel,
    VulnerabilityFindingItem,
    clean_code_snippet,
    is_dummy_code_snippet,
)
from scanner.models.rules_db import (
    DangerousDomain,
    RuntimePermission,
    TrackerKeyword,
    TrackerSignature,
)

__all__ = [
    "AppContextModel",
    "BaseReportModel",
    "DangerousDomain",
    "DependenciesSectionModel",
    "DependencyItem",
    "FindingItem",
    "FindingsSectionModel",
    "InformationalItem",
    "InformationalSectionModel",
    "NetworkDomainItem",
    "NetworkSectionModel",
    "PermissionItem",
    "PermissionsSectionModel",
    "RuntimePermission",
    "SecurityIncident",
    "SourceItem",
    "TrackerKeyword",
    "TrackerSignature",
    "VulnerabilitiesSectionModel",
    "VulnerabilityFindingItem",
    "clean_code_snippet",
    "is_dummy_code_snippet",
]
