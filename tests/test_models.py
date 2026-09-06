"""Unit tests for scanner.models package.

Verifies package exports, SQLModel class definitions, table names, default values,
and in-memory SQLite table creation and query capabilities for threat intelligence tables.
"""

from sqlalchemy import inspect
from sqlmodel import Session, SQLModel, create_engine, select

import scanner.models
from scanner.models import (
    DangerousDomain,
    RuntimePermission,
    TrackerKeyword,
    TrackerSignature,
)


def test_models_package_exports():
    """scanner.models exports threat intelligence and AI report classes in __all__."""
    expected_exports = [
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
    assert sorted(scanner.models.__all__) == sorted(expected_exports)
    for export in expected_exports:
        assert export in scanner.models.__all__
        assert hasattr(scanner.models, export)
        assert getattr(scanner.models, export) is not None


def test_models_instantiation():
    """Verifies that all 4 dynamic model classes can be instantiated correctly."""
    perm = RuntimePermission(name="android.permission.CAMERA")
    assert perm.name == "android.permission.CAMERA"

    tracker = TrackerKeyword(keyword="analytics")
    assert tracker.keyword == "analytics"

    sig = TrackerSignature(id="42", name="TrackerX", network_signature=r"trackerx\.com")
    assert sig.id == "42"
    assert sig.name == "TrackerX"
    assert sig.network_signature == r"trackerx\.com"

    domain = DangerousDomain(domain="malware-sample.test")
    assert domain.domain == "malware-sample.test"


def test_models_table_names():
    """Verifies that all model classes declare the expected __tablename__."""
    expected_tables = {
        RuntimePermission: "runtime_permissions",
        TrackerKeyword: "tracker_keywords",
        TrackerSignature: "tracker_signatures",
        DangerousDomain: "dangerous_domains",
    }
    for model_cls, table_name in expected_tables.items():
        assert model_cls.__tablename__ == table_name


def test_in_memory_db_table_creation():
    """Verifies in-memory SQLite schema creation, record insertion, and queries."""
    engine = create_engine("sqlite:///:memory:")
    SQLModel.metadata.create_all(engine)

    inspector = inspect(engine)
    table_names = set(inspector.get_table_names())

    expected_tables = {
        "runtime_permissions",
        "tracker_keywords",
        "tracker_signatures",
        "dangerous_domains",
    }
    assert expected_tables.issubset(table_names)

    # Verify session insertion and selection
    with Session(engine) as session:
        session.add(RuntimePermission(name="android.permission.RECORD_AUDIO"))
        session.add(DangerousDomain(domain="threat.example.org"))
        session.commit()

        queried_perm = session.exec(select(RuntimePermission)).first()
        assert queried_perm is not None
        assert queried_perm.name == "android.permission.RECORD_AUDIO"

        queried_domain = session.exec(select(DangerousDomain)).first()
        assert queried_domain is not None
        assert queried_domain.domain == "threat.example.org"
