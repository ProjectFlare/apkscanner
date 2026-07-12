"""Database models for static APK scanner rules.

Defines the SQLModel table mappings for runtime permissions, trackers, cloud keywords,
dangerous domains, trusted package prefixes, and maven package mappings.
"""

from sqlmodel import Field, SQLModel


class RuntimePermission(SQLModel, table=True):
    """Mappable model for Runtime Permissions database table."""

    __tablename__ = "runtime_permissions"

    name: str = Field(primary_key=True, description="The unique name of the dangerous permission.")


class CloudKeyword(SQLModel, table=True):
    """Mappable model for Cloud Keywords database table."""

    __tablename__ = "cloud_keywords"

    keyword: str = Field(primary_key=True, description="The keyword identifying cloud-hosting providers.")


class TrackerKeyword(SQLModel, table=True):
    """Mappable model for Tracker Keywords database table."""

    __tablename__ = "tracker_keywords"

    keyword: str = Field(primary_key=True, description="The keyword identifying ad/tracker domains.")


class TrackerSignature(SQLModel, table=True):
    """Mappable model for Exodus Tracker detailed signatures table."""

    __tablename__ = "tracker_signatures"

    id: str = Field(primary_key=True, description="Exodus Tracker unique identifier.")
    name: str = Field(description="Display name of the tracker.")
    code_signature: str = Field(description="Package path signatures separated by pipe characters.")
    network_signature: str = Field(description="Network regex signature patterns.")


class SchemaKeyword(SQLModel, table=True):
    """Mappable model for Schema Keywords database table."""

    __tablename__ = "schema_keywords"

    keyword: str = Field(primary_key=True, description="Well-known schema or metadata package namespaces.")


class DangerousDomain(SQLModel, table=True):
    """Mappable model for Dangerous Domains database table."""

    __tablename__ = "dangerous_domains"

    domain: str = Field(primary_key=True, description="Malware or threat-intelligence domains.")


class TrustedPackagePrefix(SQLModel, table=True):
    """Mappable model for Trusted Package Prefixes database table."""

    __tablename__ = "trusted_package_prefixes"

    prefix: str = Field(primary_key=True, description="Namespace prefixes identifying trusted applications.")


class MavenMapping(SQLModel, table=True):
    """Mappable model for Maven Mappings database table."""

    __tablename__ = "maven_mappings"

    lib_name: str = Field(primary_key=True, description="Internal library package identifier.")
    coordinate: str = Field(description="Fully qualified Maven coordinates.")


class SecretsPattern(SQLModel, table=True):
    """Mappable model for Secrets Regex Patterns database table."""

    __tablename__ = "secrets_patterns"

    key: str = Field(primary_key=True, description="Identifier of the secret check rule.")
    pattern: str = Field(description="Regex pattern representing secret patterns.")
