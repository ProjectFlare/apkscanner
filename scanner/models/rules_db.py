"""Database models for dynamic APK Scanner threat intelligence feeds.

Defines the SQLModel table mappings for runtime permissions, trackers, and dangerous domains.
"""

from typing import ClassVar

from sqlmodel import Field, SQLModel


class RuntimePermission(SQLModel, table=True):
    """Mappable model for Runtime Permissions database table.

    Attributes:
        name: The unique name of the dangerous permission.
    """

    __tablename__: ClassVar[str] = "runtime_permissions"

    name: str = Field(primary_key=True, description="The unique name of the dangerous permission.")


class TrackerKeyword(SQLModel, table=True):
    """Mappable model for Tracker Keywords database table.

    Attributes:
        keyword: The keyword identifying ad/tracker domains.
    """

    __tablename__: ClassVar[str] = "tracker_keywords"

    keyword: str = Field(primary_key=True, description="The keyword identifying ad/tracker domains.")


class TrackerSignature(SQLModel, table=True):
    """Mappable model for Exodus Tracker detailed signatures table.

    Attributes:
        id: Exodus Tracker unique identifier.
        name: Display name of the tracker.
        network_signature: Network regex signature patterns.
    """

    __tablename__: ClassVar[str] = "tracker_signatures"

    id: str = Field(primary_key=True, description="Exodus Tracker unique identifier.")
    name: str = Field(description="Display name of the tracker.")
    network_signature: str = Field(description="Network regex signature patterns.")


class DangerousDomain(SQLModel, table=True):
    """Mappable model for Dangerous Domains database table.

    Attributes:
        domain: Malware or threat-intelligence domains.
    """

    __tablename__: ClassVar[str] = "dangerous_domains"

    domain: str = Field(primary_key=True, description="Malware or threat-intelligence domains.")
