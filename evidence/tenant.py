"""
Tenant domain model.

Represents the cloud tenant (project) associated with an evidence record. / Represents the logical tenant boundary associated with evidence.
Incuse Project -> TenantContext
This model is immutable once created to support forensic integrity.
        Class: TenantContext
        Attributes: tenant_id
                    tenant_name
                    tenant_hash
                    platform
                    platform_project_id
"""

from typing import Optional
from pydantic import BaseModel, ConfigDict, Field
from common.utils import current_timestamp
from evidence.enums import CloudPlatform


class TenantContext(BaseModel):
    """
    Immutable representation of a cloud tenant/project.

    TenantContext represents the logical security and ownership
    boundary associated with an EvidenceRecord.

    The model deliberately separates the prototype's internal
    tenant identity from the identifier used by the underlying
    cloud platform.
    """

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
    )

    # ---------------------------------------------------------
    # Identification
    # ---------------------------------------------------------

    tenant_id: str = Field(
        ...,
        description=(
            "Canonical internal identifier for the logical tenant."
        ),
    )

    tenant_name: str = Field(
        ...,
        description=(
            "Human-readable name of the logical tenant."
        ),
    )

    tenant_hash: str = Field(
        ...,
        description=(
            "Privacy-preserving identifier derived from the "
            "canonical tenant identity."
        ),
    )

    # ---------------------------------------------------------
    # Platform Context
    # ---------------------------------------------------------
    ##This is to be changed, platform should be defined using enums.py 
    platform: CloudPlatform = Field(
    ...,
    description=(
        "Cloud platform associated with the tenant."
    ),
)
    ##This is to be changed, platform should be defined using enums.py 

    platform_project_id: str = Field(
        ...,
        description=(
            "Project or tenant identifier assigned by the "
            "underlying cloud platform."
        ),
    )

    # ---------------------------------------------------------
    # Tenant Metadata
    # ---------------------------------------------------------

    description: Optional[str] = Field(
        default=None,
        description=(
            "Optional descriptive information about the tenant."
        ),
    )

    enabled: bool = Field(
        default=True,
        description=(
            "Whether the tenant is currently considered active "
            "within the prototype."
        ),
    )

    # ---------------------------------------------------------
    # Model Metadata
    # ---------------------------------------------------------

    created_at: str = Field(
        default_factory=lambda: current_timestamp().isoformat(),
        description=(
            "Timestamp at which this TenantContext instance "
            "was created."
        ),
    )

    # ---------------------------------------------------------
    # Helper Properties
    # ---------------------------------------------------------

    @property
    def pseudonym(self) -> str:
        """
        Return a short privacy-preserving identifier suitable
        for dashboards and non-sensitive displays.

        Example:
            T-91AC34EF
        """
        return f"T-{self.tenant_hash[:8].upper()}"

    # ---------------------------------------------------------
    # Representation
    # ---------------------------------------------------------

    def __str__(self) -> str:
        return (
            f"TenantContext("
            f"tenant_id='{self.tenant_id}', "
            f"platform='{self.platform}', "
            f"project='{self.platform_project_id}')"
        )
