"""
Enterprise Access Intelligence Platform — Principal Model.

Represents any security principal (user, group, service principal,
managed identity, application, or device) discovered from Entra ID.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict

from src.models.enums import PrincipalType


class Principal(BaseModel):
    """A security principal in Azure AD / Entra ID.

    Attributes:
        principal_id:       Auto-incremented DB primary key (None before insert).
        tenant_id:          Entra ID tenant GUID.
        object_id:          Entra object GUID uniquely identifying the principal.
        principal_type:     Discriminator for the kind of principal.
        display_name:       Human-readable name.
        user_principal_name: UPN for user accounts (e.g. ``user@contoso.com``).
        mail:               Primary SMTP address.
        account_enabled:    Whether the account is enabled in the directory.
        user_type:          ``Member`` or ``Guest`` for user accounts.
        created_date:       When the object was created in the directory.
        modified_date:      Last modification timestamp.
        is_deleted:         Soft-delete flag (True when the object is in the
                            Entra ID recycle bin).
        source_data:        Raw JSON payload from the discovery API.
    """

    model_config = ConfigDict(from_attributes=True)

    principal_id: int | None = None
    tenant_id: str
    object_id: str
    principal_type: PrincipalType
    display_name: str = ""
    user_principal_name: str | None = None
    mail: str | None = None
    account_enabled: bool | None = None
    user_type: str | None = None
    created_date: datetime | None = None
    modified_date: datetime | None = None
    is_deleted: bool = False
    source_data: dict | None = None
