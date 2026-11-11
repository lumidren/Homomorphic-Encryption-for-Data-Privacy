"""API key management. The secret is returned once, at creation."""

from __future__ import annotations

import uuid
from datetime import timedelta

from fastapi import APIRouter, Depends, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from ..audit.service import AuditAction
from ..auth.api_keys import check_scope_ceiling, generate_api_key, role_for_scopes
from ..db.base import utcnow
from ..db.models import ApiKey, Role
from ..deps import Principal, db_session, require
from ..schemas import ApiKeyCreate, ApiKeyCreated, ApiKeyOut
from .common import audit

router = APIRouter(prefix="/v1/api-keys", tags=["api-keys"])


@router.post("", response_model=ApiKeyCreated, status_code=status.HTTP_201_CREATED)
async def create_key(
    body: ApiKeyCreate,
    request: Request,
    principal: Principal = Depends(require("api_keys:manage", Role.ADMIN)),
    session: AsyncSession = Depends(db_session),
) -> ApiKeyCreated:
    scopes = check_scope_ceiling(principal.role, set(body.scopes))
    secret, prefix, digest = generate_api_key()
    tenant = principal.tenant(session)
    row = tenant.add(
        ApiKey(
            name=body.name,
            prefix=prefix,
            key_hash=digest,
            role=role_for_scopes(scopes),
            scopes=sorted(scopes),
            created_by_user_id=principal.user_id,
            expires_at=utcnow() + timedelta(days=body.expires_in_days) if body.expires_in_days else None,
        )
    )
    await tenant.flush()
    await audit(
        request,
        tenant,
        principal,
        AuditAction.API_KEY_CREATED,
        "api_key",
        row.id,
        name=row.name,
        scopes=row.scopes,
        prefix=prefix,
    )
    await tenant.commit()
    return ApiKeyCreated(api_key=ApiKeyOut.model_validate(row), secret=secret)


@router.get("", response_model=list[ApiKeyOut])
async def list_keys(
    principal: Principal = Depends(require("api_keys:manage", Role.ADMIN)),
    session: AsyncSession = Depends(db_session),
) -> list[ApiKey]:
    tenant = principal.tenant(session)
    return list(await tenant.scalars(tenant.select(ApiKey).order_by(ApiKey.id.desc())))


@router.delete("/{key_id}", response_model=ApiKeyOut)
async def revoke_key(
    key_id: uuid.UUID,
    request: Request,
    principal: Principal = Depends(require("api_keys:manage", Role.ADMIN)),
    session: AsyncSession = Depends(db_session),
) -> ApiKey:
    tenant = principal.tenant(session)
    row = await tenant.get_or_404(ApiKey, key_id, "API key")
    if row.revoked_at is None:
        row.revoked_at = utcnow()
        await audit(request, tenant, principal, AuditAction.API_KEY_REVOKED, "api_key", row.id, prefix=row.prefix)
        await tenant.commit()
    return row
