"""Audit log viewer and chain verification."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..audit.chain import verify_chain
from ..db.models import AuditEvent
from ..deps import Principal, db_session, require
from ..errors import UnprocessableError
from ..schemas import AuditEventOut, Page
from ..telemetry import AUDIT_CHAIN_VALID

router = APIRouter(prefix="/v1/audit", tags=["audit"])


@router.get("", response_model=Page[AuditEventOut])
async def list_events(
    action: str | None = Query(None, max_length=64),
    resource_id: str | None = Query(None),
    limit: int = Query(50, ge=1, le=200),
    before_seq: int | None = Query(None, ge=1),
    principal: Principal = Depends(require("audit:read")),
    session: AsyncSession = Depends(db_session),
) -> Page[AuditEventOut]:
    stmt = select(AuditEvent).where(AuditEvent.organization_id == principal.organization_id)
    if action:
        stmt = stmt.where(AuditEvent.action == action)
    if resource_id:
        try:
            stmt = stmt.where(AuditEvent.resource_id == uuid.UUID(resource_id))
        except ValueError:
            raise UnprocessableError("resource_id must be a UUID") from None
    if before_seq is not None:
        stmt = stmt.where(AuditEvent.seq < before_seq)
    rows = list((await session.execute(stmt.order_by(AuditEvent.seq.desc()).limit(limit + 1))).scalars())
    cursor = str(rows[limit - 1].seq) if len(rows) > limit else None
    return Page[AuditEventOut](items=[AuditEventOut.model_validate(e) for e in rows[:limit]], next_cursor=cursor)


@router.get("/verify")
async def verify(
    principal: Principal = Depends(require("audit:read")),
    session: AsyncSession = Depends(db_session),
) -> dict[str, object]:
    """Re-walk this organization's hash chain from genesis and report the first broken link."""
    stmt = select(AuditEvent).where(AuditEvent.organization_id == principal.organization_id).order_by(AuditEvent.seq)
    result = verify_chain((await session.execute(stmt)).scalars())
    AUDIT_CHAIN_VALID.labels(organization=str(principal.organization_id)).set(1 if result.valid else 0)
    return result.to_dict()
