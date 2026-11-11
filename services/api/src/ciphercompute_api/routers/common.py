"""Helpers shared by routers: auditing in the request transaction, and cursor pagination."""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import Request
from sqlalchemy import Select

from ..audit.service import AuditAction, record_event
from ..db.tenancy import TenantScopedSession
from ..deps import Principal, request_context
from ..errors import UnprocessableError

MAX_PAGE = 200


async def audit(
    request: Request,
    tenant: TenantScopedSession,
    principal: Principal,
    action: AuditAction,
    resource_type: str,
    resource_id: uuid.UUID | None,
    **details: Any,
) -> None:
    await record_event(
        tenant,
        actor=principal.actor,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        context=request_context(request),
        details=details,
    )


def paginate(stmt: Select[Any], id_column: Any, *, limit: int, before: str | None) -> Select[Any]:
    """Keyset pagination on UUIDv7 ids, newest first. ``before`` is the last id of the previous page."""
    if not 1 <= limit <= MAX_PAGE:
        raise UnprocessableError(f"limit must be between 1 and {MAX_PAGE}")
    if before:
        try:
            cursor = uuid.UUID(before)
        except ValueError:
            raise UnprocessableError("invalid cursor") from None
        stmt = stmt.where(id_column < cursor)
    return stmt.order_by(id_column.desc()).limit(limit + 1)


def page_of(rows: list[Any], limit: int) -> tuple[list[Any], str | None]:
    if len(rows) > limit:
        return rows[:limit], str(rows[limit - 1].id)
    return rows, None
