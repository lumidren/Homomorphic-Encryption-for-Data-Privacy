"""Row-level tenant isolation, enforced by construction.

``TenantScopedSession`` is the only way request handlers touch tenant tables. It has no
method that returns an unscoped statement: every ``select`` starts with
``WHERE organization_id = :caller_org`` and every ``add`` pins the row to that organization.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from typing import Any, TypeVar

from sqlalchemy import Select, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..errors import NotFoundError
from .models import TenantScoped

T = TypeVar("T", bound=TenantScoped)


class TenantViolationError(RuntimeError):
    """A row from another organization reached a tenant-scoped session. Always a bug."""


class TenantScopedSession:
    __slots__ = ("_organization_id", "_session")

    def __init__(self, session: AsyncSession, organization_id: uuid.UUID) -> None:
        self._session = session
        self._organization_id = organization_id

    @property
    def organization_id(self) -> uuid.UUID:
        return self._organization_id

    @property
    def session(self) -> AsyncSession:
        """The underlying session, for transaction control and non-tenant tables only."""
        return self._session

    # [TM:I-6] Every statement built here carries the tenant predicate.
    def select(self, model: type[T]) -> Select[tuple[T]]:
        if not issubclass(model, TenantScoped):
            raise TenantViolationError(f"{model.__name__} is not a tenant-scoped model")
        return select(model).where(model.organization_id == self._organization_id)

    async def get(self, model: type[T], row_id: uuid.UUID) -> T | None:
        stmt = self.select(model).where(model.id == row_id)  # type: ignore[attr-defined]
        return (await self._session.execute(stmt)).scalars().one_or_none()

    async def get_or_404(self, model: type[T], row_id: uuid.UUID, what: str | None = None) -> T:
        row = await self.get(model, row_id)
        if row is None:
            raise NotFoundError(f"{what or model.__name__.lower()} not found", id=str(row_id))
        return row

    async def scalars(self, stmt: Select[tuple[T]]) -> Sequence[T]:
        return (await self._session.execute(stmt)).scalars().all()

    async def scalar_one_or_none(self, stmt: Select[tuple[T]]) -> T | None:
        return (await self._session.execute(stmt)).scalars().one_or_none()

    async def count(self, stmt: Select[tuple[T]]) -> int:
        return int((await self._session.execute(select(func.count()).select_from(stmt.subquery()))).scalar_one())

    def add(self, row: T) -> T:
        current = getattr(row, "organization_id", None)
        if current is None:
            row.organization_id = self._organization_id
        elif current != self._organization_id:
            raise TenantViolationError("attempted to add a row belonging to another organization")
        self._session.add(row)
        return row

    async def delete(self, row: T) -> None:
        if row.organization_id != self._organization_id:
            raise TenantViolationError("attempted to delete a row belonging to another organization")
        await self._session.delete(row)

    async def flush(self) -> None:
        await self._session.flush()

    async def commit(self) -> None:
        await self._session.commit()

    async def rollback(self) -> None:
        await self._session.rollback()

    async def refresh(self, row: Any) -> None:
        await self._session.refresh(row)
