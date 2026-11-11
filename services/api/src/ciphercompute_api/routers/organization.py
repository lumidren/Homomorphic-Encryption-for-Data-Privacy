"""The caller's organization and its members."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Request, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..audit.service import AuditAction
from ..auth.rbac import assert_can_assign_role
from ..db.models import Membership, Organization, Role, User
from ..deps import Principal, db_session, require
from ..errors import ConflictError, ForbiddenError, NotFoundError
from ..schemas import AddMemberRequest, ChangeRoleRequest, MemberOut, OrganizationOut
from .common import audit

router = APIRouter(prefix="/v1/organization", tags=["organization"])


async def _membership(session: AsyncSession, org_id: uuid.UUID, user_id: uuid.UUID) -> Membership:
    row = (
        await session.execute(
            select(Membership).where(Membership.organization_id == org_id, Membership.user_id == user_id)
        )
    ).scalar_one_or_none()
    if row is None:
        raise NotFoundError("member not found", user_id=str(user_id))
    return row


async def _owner_count(session: AsyncSession, org_id: uuid.UUID) -> int:
    return int(
        (
            await session.execute(
                select(func.count())
                .select_from(Membership)
                .where(Membership.organization_id == org_id, Membership.role == Role.OWNER)
            )
        ).scalar_one()
    )


@router.get("", response_model=OrganizationOut)
async def get_organization(
    principal: Principal = Depends(require("projects:read")), session: AsyncSession = Depends(db_session)
) -> Organization:
    org = await session.get(Organization, principal.organization_id)
    if org is None:
        raise NotFoundError("organization not found")
    return org


@router.get("/members", response_model=list[MemberOut])
async def list_members(
    principal: Principal = Depends(require("projects:read")), session: AsyncSession = Depends(db_session)
) -> list[MemberOut]:
    rows = (
        await session.execute(
            select(Membership, User)
            .join(User, User.id == Membership.user_id)
            .where(Membership.organization_id == principal.organization_id)
            .order_by(Membership.created_at)
        )
    ).all()
    return [MemberOut(user_id=u.id, email=u.email, role=m.role, created_at=m.created_at) for m, u in rows]


@router.post("/members", response_model=MemberOut, status_code=status.HTTP_201_CREATED)
async def add_member(
    body: AddMemberRequest,
    request: Request,
    principal: Principal = Depends(require("members:manage", Role.ADMIN)),
    session: AsyncSession = Depends(db_session),
) -> MemberOut:
    assert_can_assign_role(principal.role, body.role)
    user = (await session.execute(select(User).where(User.email == body.email.lower()))).scalar_one_or_none()
    if user is None:
        raise NotFoundError("no user with that email; they must register first")
    existing = (
        await session.execute(
            select(Membership).where(
                Membership.organization_id == principal.organization_id, Membership.user_id == user.id
            )
        )
    ).scalar_one_or_none()
    if existing is not None:
        raise ConflictError("user is already a member")
    membership = Membership(organization_id=principal.organization_id, user_id=user.id, role=body.role)
    session.add(membership)
    await session.flush()
    await audit(
        request, principal.tenant(session), principal, AuditAction.MEMBER_ADDED, "user", user.id, role=body.role.value
    )
    await session.commit()
    return MemberOut(user_id=user.id, email=user.email, role=membership.role, created_at=membership.created_at)


@router.patch("/members/{user_id}", response_model=MemberOut)
async def change_role(
    user_id: uuid.UUID,
    body: ChangeRoleRequest,
    request: Request,
    principal: Principal = Depends(require("members:manage", Role.OWNER)),
    session: AsyncSession = Depends(db_session),
) -> MemberOut:
    # [TM:E-1] Only owners change roles; the last owner cannot be demoted.
    membership = await _membership(session, principal.organization_id, user_id)
    if (
        membership.role == Role.OWNER
        and body.role != Role.OWNER
        and await _owner_count(session, principal.organization_id) <= 1
    ):
        raise ConflictError("an organization must keep at least one owner")
    previous = membership.role
    membership.role = body.role
    await audit(
        request,
        principal.tenant(session),
        principal,
        AuditAction.MEMBER_ROLE_CHANGED,
        "user",
        user_id,
        previous=previous.value,
        role=body.role.value,
    )
    await session.commit()
    user = await session.get(User, user_id)
    if user is None:
        raise NotFoundError("member not found", user_id=str(user_id))
    return MemberOut(user_id=user.id, email=user.email, role=membership.role, created_at=membership.created_at)


@router.delete("/members/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_member(
    user_id: uuid.UUID,
    request: Request,
    principal: Principal = Depends(require("members:manage", Role.ADMIN)),
    session: AsyncSession = Depends(db_session),
) -> None:
    membership = await _membership(session, principal.organization_id, user_id)
    if membership.role in (Role.OWNER, Role.ADMIN) and principal.role != Role.OWNER:
        raise ForbiddenError("only owners may remove owners or admins")
    if membership.role == Role.OWNER and await _owner_count(session, principal.organization_id) <= 1:
        raise ConflictError("an organization must keep at least one owner")
    await session.delete(membership)
    await audit(request, principal.tenant(session), principal, AuditAction.MEMBER_REMOVED, "user", user_id)
    await session.commit()
