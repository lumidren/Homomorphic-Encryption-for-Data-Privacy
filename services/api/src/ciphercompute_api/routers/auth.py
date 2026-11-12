"""Registration, login, token refresh and logout."""

from __future__ import annotations

import re
import secrets
import time

from fastapi import APIRouter, Depends, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..audit.service import Actor, AuditAction, record_event
from ..auth.api_keys import scopes_for_role
from ..auth.tokens import RefreshReuseError
from ..db.models import ActorType, Membership, Organization, Role, User
from ..db.tenancy import TenantScopedSession
from ..deps import Principal, db_session, get_principal, get_state, request_context, require_user
from ..errors import ConflictError, ForbiddenError, UnauthorizedError
from ..logging import get_logger
from ..schemas import LoginRequest, LogoutRequest, MeResponse, RefreshRequest, RegisterRequest, TokenResponse

router = APIRouter(prefix="/v1/auth", tags=["auth"])
log = get_logger(__name__)

# A valid Argon2id hash of a random password; verifying against it when the email is unknown
# makes the unknown-user path cost the same as the wrong-password path.
_DUMMY_HASH: str | None = None


def _slugify(name: str) -> str:
    base = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:48] or "org"
    return f"{base}-{secrets.token_hex(3)}"


async def _issue(request: Request, session: AsyncSession, user: User, membership: Membership) -> TokenResponse:
    state = get_state(request)
    access, _ = state.tokens.issue_access(
        user_id=user.id, organization_id=membership.organization_id, role=membership.role
    )
    refresh, _ = await state.tokens.issue_refresh(session, user_id=user.id, organization_id=membership.organization_id)
    return TokenResponse(
        access_token=access,
        refresh_token=refresh,
        expires_in=state.settings.access_token_ttl_seconds,
        organization_id=membership.organization_id,
        role=membership.role,
    )


@router.post("/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
async def register(
    body: RegisterRequest, request: Request, session: AsyncSession = Depends(db_session)
) -> TokenResponse:
    """Create a user and a new organization owned by that user."""
    state = get_state(request)
    if not state.settings.allow_self_registration:
        raise ForbiddenError("self-registration is disabled")
    ip = request_context(request).ip or "unknown"
    await state.limiter.check(f"register:{ip}", limit=state.settings.login_rate_limit_per_minute, bucket="auth")
    email = body.email.lower()
    if (await session.execute(select(User.id).where(User.email == email))).scalar_one_or_none() is not None:
        raise ConflictError("an account with this email already exists")
    user = User(email=email, password_hash=state.passwords.hash(body.password))
    org = Organization(name=body.organization_name, slug=_slugify(body.organization_name))
    session.add_all([user, org])
    await session.flush()
    membership = Membership(organization_id=org.id, user_id=user.id, role=Role.OWNER)
    session.add(membership)
    await session.flush()
    await record_event(
        TenantScopedSession(session, org.id),
        actor=Actor(ActorType.USER, user.id),
        action=AuditAction.USER_REGISTERED,
        resource_type="user",
        resource_id=user.id,
        context=request_context(request),
        details={"organization_name": org.name},
    )
    tokens = await _issue(request, session, user, membership)
    await session.commit()
    return tokens


@router.post("/login", response_model=TokenResponse)
async def login(body: LoginRequest, request: Request, session: AsyncSession = Depends(db_session)) -> TokenResponse:
    global _DUMMY_HASH
    state = get_state(request)
    context = request_context(request)
    email = body.email.lower()
    # [TM:S-1] Per-IP and per-account limits on credential guessing.
    await state.limiter.check(
        f"login-ip:{context.ip}", limit=state.settings.login_rate_limit_per_minute * 5, bucket="auth"
    )
    await state.limiter.check(f"login-acct:{email}", limit=state.settings.login_rate_limit_per_minute, bucket="auth")
    user = (await session.execute(select(User).where(User.email == email))).scalar_one_or_none()
    if user is None:
        if _DUMMY_HASH is None:
            _DUMMY_HASH = state.passwords.hash(secrets.token_urlsafe(16))
        state.passwords.verify(body.password, _DUMMY_HASH)
        raise UnauthorizedError("invalid email or password")
    memberships = (
        (await session.execute(select(Membership).where(Membership.user_id == user.id).order_by(Membership.created_at)))
        .scalars()
        .all()
    )
    ok = user.is_active and state.passwords.verify(body.password, user.password_hash)
    if not ok or not memberships:
        if memberships:
            await record_event(
                TenantScopedSession(session, memberships[0].organization_id),
                actor=Actor(ActorType.USER, user.id),
                action=AuditAction.USER_LOGIN_FAILED,
                resource_type="user",
                resource_id=user.id,
                context=context,
            )
            await session.commit()
        raise UnauthorizedError("invalid email or password")
    if body.organization_id is not None:
        chosen = next((m for m in memberships if m.organization_id == body.organization_id), None)
        if chosen is None:
            raise UnauthorizedError("invalid email or password")
    else:
        chosen = memberships[0]
    if state.passwords.needs_rehash(user.password_hash):
        user.password_hash = state.passwords.hash(body.password)
    await record_event(
        TenantScopedSession(session, chosen.organization_id),
        actor=Actor(ActorType.USER, user.id),
        action=AuditAction.USER_LOGIN,
        resource_type="user",
        resource_id=user.id,
        context=context,
    )
    tokens = await _issue(request, session, user, chosen)
    await session.commit()
    return tokens


@router.post("/refresh", response_model=TokenResponse)
async def refresh(body: RefreshRequest, request: Request, session: AsyncSession = Depends(db_session)) -> TokenResponse:
    state = get_state(request)
    await state.limiter.check(
        f"refresh:{request_context(request).ip}", limit=state.settings.login_rate_limit_per_minute * 5, bucket="auth"
    )
    try:
        secret, row = await state.tokens.rotate_refresh(session, body.refresh_token)
    except RefreshReuseError as exc:
        family = await state.tokens.family_of(session, body.refresh_token)
        if family is not None:
            await record_event(
                TenantScopedSession(session, family.organization_id),
                actor=Actor(ActorType.USER, family.user_id),
                action=AuditAction.TOKEN_REUSE_DETECTED,
                resource_type="refresh_token_family",
                resource_id=family.family_id,
                context=request_context(request),
            )
        await session.commit()  # the family revocation must persist even though we refuse
        log.warning("refresh_token_reuse", family_id=exc.details.get("family_id"))
        raise
    membership = (
        await session.execute(
            select(Membership).where(
                Membership.user_id == row.user_id, Membership.organization_id == row.organization_id
            )
        )
    ).scalar_one_or_none()
    user = await session.get(User, row.user_id)
    if membership is None or user is None or not user.is_active:
        await state.tokens.revoke_family(session, row.family_id)
        await session.commit()
        raise UnauthorizedError("membership no longer valid")
    access, _ = state.tokens.issue_access(
        user_id=user.id, organization_id=membership.organization_id, role=membership.role
    )
    await session.commit()
    return TokenResponse(
        access_token=access,
        refresh_token=secret,
        expires_in=state.settings.access_token_ttl_seconds,
        organization_id=membership.organization_id,
        role=membership.role,
    )


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    body: LogoutRequest,
    request: Request,
    principal: Principal = Depends(get_principal),
    session: AsyncSession = Depends(db_session),
) -> None:
    state = get_state(request)
    require_user(principal)
    if principal.token_jti and principal.token_expires_at:
        ttl = max(1, principal.token_expires_at - int(time.time()))
        await state.redis.set(f"jti:deny:{principal.token_jti}", "1", ex=ttl)
    if body.refresh_token:
        row = await state.tokens.family_of(session, body.refresh_token)
        if row is not None and row.user_id == principal.user_id:
            await state.tokens.revoke_family(session, row.family_id)
    await record_event(
        principal.tenant(session),
        actor=principal.actor,
        action=AuditAction.USER_LOGOUT,
        resource_type="user",
        resource_id=principal.user_id,
        context=request_context(request),
    )
    await session.commit()


@router.get("/me", response_model=MeResponse)
async def me(principal: Principal = Depends(get_principal), session: AsyncSession = Depends(db_session)) -> MeResponse:
    email = None
    if principal.user_id is not None:
        user = await session.get(User, principal.user_id)
        email = user.email if user else None
    return MeResponse(
        principal_type=principal.kind.value,
        principal_id=principal.id,
        organization_id=principal.organization_id,
        role=principal.role,
        scopes=sorted(principal.scopes if principal.api_key_id else scopes_for_role(principal.role)),
        email=email,
    )
