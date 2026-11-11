"""Shared application state, authentication and authorization dependencies."""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass, field

from fastapi import Depends, Request
from redis.asyncio import Redis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from .audit.service import Actor, RequestContext
from .auth.api_keys import hash_api_key, looks_like_api_key, scopes_for_role, verify_api_key
from .auth.passwords import PasswordService
from .auth.rbac import assert_role
from .auth.tokens import TokenService
from .config import Settings
from .db.base import utcnow
from .db.models import ActorType, ApiKey, Membership, Role, User
from .db.tenancy import TenantScopedSession
from .errors import ForbiddenError, UnauthorizedError
from .queue import JobQueue
from .ratelimit import RateLimiter
from .storage.objects import ObjectStore
from .telemetry import current_trace_id


@dataclass
class AppState:
    settings: Settings
    engine: AsyncEngine
    session_factory: async_sessionmaker[AsyncSession]
    redis: Redis
    store: ObjectStore
    queue: JobQueue
    tokens: TokenService
    passwords: PasswordService
    limiter: RateLimiter
    draining: bool = field(default=False)


def get_state(request: Request) -> AppState:
    return request.app.state.cc  # type: ignore[no-any-return]


async def db_session(request: Request) -> AsyncIterator[AsyncSession]:
    async with get_state(request).session_factory() as session:
        yield session


@dataclass(frozen=True, slots=True)
class Principal:
    kind: ActorType
    id: uuid.UUID
    organization_id: uuid.UUID
    role: Role
    scopes: frozenset[str]
    user_id: uuid.UUID | None = None
    api_key_id: uuid.UUID | None = None
    token_jti: str | None = None
    token_expires_at: int | None = None

    @property
    def actor(self) -> Actor:
        return Actor(self.kind, self.id)

    def tenant(self, session: AsyncSession) -> TenantScopedSession:
        return TenantScopedSession(session, self.organization_id)


def client_ip(request: Request, settings: Settings) -> str | None:
    if settings.trust_x_forwarded_for:
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return forwarded.split(",")[0].strip()[:64]
    return request.client.host if request.client else None


def request_context(request: Request) -> RequestContext:
    return RequestContext(
        ip=client_ip(request, get_state(request).settings),
        user_agent=request.headers.get("user-agent"),
        request_id=getattr(request.state, "request_id", None),
        trace_id=current_trace_id(),
    )


async def _principal_from_api_key(session: AsyncSession, token: str) -> Principal:
    row = (await session.execute(select(ApiKey).where(ApiKey.key_hash == hash_api_key(token)))).scalar_one_or_none()
    if row is None or not verify_api_key(token, row.key_hash):
        raise UnauthorizedError("invalid API key")
    now = utcnow()
    if row.revoked_at is not None:
        raise UnauthorizedError("API key revoked")
    if row.expires_at is not None and row.expires_at <= now:
        raise UnauthorizedError("API key expired")
    row.last_used_at = now
    await session.commit()
    return Principal(
        kind=ActorType.API_KEY,
        id=row.id,
        organization_id=row.organization_id,
        role=row.role,
        scopes=frozenset(row.scopes),
        api_key_id=row.id,
    )


async def _principal_from_jwt(state: AppState, session: AsyncSession, token: str) -> Principal:
    claims = state.tokens.decode_access(token)
    if await state.redis.exists(f"jti:deny:{claims.jti}"):
        raise UnauthorizedError("token revoked")
    row = (
        await session.execute(
            select(Membership, User)
            .join(User, User.id == Membership.user_id)
            .where(Membership.user_id == claims.user_id, Membership.organization_id == claims.organization_id)
        )
    ).one_or_none()
    if row is None or not row[1].is_active:
        raise UnauthorizedError("membership no longer valid")
    membership: Membership = row[0]
    # The *current* role applies, so a demotion takes effect before the token expires.
    return Principal(
        kind=ActorType.USER,
        id=claims.user_id,
        organization_id=claims.organization_id,
        role=membership.role,
        scopes=scopes_for_role(membership.role),
        user_id=claims.user_id,
        token_jti=claims.jti,
        token_expires_at=claims.expires_at,
    )


async def get_principal(request: Request, session: AsyncSession = Depends(db_session)) -> Principal:
    state = get_state(request)
    header = request.headers.get("authorization", "")
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        raise UnauthorizedError("missing bearer token")
    token = token.strip()
    if looks_like_api_key(token):
        principal = await _principal_from_api_key(session, token)
    else:
        principal = await _principal_from_jwt(state, session, token)
    await state.limiter.check(f"{principal.kind.value}:{principal.id}")
    request.state.principal_id = str(principal.id)
    request.state.organization_id = str(principal.organization_id)
    return principal


def require(scope: str, minimum: Role = Role.VIEWER) -> Callable[..., Awaitable[Principal]]:
    """Dependency factory: the principal must hold ``scope`` and at least ``minimum`` role."""

    async def _dependency(principal: Principal = Depends(get_principal)) -> Principal:
        if scope not in principal.scopes:
            raise ForbiddenError(f"missing scope '{scope}'", required_scope=scope)
        assert_role(principal.role, minimum, scope)
        return principal

    return _dependency


def require_user(principal: Principal) -> uuid.UUID:
    if principal.user_id is None:
        raise ForbiddenError("this action requires a user session, not an API key")
    return principal.user_id
