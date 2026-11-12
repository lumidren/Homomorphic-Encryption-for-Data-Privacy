"""JWT access tokens and rotating refresh tokens with reuse detection.

* Access tokens: HS256, ``kid`` header for secret rotation, 15-minute lifetime, ``jti`` so a
  logout can deny-list the token for its remaining lifetime.
* Refresh tokens: opaque 384-bit secrets, stored only as SHA-256 digests, grouped in a
  *family* per login. Using a refresh token rotates it; presenting an already-rotated or
  revoked token is treated as theft and revokes the whole family.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import uuid
from dataclasses import dataclass
from datetime import timedelta

import jwt
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from ciphercompute_core.ids import uuid7

from ..config import Settings
from ..db.base import utcnow
from ..db.models import RefreshToken, Role
from ..errors import UnauthorizedError

ALGORITHM = "HS256"


@dataclass(frozen=True, slots=True)
class AccessClaims:
    user_id: uuid.UUID
    organization_id: uuid.UUID
    role: Role
    jti: str
    expires_at: int


class RefreshReuseError(UnauthorizedError):
    code = "refresh_token_reuse"


class TokenService:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._secrets: dict[str, str] = {settings.jwt_kid: settings.jwt_secret.get_secret_value()}
        if settings.jwt_previous_secret is not None:
            # [TM:K-2] Rotation grace: tokens signed with the previous secret stay valid until
            # they expire, new tokens use the current one.
            self._secrets[settings.jwt_previous_kid] = settings.jwt_previous_secret.get_secret_value()

    # ----- access tokens --------------------------------------------------------------------

    def issue_access(self, *, user_id: uuid.UUID, organization_id: uuid.UUID, role: Role) -> tuple[str, AccessClaims]:
        now = utcnow()
        exp = now + timedelta(seconds=self._settings.access_token_ttl_seconds)
        jti = uuid7().hex
        claims = {
            "iss": self._settings.jwt_issuer,
            "sub": str(user_id),
            "org": str(organization_id),
            "role": role.value,
            "iat": int(now.timestamp()),
            "exp": int(exp.timestamp()),
            "jti": jti,
        }
        token = jwt.encode(
            claims, self._secrets[self._settings.jwt_kid], algorithm=ALGORITHM, headers={"kid": self._settings.jwt_kid}
        )
        return token, AccessClaims(user_id, organization_id, role, jti, int(exp.timestamp()))

    def decode_access(self, token: str) -> AccessClaims:
        # [TM:S-3] Signature, issuer and expiry are all verified; unknown kids are rejected.
        try:
            kid = jwt.get_unverified_header(token).get("kid")
        except jwt.PyJWTError as exc:
            raise UnauthorizedError("invalid token") from exc
        secret = self._secrets.get(str(kid))
        if secret is None:
            raise UnauthorizedError("invalid token")
        try:
            payload = jwt.decode(
                token,
                secret,
                algorithms=[ALGORITHM],
                issuer=self._settings.jwt_issuer,
                options={"require": ["exp", "iat", "sub", "org", "role", "jti", "iss"]},
            )
        except jwt.ExpiredSignatureError as exc:
            raise UnauthorizedError("token expired") from exc
        except jwt.PyJWTError as exc:
            raise UnauthorizedError("invalid token") from exc
        try:
            return AccessClaims(
                user_id=uuid.UUID(payload["sub"]),
                organization_id=uuid.UUID(payload["org"]),
                role=Role(payload["role"]),
                jti=str(payload["jti"]),
                expires_at=int(payload["exp"]),
            )
        except (ValueError, KeyError) as exc:
            raise UnauthorizedError("invalid token") from exc

    # ----- refresh tokens -------------------------------------------------------------------

    @staticmethod
    def hash_refresh(secret: str) -> str:
        return hashlib.sha256(secret.encode("utf-8")).hexdigest()

    async def issue_refresh(
        self,
        session: AsyncSession,
        *,
        user_id: uuid.UUID,
        organization_id: uuid.UUID,
        family_id: uuid.UUID | None = None,
    ) -> tuple[str, RefreshToken]:
        secret = secrets.token_urlsafe(48)
        row = RefreshToken(
            user_id=user_id,
            organization_id=organization_id,
            family_id=family_id or uuid7(),
            token_hash=self.hash_refresh(secret),
            expires_at=utcnow() + timedelta(seconds=self._settings.refresh_token_ttl_seconds),
        )
        session.add(row)
        await session.flush()
        return secret, row

    async def rotate_refresh(self, session: AsyncSession, presented: str) -> tuple[str, RefreshToken]:
        """Exchange a refresh token for a new one; revoke the family on reuse."""
        digest = self.hash_refresh(presented)
        row = (
            await session.execute(select(RefreshToken).where(RefreshToken.token_hash == digest))
        ).scalar_one_or_none()
        # [TM:I-4] Constant-time confirmation even though the lookup was by digest.
        if row is None or not hmac.compare_digest(row.token_hash, digest):
            raise UnauthorizedError("invalid refresh token")
        now = utcnow()
        if row.revoked_at is not None or row.replaced_by_id is not None:
            # [TM:P-2] A token that was already rotated or revoked is being replayed: the
            # legitimate holder or a thief has it — nobody can be trusted, revoke the family.
            await self.revoke_family(session, row.family_id)
            raise RefreshReuseError("refresh token reuse detected; session revoked", family_id=str(row.family_id))
        if row.expires_at <= now:
            raise UnauthorizedError("refresh token expired")
        secret, fresh = await self.issue_refresh(
            session, user_id=row.user_id, organization_id=row.organization_id, family_id=row.family_id
        )
        row.replaced_by_id = fresh.id
        row.revoked_at = now
        await session.flush()
        return secret, fresh

    async def revoke_family(self, session: AsyncSession, family_id: uuid.UUID) -> int:
        result = await session.execute(
            update(RefreshToken)
            .where(RefreshToken.family_id == family_id, RefreshToken.revoked_at.is_(None))
            .values(revoked_at=utcnow())
        )
        await session.flush()
        return int(getattr(result, "rowcount", 0) or 0)

    async def family_of(self, session: AsyncSession, presented: str) -> RefreshToken | None:
        digest = self.hash_refresh(presented)
        return (
            await session.execute(select(RefreshToken).where(RefreshToken.token_hash == digest))
        ).scalar_one_or_none()
