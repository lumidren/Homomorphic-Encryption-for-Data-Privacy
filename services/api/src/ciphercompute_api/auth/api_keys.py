"""API keys: random, prefixed for secret scanners, stored as digests, scoped and role-capped."""

from __future__ import annotations

import hashlib
import hmac
import secrets
from typing import Final

from ..db.models import ROLE_RANK, Role
from ..errors import ForbiddenError, UnprocessableError

KEY_PREFIX: Final = "cc_"
PREFIX_DISPLAY_LEN: Final = 12

SCOPES: Final[frozenset[str]] = frozenset(
    {
        "projects:read",
        "projects:write",
        "datasets:read",
        "datasets:write",
        "keys:write",
        "jobs:read",
        "jobs:write",
        "audit:read",
        "api_keys:manage",
        "members:manage",
    }
)

_READ: Final = frozenset({"projects:read", "datasets:read", "jobs:read", "audit:read"})
_ANALYST: Final = _READ | {"projects:write", "datasets:write", "keys:write", "jobs:write"}
_ADMIN: Final = _ANALYST | {"api_keys:manage", "members:manage"}

#: The most a key created by a principal of this role may be granted.
SCOPE_CEILING: Final[dict[Role, frozenset[str]]] = {
    Role.VIEWER: _READ,
    Role.ANALYST: _ANALYST,
    Role.ADMIN: _ADMIN,
    Role.OWNER: _ADMIN,
}


def scopes_for_role(role: Role) -> frozenset[str]:
    return SCOPE_CEILING[role]


def generate_api_key() -> tuple[str, str, str]:
    """Return ``(secret, display_prefix, digest)``. The secret is shown to the caller once."""
    # [TM:S-2] 192 bits of entropy behind a registered prefix; only the digest is stored.
    secret = KEY_PREFIX + secrets.token_hex(24)
    return secret, secret[:PREFIX_DISPLAY_LEN], hash_api_key(secret)


def hash_api_key(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def verify_api_key(presented: str, stored_digest: str) -> bool:
    # [TM:I-4] Constant-time comparison; the row was fetched by digest but is re-checked here.
    return hmac.compare_digest(hash_api_key(presented), stored_digest)


def looks_like_api_key(token: str) -> bool:
    return token.startswith(KEY_PREFIX)


def check_scope_ceiling(creator_role: Role, requested: set[str]) -> frozenset[str]:
    """Validate requested scopes and refuse any beyond the creator's ceiling."""
    unknown = requested - SCOPES
    if unknown:
        raise UnprocessableError(f"unknown scopes: {sorted(unknown)}", unknown=sorted(unknown))
    ceiling = SCOPE_CEILING[creator_role]
    excess = requested - ceiling
    if excess:
        # [TM:E-2] A principal cannot mint a key more powerful than itself.
        raise ForbiddenError(
            f"role '{creator_role.value}' cannot grant scopes {sorted(excess)}",
            excess=sorted(excess),
            ceiling=sorted(ceiling),
        )
    return frozenset(requested)


def role_for_scopes(scopes: frozenset[str]) -> Role:
    """The lowest role whose ceiling covers ``scopes`` (used for RBAC checks on key principals)."""
    for role in sorted(ROLE_RANK, key=ROLE_RANK.__getitem__):
        if scopes <= SCOPE_CEILING[role]:
            return role
    return Role.ADMIN
