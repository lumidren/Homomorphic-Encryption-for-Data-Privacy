"""Role-based access control: owner > admin > analyst > viewer."""

from __future__ import annotations

from ..db.models import ROLE_RANK, Role
from ..errors import ForbiddenError


def role_at_least(role: Role, minimum: Role) -> bool:
    return ROLE_RANK[role] >= ROLE_RANK[minimum]


def assert_role(role: Role, minimum: Role, action: str) -> None:
    # [TM:E-1] Enforced on every mutating route through the ``require_role`` dependency.
    if not role_at_least(role, minimum):
        raise ForbiddenError(
            f"{action} requires role '{minimum.value}' or higher", role=role.value, required=minimum.value
        )


def assert_can_assign_role(actor_role: Role, target_role: Role) -> None:
    """Only owners may create owners or change roles at all; admins may invite below admin."""
    if actor_role == Role.OWNER:
        return
    if actor_role == Role.ADMIN and ROLE_RANK[target_role] < ROLE_RANK[Role.ADMIN]:
        return
    raise ForbiddenError("insufficient role to assign that role", actor=actor_role.value, target=target_role.value)
