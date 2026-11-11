"""Recording audit events inside the caller's transaction."""

from __future__ import annotations

import enum
import uuid
from dataclasses import dataclass
from typing import Any

from sqlalchemy import select

from ciphercompute_core.ids import uuid7

from ..db.base import utcnow
from ..db.models import ActorType, AuditEvent, Organization
from ..db.tenancy import TenantScopedSession
from .chain import GENESIS, compute_hash, event_payload


class AuditAction(enum.StrEnum):
    USER_REGISTERED = "user.registered"
    USER_LOGIN = "user.login"
    USER_LOGIN_FAILED = "user.login_failed"
    TOKEN_REFRESHED = "token.refreshed"  # noqa: S105 - audit action name
    TOKEN_REUSE_DETECTED = "token.reuse_detected"  # noqa: S105 - audit action name
    USER_LOGOUT = "user.logout"
    MEMBER_ADDED = "member.added"
    MEMBER_ROLE_CHANGED = "member.role_changed"
    MEMBER_REMOVED = "member.removed"
    PROJECT_CREATED = "project.created"
    PROJECT_UPDATED = "project.updated"
    PROJECT_DELETED = "project.deleted"
    KEY_BUNDLE_CREATED = "key_bundle.created"
    KEY_BUNDLE_CONFIRMED = "key_bundle.confirmed"
    KEY_BUNDLE_REJECTED = "key_bundle.rejected"
    KEY_BUNDLE_REVOKED = "key_bundle.revoked"
    DATASET_CREATED = "dataset.created"
    DATASET_DELETED = "dataset.deleted"
    CIPHERTEXT_CREATED = "ciphertext.created"
    CIPHERTEXT_CONFIRMED = "ciphertext.confirmed"
    CIPHERTEXT_ACCESSED = "ciphertext.accessed"
    CIPHERTEXT_DELETED = "ciphertext.deleted"
    JOB_SUBMITTED = "job.submitted"
    JOB_STARTED = "job.started"
    JOB_COMPLETED = "job.completed"
    JOB_FAILED = "job.failed"
    JOB_CANCELLED = "job.cancelled"
    RESULT_ACCESSED = "result.accessed"
    API_KEY_CREATED = "api_key.created"
    API_KEY_REVOKED = "api_key.revoked"
    AUDIT_VERIFIED = "audit.verified"


@dataclass(frozen=True, slots=True)
class RequestContext:
    ip: str | None = None
    user_agent: str | None = None
    request_id: str | None = None
    trace_id: str | None = None


@dataclass(frozen=True, slots=True)
class Actor:
    type: ActorType
    id: uuid.UUID | None

    @classmethod
    def system(cls) -> Actor:
        return cls(ActorType.SYSTEM, None)


async def record_event(
    tenant: TenantScopedSession,
    *,
    actor: Actor,
    action: AuditAction,
    resource_type: str,
    resource_id: uuid.UUID | None,
    context: RequestContext,
    details: dict[str, Any] | None = None,
) -> AuditEvent:
    """Append one event to the organization's chain, in the caller's open transaction.

    The organization row is locked for the duration of the transaction so two concurrent
    writers cannot both read the same chain head (PostgreSQL); SQLite serialises writers anyway.
    """
    session = tenant.session
    org_id = tenant.organization_id
    await session.execute(select(Organization.id).where(Organization.id == org_id).with_for_update())
    last_hash = (
        await session.execute(
            select(AuditEvent.hash).where(AuditEvent.organization_id == org_id).order_by(AuditEvent.seq.desc()).limit(1)
        )
    ).scalar_one_or_none()
    # [TM:R-1] Same transaction as the action it describes: either both persist or neither.
    event = AuditEvent(
        id=uuid7(),
        organization_id=org_id,
        actor_type=actor.type,
        actor_id=actor.id,
        action=action.value,
        resource_type=resource_type,
        resource_id=resource_id,
        ip=context.ip,
        user_agent=(context.user_agent or "")[:256] or None,
        request_id=context.request_id,
        trace_id=context.trace_id,
        details=details or {},
        prev_hash=last_hash or GENESIS,
        hash="",
        # truncated to microseconds explicitly so the hashed value equals the stored value
        occurred_at=utcnow(),
    )
    event.hash = compute_hash(event.prev_hash, event_payload(event))
    session.add(event)
    await session.flush()
    return event
