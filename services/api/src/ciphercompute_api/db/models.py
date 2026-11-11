"""ORM models.

Tenancy: ``organizations → projects → datasets → ciphertexts`` and ``jobs``. Every table that
holds tenant data mixes in :class:`TenantScoped` and is only ever queried through
:class:`~ciphercompute_api.db.tenancy.TenantScopedSession`. Identifiers are UUIDv7.

The audit table is append-only at the database level: triggers reject ``UPDATE`` and
``DELETE`` on PostgreSQL (migration ``0001``) and on SQLite (attached here so test databases
built with ``create_all`` enforce the same rule).
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    DDL,
    BigInteger,
    Boolean,
    Enum,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    event,
)
from sqlalchemy.orm import Mapped, declared_attr, mapped_column, relationship

from ciphercompute_core.ids import uuid7

from .base import Base, utcnow


def _enum(enum_cls: type[enum.StrEnum], length: int = 16) -> Enum:
    return Enum(enum_cls, native_enum=False, length=length, values_callable=lambda e: [m.value for m in e])


class Role(enum.StrEnum):
    OWNER = "owner"
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


ROLE_RANK: dict[Role, int] = {Role.VIEWER: 0, Role.ANALYST: 1, Role.ADMIN: 2, Role.OWNER: 3}


class KeyBundleStatus(enum.StrEnum):
    PENDING = "pending"
    ACTIVE = "active"
    REVOKED = "revoked"


class CiphertextStatus(enum.StrEnum):
    PENDING = "pending"
    READY = "ready"


class JobStatus(enum.StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ActorType(enum.StrEnum):
    USER = "user"
    API_KEY = "api_key"
    SYSTEM = "system"


# ----- mixins ---------------------------------------------------------------------------------


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(default=utcnow, nullable=False)


class TenantScoped:
    """Rows that belong to exactly one organization."""

    @declared_attr
    @classmethod
    def organization_id(cls) -> Mapped[uuid.UUID]:
        return mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)


# ----- identity ---------------------------------------------------------------------------------


class Organization(TimestampMixin, Base):
    __tablename__ = "organizations"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid7)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    slug: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)

    memberships: Mapped[list[Membership]] = relationship(back_populates="organization", cascade="all, delete-orphan")


class User(TimestampMixin, Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid7)
    email: Mapped[str] = mapped_column(String(254), nullable=False, unique=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    memberships: Mapped[list[Membership]] = relationship(back_populates="user", cascade="all, delete-orphan")


class Membership(TimestampMixin, Base):
    __tablename__ = "memberships"
    __table_args__ = (UniqueConstraint("organization_id", "user_id", name="uq_memberships_org_user"),)

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid7)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    role: Mapped[Role] = mapped_column(_enum(Role), nullable=False)

    organization: Mapped[Organization] = relationship(back_populates="memberships")
    user: Mapped[User] = relationship(back_populates="memberships")


class RefreshToken(TimestampMixin, Base):
    """Opaque refresh tokens, stored hashed, rotated on use, grouped in families for reuse detection."""

    __tablename__ = "refresh_tokens"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid7)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    family_id: Mapped[uuid.UUID] = mapped_column(nullable=False, index=True)
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    expires_at: Mapped[datetime] = mapped_column(nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(nullable=True)
    replaced_by_id: Mapped[uuid.UUID | None] = mapped_column(nullable=True)


class ApiKey(TenantScoped, TimestampMixin, Base):
    __tablename__ = "api_keys"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid7)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    prefix: Mapped[str] = mapped_column(String(16), nullable=False)
    key_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    role: Mapped[Role] = mapped_column(_enum(Role), nullable=False)
    scopes: Mapped[list[Any]] = mapped_column(nullable=False, default=list)
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    expires_at: Mapped[datetime | None] = mapped_column(nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(nullable=True)
    last_used_at: Mapped[datetime | None] = mapped_column(nullable=True)


# ----- tenant data -------------------------------------------------------------------------------


class Project(TenantScoped, TimestampMixin, Base):
    __tablename__ = "projects"
    __table_args__ = (UniqueConstraint("organization_id", "name", name="uq_projects_org_name"),)

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid7)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )


class KeyBundle(TenantScoped, TimestampMixin, Base):
    """A client's public/relinearization/Galois key set. Never holds secret material."""

    __tablename__ = "key_bundles"
    __table_args__ = (Index("ix_key_bundles_org_ring", "organization_id", "ring_id"),)

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid7)
    project_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
    )
    ring_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    fingerprint: Mapped[str | None] = mapped_column(String(80), nullable=True)
    params: Mapped[dict[str, Any] | None] = mapped_column(nullable=True)
    object_key: Mapped[str] = mapped_column(String(512), nullable=False)
    declared_size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    size_bytes: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    status: Mapped[KeyBundleStatus] = mapped_column(
        _enum(KeyBundleStatus), default=KeyBundleStatus.PENDING, nullable=False
    )
    confirmed_at: Mapped[datetime | None] = mapped_column(nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(nullable=True)
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_by_api_key_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("api_keys.id", ondelete="SET NULL"), nullable=True
    )


class Dataset(TenantScoped, TimestampMixin, Base):
    __tablename__ = "datasets"
    __table_args__ = (UniqueConstraint("project_id", "name", name="uq_datasets_project_name"),)

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid7)
    project_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
    )
    key_bundle_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("key_bundles.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)


class Ciphertext(TenantScoped, TimestampMixin, Base):
    __tablename__ = "ciphertexts"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid7)
    dataset_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("datasets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    label: Mapped[str] = mapped_column(String(120), nullable=False)
    object_key: Mapped[str] = mapped_column(String(512), nullable=False)
    declared_size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    size_bytes: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    fingerprint: Mapped[str | None] = mapped_column(String(80), nullable=True)
    length: Mapped[int | None] = mapped_column(Integer, nullable=True)
    levels_consumed: Mapped[int | None] = mapped_column(Integer, nullable=True)
    status: Mapped[CiphertextStatus] = mapped_column(
        _enum(CiphertextStatus), default=CiphertextStatus.PENDING, nullable=False
    )
    confirmed_at: Mapped[datetime | None] = mapped_column(nullable=True)


class Job(TenantScoped, TimestampMixin, Base):
    __tablename__ = "jobs"
    __table_args__ = (
        UniqueConstraint("organization_id", "idempotency_key", name="uq_jobs_org_idempotency_key"),
        Index("ix_jobs_org_status_created", "organization_id", "status", "created_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid7)
    project_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
    )
    key_bundle_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("key_bundles.id", ondelete="RESTRICT"), nullable=False)
    operation: Mapped[str] = mapped_column(String(64), nullable=False)
    args: Mapped[dict[str, Any]] = mapped_column(nullable=False, default=dict)
    input_ids: Mapped[list[Any]] = mapped_column(nullable=False, default=list)
    input_fingerprints: Mapped[list[Any]] = mapped_column(nullable=False, default=list)
    manifest_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    idempotency_key: Mapped[str | None] = mapped_column(String(128), nullable=True)
    request_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    status: Mapped[JobStatus] = mapped_column(_enum(JobStatus), default=JobStatus.QUEUED, nullable=False)
    attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    plan: Mapped[dict[str, Any]] = mapped_column(nullable=False, default=dict)
    depth_report: Mapped[dict[str, Any] | None] = mapped_column(nullable=True)
    result_object_key: Mapped[str | None] = mapped_column(String(512), nullable=True)
    result_fingerprint: Mapped[str | None] = mapped_column(String(80), nullable=True)
    result_length: Mapped[int | None] = mapped_column(Integer, nullable=True)
    result_size_bytes: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    error: Mapped[dict[str, Any] | None] = mapped_column(nullable=True)
    submitted_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    submitted_by_api_key_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("api_keys.id", ondelete="SET NULL"), nullable=True
    )
    started_at: Mapped[datetime | None] = mapped_column(nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(nullable=True)
    worker_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    compute_seconds: Mapped[float | None] = mapped_column(Float, nullable=True)


# ----- audit -------------------------------------------------------------------------------------


class AuditEvent(Base):
    """Append-only, hash-chained per organization. See audit/chain.py."""

    __tablename__ = "audit_events"

    seq: Mapped[int] = mapped_column(
        Integer().with_variant(BigInteger(), "postgresql"), primary_key=True, autoincrement=True
    )
    id: Mapped[uuid.UUID] = mapped_column(nullable=False, unique=True, default=uuid7)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    occurred_at: Mapped[datetime] = mapped_column(default=utcnow, nullable=False)
    actor_type: Mapped[ActorType] = mapped_column(_enum(ActorType), nullable=False)
    actor_id: Mapped[uuid.UUID | None] = mapped_column(nullable=True)
    action: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    resource_type: Mapped[str] = mapped_column(String(32), nullable=False)
    resource_id: Mapped[uuid.UUID | None] = mapped_column(nullable=True)
    ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(256), nullable=True)
    request_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    trace_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    details: Mapped[dict[str, Any]] = mapped_column(nullable=False, default=dict)
    prev_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)


# [TM:T-1] Database-level immutability of the audit log. The PostgreSQL version lives in the
# Alembic migration (functions cannot be expressed portably); SQLite gets the same rule here so
# every test database enforces it too.
_SQLITE_AUDIT_TRIGGERS = (
    DDL(  # type: ignore[no-untyped-call]
        "CREATE TRIGGER IF NOT EXISTS audit_events_no_update BEFORE UPDATE ON audit_events "
        "BEGIN SELECT RAISE(ABORT, 'audit_events is append-only'); END"
    ),
    DDL(  # type: ignore[no-untyped-call]
        "CREATE TRIGGER IF NOT EXISTS audit_events_no_delete BEFORE DELETE ON audit_events "
        "BEGIN SELECT RAISE(ABORT, 'audit_events is append-only'); END"
    ),
)
_POSTGRES_AUDIT_TRIGGERS = (
    DDL(  # type: ignore[no-untyped-call]
        "CREATE OR REPLACE FUNCTION audit_events_immutable() RETURNS trigger LANGUAGE plpgsql AS "
        "'BEGIN RAISE EXCEPTION ''audit_events is append-only''; END'"
    ),
    DDL(  # type: ignore[no-untyped-call]
        "CREATE OR REPLACE TRIGGER audit_events_no_update BEFORE UPDATE ON audit_events "
        "FOR EACH ROW EXECUTE FUNCTION audit_events_immutable()"
    ),
    DDL(  # type: ignore[no-untyped-call]
        "CREATE OR REPLACE TRIGGER audit_events_no_delete BEFORE DELETE ON audit_events "
        "FOR EACH ROW EXECUTE FUNCTION audit_events_immutable()"
    ),
)
for _ddl in _SQLITE_AUDIT_TRIGGERS:
    event.listen(AuditEvent.__table__, "after_create", _ddl.execute_if(dialect="sqlite"))
for _ddl in _POSTGRES_AUDIT_TRIGGERS:
    event.listen(AuditEvent.__table__, "after_create", _ddl.execute_if(dialect="postgresql"))
