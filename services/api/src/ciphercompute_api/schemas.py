"""Request and response models (the OpenAPI 3.1 contract)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Generic, Literal, TypeVar

from pydantic import BaseModel, ConfigDict, EmailStr, Field

from .db.models import CiphertextStatus, JobStatus, KeyBundleStatus, Role


class Model(BaseModel):
    model_config = ConfigDict(from_attributes=True)


# ----- auth -------------------------------------------------------------------------------------


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=12, max_length=256)
    organization_name: str = Field(min_length=2, max_length=120)

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "email": "ada@hospital.example",
                    "password": "correct horse battery staple",
                    "organization_name": "St. Example Hospital",
                }
            ]
        }
    )


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=256)
    organization_id: uuid.UUID | None = None

    model_config = ConfigDict(
        json_schema_extra={"examples": [{"email": "ada@hospital.example", "password": "correct horse battery staple"}]}
    )


class RefreshRequest(BaseModel):
    refresh_token: str = Field(min_length=16, max_length=256)


class LogoutRequest(BaseModel):
    refresh_token: str | None = Field(default=None, min_length=16, max_length=256)


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: Literal["bearer"] = "bearer"  # noqa: S105 - OAuth2 token type, not a secret
    expires_in: int
    organization_id: uuid.UUID
    role: Role


class MeResponse(BaseModel):
    principal_type: str
    principal_id: uuid.UUID
    organization_id: uuid.UUID
    role: Role
    scopes: list[str]
    email: str | None = None


# ----- organization ---------------------------------------------------------------------------


class OrganizationOut(Model):
    id: uuid.UUID
    name: str
    slug: str
    created_at: datetime


class MemberOut(BaseModel):
    user_id: uuid.UUID
    email: str
    role: Role
    created_at: datetime


class AddMemberRequest(BaseModel):
    email: EmailStr
    role: Role = Role.ANALYST

    model_config = ConfigDict(json_schema_extra={"examples": [{"email": "grace@hospital.example", "role": "analyst"}]})


class ChangeRoleRequest(BaseModel):
    role: Role


# ----- projects -----------------------------------------------------------------------------------


class ProjectCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    description: str = Field(default="", max_length=2000)

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [{"name": "cardio-risk", "description": "Encrypted cardiovascular risk scoring"}]
        }
    )


class ProjectUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=120)
    description: str | None = Field(default=None, max_length=2000)


class ProjectOut(Model):
    id: uuid.UUID
    name: str
    description: str
    created_at: datetime


# ----- key bundles --------------------------------------------------------------------------------


class KeyBundleOut(Model):
    id: uuid.UUID
    project_id: uuid.UUID
    ring_id: str | None
    fingerprint: str | None
    params: dict[str, Any] | None
    size_bytes: int | None
    status: KeyBundleStatus
    created_at: datetime
    revoked_at: datetime | None


# ----- datasets & ciphertexts -------------------------------------------------------------------


class DatasetCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    description: str = Field(default="", max_length=2000)
    key_bundle_id: uuid.UUID

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [{"name": "vitals-2026-q4", "key_bundle_id": "01934f6e-7c1a-7b3e-9a51-6f0c2d8e4b11"}]
        }
    )


class DatasetOut(Model):
    id: uuid.UUID
    project_id: uuid.UUID
    key_bundle_id: uuid.UUID
    name: str
    description: str
    created_at: datetime


class CiphertextCreate(BaseModel):
    label: str = Field(min_length=1, max_length=120)
    size_bytes: int = Field(gt=0)

    model_config = ConfigDict(json_schema_extra={"examples": [{"label": "systolic_bp", "size_bytes": 338012}]})


class CiphertextOut(Model):
    id: uuid.UUID
    dataset_id: uuid.UUID
    label: str
    status: CiphertextStatus
    size_bytes: int | None
    declared_size_bytes: int
    fingerprint: str | None
    length: int | None
    levels_consumed: int | None
    created_at: datetime


class PresignedUploadOut(BaseModel):
    url: str
    fields: dict[str, str]
    expires_at: str
    max_bytes: int


class CiphertextUploadOut(BaseModel):
    ciphertext: CiphertextOut
    upload: PresignedUploadOut


class DownloadOut(BaseModel):
    url: str
    expires_at: str


# ----- jobs ---------------------------------------------------------------------------------------


class JobCreate(BaseModel):
    operation: str = Field(min_length=1, max_length=64)
    inputs: list[uuid.UUID] = Field(min_length=1)
    args: dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {"operation": "mean", "inputs": ["01934f6e-8a20-7d11-b0c4-2b7e6a1f9c03"], "args": {}},
                {
                    "operation": "logistic_regression",
                    "inputs": ["01934f6e-8a20-7d11-b0c4-2b7e6a1f9c03", "01934f6e-8a21-7a02-8c55-91d0e4f3a7b2"],
                    "args": {"weights": [0.8, -0.3], "intercept": -1.2, "layout": "columns", "degree": 3},
                },
            ]
        }
    )


class JobOut(Model):
    id: uuid.UUID
    project_id: uuid.UUID
    key_bundle_id: uuid.UUID
    operation: str
    args: dict[str, Any]
    input_ids: list[Any]
    input_fingerprints: list[Any]
    manifest_hash: str
    status: JobStatus
    attempts: int
    plan: dict[str, Any]
    depth_report: dict[str, Any] | None
    result_fingerprint: str | None
    result_length: int | None
    result_size_bytes: int | None
    error: dict[str, Any] | None
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    compute_seconds: float | None


class JobResultOut(BaseModel):
    job_id: uuid.UUID
    download: DownloadOut
    manifest_hash: str
    input_fingerprints: list[Any]
    result_fingerprint: str | None
    result_length: int | None
    depth_report: dict[str, Any] | None


# ----- catalog / advisor ----------------------------------------------------------------------------


class AdvisorStep(BaseModel):
    operation: str
    args: dict[str, Any] = Field(default_factory=dict)


class AdvisorRequest(BaseModel):
    steps: list[AdvisorStep] = Field(min_length=1, max_length=32)
    input_lengths: list[int] = Field(min_length=1)
    security_level: Literal[128, 192, 256] = 128
    min_poly_modulus_degree: Literal[8192, 16384, 32768] = 8192
    prefer: Literal["balanced", "deep"] = "balanced"
    min_precision_bits: int = Field(default=0, ge=0, le=50)

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "steps": [{"operation": "logistic_regression", "args": {"weights": [0.5, -0.2, 0.1], "degree": 3}}],
                    "input_lengths": [3],
                    "security_level": 128,
                }
            ]
        }
    )


# ----- api keys --------------------------------------------------------------------------------------


class ApiKeyCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    scopes: list[str] = Field(min_length=1)
    expires_in_days: int | None = Field(default=None, ge=1, le=365)

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {"name": "ci-pipeline", "scopes": ["jobs:write", "jobs:read", "datasets:write"], "expires_in_days": 90}
            ]
        }
    )


class ApiKeyOut(Model):
    id: uuid.UUID
    name: str
    prefix: str
    role: Role
    scopes: list[Any]
    created_at: datetime
    expires_at: datetime | None
    revoked_at: datetime | None
    last_used_at: datetime | None


class ApiKeyCreated(BaseModel):
    api_key: ApiKeyOut
    secret: str = Field(description="Shown once. Store it in a secret manager.")


# ----- audit -------------------------------------------------------------------------------------------


class AuditEventOut(Model):
    seq: int
    id: uuid.UUID
    occurred_at: datetime
    actor_type: str
    actor_id: uuid.UUID | None
    action: str
    resource_type: str
    resource_id: uuid.UUID | None
    ip: str | None
    request_id: str | None
    trace_id: str | None
    details: dict[str, Any]
    prev_hash: str
    hash: str


T = TypeVar("T")


class Page(BaseModel, Generic[T]):  # noqa: UP046 - pydantic generics need the explicit base
    items: list[T]
    next_cursor: str | None = None
