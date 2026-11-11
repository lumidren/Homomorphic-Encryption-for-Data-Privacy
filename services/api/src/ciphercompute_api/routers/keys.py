"""Public key bundles.

The bundle is uploaded *through* the API (not presigned) on purpose: it is parsed by
``PublicKeyBundle.load`` before a single byte is persisted, so a bundle that carries a secret
key is refused without ever reaching storage.
"""

from __future__ import annotations

import asyncio
import uuid

from fastapi import APIRouter, Depends, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from ciphercompute_core import PublicKeyBundle
from ciphercompute_core.errors import CipherComputeError
from ciphercompute_core.ids import uuid7

from ..audit.service import AuditAction
from ..db.base import utcnow
from ..db.models import KeyBundle, KeyBundleStatus, Project, Role
from ..deps import Principal, db_session, get_state, require
from ..errors import ConflictError, PayloadTooLargeError, UnprocessableError
from ..schemas import KeyBundleOut
from ..storage.objects import ObjectStore
from ..telemetry import BUNDLE_BYTES
from .common import audit

router = APIRouter(prefix="/v1", tags=["key-bundles"])

_BUNDLE_BODY = {
    "requestBody": {
        "required": True,
        "content": {
            "application/octet-stream": {
                "schema": {"type": "string", "format": "binary"},
                "example": "<bytes of KeyRing.public_bundle().to_bytes()>",
            }
        },
    }
}


async def read_limited_body(request: Request, limit: int) -> bytes:
    declared = request.headers.get("content-length")
    if declared is not None and declared.isdigit() and int(declared) > limit:
        raise PayloadTooLargeError(f"body is {declared} bytes; the limit is {limit}", limit=limit)
    chunks: list[bytes] = []
    received = 0
    async for chunk in request.stream():
        received += len(chunk)
        if received > limit:
            raise PayloadTooLargeError(f"body exceeds the {limit}-byte limit", limit=limit)
        chunks.append(chunk)
    if received == 0:
        raise UnprocessableError("empty body; send the serialized bundle as application/octet-stream")
    return b"".join(chunks)


@router.post(
    "/projects/{project_id}/key-bundles",
    response_model=KeyBundleOut,
    status_code=status.HTTP_201_CREATED,
    openapi_extra=_BUNDLE_BODY,
    summary="Upload a public key bundle (public, relinearization and Galois keys — never a secret key)",
)
async def upload_bundle(
    project_id: uuid.UUID,
    request: Request,
    principal: Principal = Depends(require("keys:write", Role.ANALYST)),
    session: AsyncSession = Depends(db_session),
) -> KeyBundle:
    state = get_state(request)
    tenant = principal.tenant(session)
    await tenant.get_or_404(Project, project_id, "project")
    data = await read_limited_body(request, state.settings.max_bundle_bytes)
    # [TM:I-2] Parse and gate *before* persisting anything: a private context raises
    # SecretKeyLeakError here and nothing is written to storage.
    try:
        bundle = await asyncio.to_thread(PublicKeyBundle.load, data)
    except CipherComputeError as exc:
        await audit(request, tenant, principal, AuditAction.KEY_BUNDLE_REJECTED, "project", project_id, reason=exc.code)
        await tenant.commit()
        raise
    existing = await tenant.scalar_one_or_none(
        tenant.select(KeyBundle).where(KeyBundle.project_id == project_id, KeyBundle.ring_id == bundle.ring_id)
    )
    if existing is not None:
        raise ConflictError("this key ring is already registered in the project", key_bundle_id=str(existing.id))
    bundle_id = uuid7()
    row = KeyBundle(
        id=bundle_id,
        project_id=project_id,
        object_key=ObjectStore.key_for_bundle(principal.organization_id, project_id, bundle_id),
        declared_size_bytes=len(data),
        size_bytes=len(data),
        ring_id=bundle.ring_id,
        fingerprint=bundle.fingerprint,
        params=bundle.params.to_dict(),
        status=KeyBundleStatus.ACTIVE,
        confirmed_at=utcnow(),
        created_by_user_id=principal.user_id,
        created_by_api_key_id=principal.api_key_id,
    )
    await state.store.put_bytes(row.object_key, principal.organization_id, data)
    tenant.add(row)
    await tenant.flush()
    await audit(
        request,
        tenant,
        principal,
        AuditAction.KEY_BUNDLE_CREATED,
        "key_bundle",
        row.id,
        ring_id=bundle.ring_id,
        fingerprint=bundle.fingerprint,
        params=row.params,
        size_bytes=len(data),
    )
    await tenant.commit()
    BUNDLE_BYTES.observe(len(data))
    return row


@router.get("/projects/{project_id}/key-bundles", response_model=list[KeyBundleOut])
async def list_bundles(
    project_id: uuid.UUID,
    principal: Principal = Depends(require("projects:read")),
    session: AsyncSession = Depends(db_session),
) -> list[KeyBundle]:
    tenant = principal.tenant(session)
    await tenant.get_or_404(Project, project_id, "project")
    stmt = tenant.select(KeyBundle).where(KeyBundle.project_id == project_id).order_by(KeyBundle.id.desc())
    return list(await tenant.scalars(stmt))


@router.get("/key-bundles/{bundle_id}", response_model=KeyBundleOut)
async def get_bundle(
    bundle_id: uuid.UUID,
    principal: Principal = Depends(require("projects:read")),
    session: AsyncSession = Depends(db_session),
) -> KeyBundle:
    return await principal.tenant(session).get_or_404(KeyBundle, bundle_id, "key bundle")


@router.post("/key-bundles/{bundle_id}/revoke", response_model=KeyBundleOut)
async def revoke_bundle(
    bundle_id: uuid.UUID,
    request: Request,
    principal: Principal = Depends(require("keys:write", Role.ADMIN)),
    session: AsyncSession = Depends(db_session),
) -> KeyBundle:
    """Revoke a bundle so no new jobs run under it (see RUNBOOK, key rotation)."""
    tenant = principal.tenant(session)
    row = await tenant.get_or_404(KeyBundle, bundle_id, "key bundle")
    if row.status != KeyBundleStatus.REVOKED:
        row.status = KeyBundleStatus.REVOKED
        row.revoked_at = utcnow()
        await audit(request, tenant, principal, AuditAction.KEY_BUNDLE_REVOKED, "key_bundle", row.id)
        await tenant.commit()
    return row
