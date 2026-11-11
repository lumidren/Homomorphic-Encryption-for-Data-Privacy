"""Ciphertext upload (presigned, direct to object storage), confirmation and download.

Flow: ``POST /datasets/{id}/ciphertexts`` reserves a row and returns a presigned POST whose
policy caps the size; the client uploads the envelope straight to the bucket; ``POST
/ciphertexts/{id}/confirm`` reads the envelope header, checks it belongs to the dataset's key
ring and parameters, and fingerprints the object. The worker re-verifies the header against
the ciphertext itself and the fingerprint against the bytes before computing.
"""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, Query, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from ciphercompute_core import CKKSParams
from ciphercompute_core.envelope import MAGIC_CIPHERTEXT, unpack
from ciphercompute_core.errors import CipherComputeError
from ciphercompute_core.ids import uuid7

from ..audit.service import AuditAction
from ..db.base import utcnow
from ..db.models import Ciphertext, CiphertextStatus, Dataset, KeyBundle, KeyBundleStatus, Role
from ..deps import Principal, db_session, get_state, require
from ..errors import ConflictError, PayloadTooLargeError, UnprocessableError
from ..schemas import CiphertextCreate, CiphertextOut, CiphertextUploadOut, DownloadOut, Page, PresignedUploadOut
from ..storage.objects import ObjectStore
from ..telemetry import CIPHERTEXT_BYTES
from .common import audit, page_of, paginate

router = APIRouter(prefix="/v1", tags=["ciphertexts"])

_PREFIX_LEN = 9
_MAX_HEADER = 64 * 1024


@router.post(
    "/datasets/{dataset_id}/ciphertexts", response_model=CiphertextUploadOut, status_code=status.HTTP_201_CREATED
)
async def create_ciphertext(
    dataset_id: uuid.UUID,
    body: CiphertextCreate,
    request: Request,
    principal: Principal = Depends(require("datasets:write", Role.ANALYST)),
    session: AsyncSession = Depends(db_session),
) -> CiphertextUploadOut:
    state = get_state(request)
    tenant = principal.tenant(session)
    dataset = await tenant.get_or_404(Dataset, dataset_id, "dataset")
    limit = state.settings.max_ciphertext_bytes
    if body.size_bytes > limit:
        # [TM:D-1] Oversized uploads are refused up front, and the presigned policy enforces
        # the declared size so the bucket rejects anything larger.
        raise PayloadTooLargeError(f"ciphertext of {body.size_bytes} bytes exceeds the {limit}-byte limit", limit=limit)
    ct_id = uuid7()
    row = tenant.add(
        Ciphertext(
            id=ct_id,
            dataset_id=dataset.id,
            label=body.label,
            object_key=ObjectStore.key_for_ciphertext(principal.organization_id, dataset.project_id, dataset.id, ct_id),
            declared_size_bytes=body.size_bytes,
        )
    )
    await tenant.flush()
    upload = await state.store.presign_upload(row.object_key, principal.organization_id, max_bytes=body.size_bytes)
    await audit(
        request,
        tenant,
        principal,
        AuditAction.CIPHERTEXT_CREATED,
        "ciphertext",
        row.id,
        label=row.label,
        dataset_id=str(dataset.id),
    )
    await tenant.commit()
    return CiphertextUploadOut(
        ciphertext=CiphertextOut.model_validate(row),
        upload=PresignedUploadOut(
            url=upload.url, fields=upload.fields, expires_at=upload.expires_at, max_bytes=upload.max_bytes
        ),
    )


@router.post("/ciphertexts/{ciphertext_id}/confirm", response_model=CiphertextOut)
async def confirm_ciphertext(
    ciphertext_id: uuid.UUID,
    request: Request,
    principal: Principal = Depends(require("datasets:write", Role.ANALYST)),
    session: AsyncSession = Depends(db_session),
) -> Ciphertext:
    state = get_state(request)
    tenant = principal.tenant(session)
    row = await tenant.get_or_404(Ciphertext, ciphertext_id, "ciphertext")
    if row.status == CiphertextStatus.READY:
        return row
    info = await state.store.head(row.object_key, principal.organization_id)
    if info is None:
        raise ConflictError("the ciphertext has not been uploaded yet")
    if info.size > row.declared_size_bytes:
        await state.store.delete(row.object_key, principal.organization_id)
        raise PayloadTooLargeError(
            "uploaded object is larger than declared", declared=row.declared_size_bytes, actual=info.size
        )
    dataset = await tenant.get_or_404(Dataset, row.dataset_id, "dataset")
    bundle = await tenant.get_or_404(KeyBundle, dataset.key_bundle_id, "key bundle")
    if bundle.status != KeyBundleStatus.ACTIVE or bundle.params is None:
        raise UnprocessableError("the dataset's key bundle is not active")
    header = await _read_header(request, row.object_key, principal.organization_id, info.size)
    params = CKKSParams.from_dict(bundle.params)
    if header.get("kind") != "ckks_vector":
        raise UnprocessableError("object is not a CKKS vector envelope")
    if header.get("ring_id") != bundle.ring_id:
        raise UnprocessableError("ciphertext was encrypted under a different key ring than the dataset's bundle")
    try:
        if CKKSParams.from_dict(header.get("params") or {}) != params:
            raise UnprocessableError("ciphertext parameters do not match the key bundle")
    except CipherComputeError as exc:
        raise UnprocessableError(f"ciphertext parameters are invalid: {exc}") from exc
    length, levels = header.get("length"), header.get("levels_consumed")
    if not isinstance(length, int) or not 1 <= length <= params.slots:
        raise UnprocessableError("ciphertext header has an invalid length")
    if not isinstance(levels, int) or not 0 <= levels <= params.depth:
        raise UnprocessableError("ciphertext header has an invalid level count")
    fingerprint, size = await state.store.sha256_of(
        row.object_key, principal.organization_id, max_bytes=state.settings.max_ciphertext_bytes
    )
    row.fingerprint = fingerprint
    row.size_bytes = size
    row.length = length
    row.levels_consumed = levels
    row.status = CiphertextStatus.READY
    row.confirmed_at = utcnow()
    await audit(
        request,
        tenant,
        principal,
        AuditAction.CIPHERTEXT_CONFIRMED,
        "ciphertext",
        row.id,
        fingerprint=fingerprint,
        size_bytes=size,
    )
    await tenant.commit()
    CIPHERTEXT_BYTES.observe(size)
    return row


async def _read_header(request: Request, key: str, organization_id: uuid.UUID, size: int) -> dict[str, Any]:
    store = get_state(request).store
    if size < _PREFIX_LEN:
        raise UnprocessableError("object is too small to be a ciphertext envelope")
    prefix = await store.get_range(key, organization_id, 0, _PREFIX_LEN - 1)
    header_len = int.from_bytes(prefix[5:9], "big")
    if header_len > _MAX_HEADER or _PREFIX_LEN + header_len > size:
        raise UnprocessableError("ciphertext envelope header is invalid")
    blob = await store.get_range(key, organization_id, 0, _PREFIX_LEN + header_len - 1)
    try:
        header, _ = unpack(MAGIC_CIPHERTEXT, blob)
    except CipherComputeError as exc:
        raise UnprocessableError(f"ciphertext envelope is invalid: {exc}") from exc
    return header


@router.get("/datasets/{dataset_id}/ciphertexts", response_model=Page[CiphertextOut])
async def list_ciphertexts(
    dataset_id: uuid.UUID,
    limit: int = Query(100),
    before: str | None = Query(None),
    principal: Principal = Depends(require("datasets:read")),
    session: AsyncSession = Depends(db_session),
) -> Page[CiphertextOut]:
    tenant = principal.tenant(session)
    await tenant.get_or_404(Dataset, dataset_id, "dataset")
    stmt = paginate(
        tenant.select(Ciphertext).where(Ciphertext.dataset_id == dataset_id), Ciphertext.id, limit=limit, before=before
    )
    items, cursor = page_of(list(await tenant.scalars(stmt)), limit)
    return Page[CiphertextOut](items=[CiphertextOut.model_validate(c) for c in items], next_cursor=cursor)


@router.get("/ciphertexts/{ciphertext_id}", response_model=CiphertextOut)
async def get_ciphertext(
    ciphertext_id: uuid.UUID,
    principal: Principal = Depends(require("datasets:read")),
    session: AsyncSession = Depends(db_session),
) -> Ciphertext:
    return await principal.tenant(session).get_or_404(Ciphertext, ciphertext_id, "ciphertext")


@router.get("/ciphertexts/{ciphertext_id}/download", response_model=DownloadOut)
async def download_ciphertext(
    ciphertext_id: uuid.UUID,
    request: Request,
    principal: Principal = Depends(require("datasets:read")),
    session: AsyncSession = Depends(db_session),
) -> DownloadOut:
    tenant = principal.tenant(session)
    row = await tenant.get_or_404(Ciphertext, ciphertext_id, "ciphertext")
    if row.status != CiphertextStatus.READY:
        raise ConflictError("ciphertext is not confirmed")
    url, expires_at = await get_state(request).store.presign_download(row.object_key, principal.organization_id)
    await audit(request, tenant, principal, AuditAction.CIPHERTEXT_ACCESSED, "ciphertext", row.id)
    await tenant.commit()
    return DownloadOut(url=url, expires_at=expires_at)


@router.delete("/ciphertexts/{ciphertext_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_ciphertext(
    ciphertext_id: uuid.UUID,
    request: Request,
    principal: Principal = Depends(require("datasets:write", Role.ANALYST)),
    session: AsyncSession = Depends(db_session),
) -> None:
    tenant = principal.tenant(session)
    row = await tenant.get_or_404(Ciphertext, ciphertext_id, "ciphertext")
    key = row.object_key
    await tenant.delete(row)
    await audit(request, tenant, principal, AuditAction.CIPHERTEXT_DELETED, "ciphertext", ciphertext_id)
    await tenant.commit()
    await get_state(request).store.delete(key, principal.organization_id)
