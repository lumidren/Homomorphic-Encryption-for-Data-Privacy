"""Job submission, status, results, cancellation and live progress (Server-Sent Events)."""

from __future__ import annotations

import asyncio
import json
import time
import uuid
from collections.abc import AsyncIterator
from typing import Any

from fastapi import APIRouter, Depends, Header, Query, Request, Response, status
from fastapi.responses import StreamingResponse
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from ciphercompute_core import CKKSParams, get_operation, plan
from ciphercompute_core.errors import CipherComputeError
from ciphercompute_core.manifest import manifest_hash

from ..audit.service import AuditAction
from ..db.models import Ciphertext, CiphertextStatus, Dataset, Job, JobStatus, KeyBundle, KeyBundleStatus, Project, Role
from ..db.tenancy import TenantScopedSession
from ..deps import Principal, db_session, get_state, require
from ..errors import ApiError, ConflictError, UnprocessableError
from ..idempotency import assert_same_request, request_hash, validate_key
from ..logging import get_logger
from ..schemas import DownloadOut, JobCreate, JobOut, JobResultOut, Page
from ..telemetry import JOBS_REFUSED, JOBS_SUBMITTED
from .common import audit, page_of, paginate

router = APIRouter(prefix="/v1", tags=["jobs"])
log = get_logger(__name__)

TERMINAL = {JobStatus.SUCCEEDED, JobStatus.FAILED, JobStatus.CANCELLED}
SSE_MAX_SECONDS = 600




async def _load_inputs(
    tenant: TenantScopedSession, project_id: uuid.UUID, ids: list[uuid.UUID]
) -> tuple[list[Ciphertext], KeyBundle]:
    if len(set(ids)) != len(ids):
        # Allowed by the maths (x·x), but almost always a client bug; be explicit.
        pass
    rows = {c.id: c for c in await tenant.scalars(tenant.select(Ciphertext).where(Ciphertext.id.in_(set(ids))))}
    missing = [str(i) for i in ids if i not in rows]
    if missing:
        raise UnprocessableError("unknown input ciphertexts", missing=missing)
    ordered = [rows[i] for i in ids]
    not_ready = [str(c.id) for c in ordered if c.status != CiphertextStatus.READY]
    if not_ready:
        raise UnprocessableError("input ciphertexts are not confirmed", not_ready=not_ready)
    dataset_ids = {c.dataset_id for c in ordered}
    datasets = {d.id: d for d in await tenant.scalars(tenant.select(Dataset).where(Dataset.id.in_(dataset_ids)))}
    if any(d.project_id != project_id for d in datasets.values()):
        raise UnprocessableError("all inputs must belong to datasets of this project")
    bundle_ids = {d.key_bundle_id for d in datasets.values()}
    if len(bundle_ids) != 1:
        raise UnprocessableError("all inputs must be encrypted under the same key bundle")
    bundle = await tenant.get_or_404(KeyBundle, bundle_ids.pop(), "key bundle")
    if bundle.status != KeyBundleStatus.ACTIVE or bundle.params is None:
        raise UnprocessableError("the key bundle is revoked or inactive", key_bundle_id=str(bundle.id))
    return ordered, bundle


@router.post(
    "/projects/{project_id}/jobs",
    response_model=JobOut,
    status_code=status.HTTP_202_ACCEPTED,
    responses={200: {"description": "Idempotent replay: the job created by the first request", "model": JobOut}},
)
async def submit_job(
    project_id: uuid.UUID,
    body: JobCreate,
    request: Request,
    response: Response,
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    principal: Principal = Depends(require("jobs:write", Role.ANALYST)),
    session: AsyncSession = Depends(db_session),
) -> Job:
    state = get_state(request)
    tenant = principal.tenant(session)
    key = validate_key(idempotency_key)
    req_hash = request_hash({"project_id": str(project_id), **body.model_dump(mode="json")})
    if key is not None:
        prior = await tenant.scalar_one_or_none(tenant.select(Job).where(Job.idempotency_key == key))
        if prior is not None:
            assert_same_request(prior.request_hash, req_hash)
            response.status_code = status.HTTP_200_OK
            return prior

    await tenant.get_or_404(Project, project_id, "project")
    if len(body.inputs) > state.settings.max_inputs_per_job:
        raise UnprocessableError(f"a job may have at most {state.settings.max_inputs_per_job} inputs")
    spec = get_operation(body.operation)
    if len(body.inputs) < spec.min_inputs or (spec.max_inputs is not None and len(body.inputs) > spec.max_inputs):
        raise UnprocessableError(
            f"{spec.name} takes between {spec.min_inputs} and {spec.max_inputs or 'any number of'} inputs"
        )
    inputs, bundle = await _load_inputs(tenant, project_id, body.inputs)
    params = CKKSParams.from_dict(bundle.params or {})
    lengths = [int(c.length or 0) for c in inputs]
    normalized = spec.normalize(lengths, body.args)
    try:
        # [TM:D-2] Refused here — with the exact parameter set that would work — before any
        # worker spends CPU on it.
        planned = plan(
            params,
            [(spec.name, normalized)],
            input_lengths=lengths,
            initial_levels_consumed=max(int(c.levels_consumed or 0) for c in inputs),
        )
    except CipherComputeError as exc:
        JOBS_REFUSED.labels(reason=exc.code).inc()
        raise
    fingerprints = [str(c.fingerprint) for c in inputs]
    job = tenant.add(
        Job(
            project_id=project_id,
            key_bundle_id=bundle.id,
            operation=spec.name,
            args=normalized,
            input_ids=[str(c.id) for c in inputs],
            input_fingerprints=fingerprints,
            manifest_hash=manifest_hash(spec.name, normalized, fingerprints, bundle.fingerprint),
            idempotency_key=key,
            request_hash=req_hash,
            plan=planned.to_dict(),
            depth_report=planned.report.to_dict(),
            submitted_by_user_id=principal.user_id,
            submitted_by_api_key_id=principal.api_key_id,
        )
    )
    try:
        await tenant.flush()
    except IntegrityError:
        # Lost a race with a concurrent request carrying the same Idempotency-Key.
        await tenant.rollback()
        prior = await tenant.scalar_one_or_none(tenant.select(Job).where(Job.idempotency_key == key))
        if prior is None:
            raise
        assert_same_request(prior.request_hash, req_hash)
        response.status_code = status.HTTP_200_OK
        return prior
    await audit(
        request,
        tenant,
        principal,
        AuditAction.JOB_SUBMITTED,
        "job",
        job.id,
        operation=spec.name,
        inputs=job.input_ids,
        required_depth=planned.required_depth,
        manifest_hash=job.manifest_hash,
    )
    await tenant.commit()
    try:
        await state.queue.enqueue(job.id, principal.organization_id)
    except Exception as exc:
        log.error("enqueue_failed", job_id=str(job.id), error=type(exc).__name__)
        job.status = JobStatus.FAILED
        job.error = {"code": "queue_unavailable", "message": "the job queue is unavailable; resubmit later"}
        await tenant.commit()
        raise ApiError("job queue unavailable", status_code=503, code="queue_unavailable", job_id=str(job.id)) from exc
    JOBS_SUBMITTED.labels(operation=spec.name, organization=str(principal.organization_id)).inc()
    return job


@router.get("/jobs", response_model=Page[JobOut])
async def list_jobs(
    project_id: uuid.UUID | None = Query(None),
    status_filter: JobStatus | None = Query(None, alias="status"),
    limit: int = Query(50),
    before: str | None = Query(None),
    principal: Principal = Depends(require("jobs:read")),
    session: AsyncSession = Depends(db_session),
) -> Page[JobOut]:
    tenant = principal.tenant(session)
    stmt = tenant.select(Job)
    if project_id is not None:
        stmt = stmt.where(Job.project_id == project_id)
    if status_filter is not None:
        stmt = stmt.where(Job.status == status_filter)
    items, cursor = page_of(list(await tenant.scalars(paginate(stmt, Job.id, limit=limit, before=before))), limit)
    return Page[JobOut](items=[JobOut.model_validate(j) for j in items], next_cursor=cursor)


@router.get("/jobs/{job_id}", response_model=JobOut)
async def get_job(
    job_id: uuid.UUID,
    principal: Principal = Depends(require("jobs:read")),
    session: AsyncSession = Depends(db_session),
) -> Job:
    return await principal.tenant(session).get_or_404(Job, job_id, "job")


@router.post("/jobs/{job_id}/cancel", response_model=JobOut)
async def cancel_job(
    job_id: uuid.UUID,
    request: Request,
    principal: Principal = Depends(require("jobs:write", Role.ANALYST)),
    session: AsyncSession = Depends(db_session),
) -> Job:
    tenant = principal.tenant(session)
    job = await tenant.get_or_404(Job, job_id, "job")
    if job.status == JobStatus.CANCELLED:
        return job
    if job.status != JobStatus.QUEUED:
        raise ConflictError(f"only queued jobs can be cancelled; this job is {job.status.value}")
    job.status = JobStatus.CANCELLED
    await audit(request, tenant, principal, AuditAction.JOB_CANCELLED, "job", job.id)
    await tenant.commit()
    return job


@router.get("/jobs/{job_id}/result", response_model=JobResultOut)
async def get_result(
    job_id: uuid.UUID,
    request: Request,
    principal: Principal = Depends(require("jobs:read")),
    session: AsyncSession = Depends(db_session),
) -> JobResultOut:
    tenant = principal.tenant(session)
    job = await tenant.get_or_404(Job, job_id, "job")
    if job.status != JobStatus.SUCCEEDED or not job.result_object_key:
        raise ConflictError(f"job has no result; status is {job.status.value}", status=job.status.value)
    url, expires_at = await get_state(request).store.presign_download(job.result_object_key, principal.organization_id)
    await audit(request, tenant, principal, AuditAction.RESULT_ACCESSED, "job", job.id)
    await tenant.commit()
    return JobResultOut(
        job_id=job.id,
        download=DownloadOut(url=url, expires_at=expires_at),
        manifest_hash=job.manifest_hash,
        input_fingerprints=job.input_fingerprints,
        result_fingerprint=job.result_fingerprint,
        result_length=job.result_length,
        depth_report=job.depth_report,
    )


def _sse(event: str, data: dict[str, Any]) -> bytes:
    return f"event: {event}\ndata: {json.dumps(data, default=str)}\n\n".encode()


@router.get(
    "/jobs/{job_id}/events",
    response_class=StreamingResponse,
    responses={200: {"content": {"text/event-stream": {"example": 'event: status\ndata: {"status": "running"}\n\n'}}}},
)
async def job_events(
    job_id: uuid.UUID,
    request: Request,
    principal: Principal = Depends(require("jobs:read")),
    session: AsyncSession = Depends(db_session),
) -> StreamingResponse:
    """Server-Sent Events: one ``status`` event per state change, ``heartbeat`` comments in between."""
    state = get_state(request)
    await principal.tenant(session).get_or_404(Job, job_id, "job")
    await session.close()
    interval = state.settings.job_poll_interval_seconds

    async def stream() -> AsyncIterator[bytes]:
        last: tuple[str, int] | None = None
        started = time.monotonic()
        while time.monotonic() - started < SSE_MAX_SECONDS:
            if await request.is_disconnected():
                return
            async with state.session_factory() as poll_session:
                job = await TenantScopedSession(poll_session, principal.organization_id).get(Job, job_id)
            if job is None:
                yield _sse("error", {"code": "not_found"})
                return
            current = (job.status.value, job.attempts)
            if current != last:
                last = current
                yield _sse("status", JobOut.model_validate(job).model_dump(mode="json"))
                if job.status in TERMINAL:
                    return
            else:
                yield b": heartbeat\n\n"
            await asyncio.sleep(interval)
        yield _sse("timeout", {"reconnect": True})

    return StreamingResponse(
        stream(), media_type="text/event-stream", headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"}
    )
