"""Execute one job: claim, verify, compute on ciphertexts, store, record.

The worker holds public key material only. Every input is checked against the SHA-256 recorded
when it was uploaded, and the result's measured depth must equal the depth the API planned —
any mismatch fails the job rather than returning a result nobody can trust.
"""

from __future__ import annotations

import asyncio
import hashlib
import random
import socket
import time
import uuid
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any, Literal

from botocore.exceptions import BotoCoreError, ClientError
from redis.exceptions import RedisError
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ciphercompute_api.audit.service import Actor, AuditAction, RequestContext, record_event
from ciphercompute_api.db.base import utcnow
from ciphercompute_api.db.models import (
    Ciphertext,
    CiphertextStatus,
    Job,
    JobStatus,
    KeyBundle,
    KeyBundleStatus,
)
from ciphercompute_api.db.tenancy import TenantScopedSession
from ciphercompute_api.logging import get_logger
from ciphercompute_api.storage.objects import ObjectStore
from ciphercompute_core import CKKSParams, EncryptedVector, PublicKeyBundle, apply_operation, plan
from ciphercompute_core.errors import CipherComputeError

from .concurrency import TenantSemaphore, job_weight
from .config import WorkerSettings
from .metrics import (
    CIPHERTEXT_INPUT_BYTES,
    JOB_COMPUTE_SECONDS,
    JOB_END_TO_END_SECONDS,
    JOB_QUEUE_WAIT_SECONDS,
    JOB_RETRIES,
    JOBS_FINISHED,
    LEVELS_CONSUMED_RATIO,
    RESULT_BYTES,
    TENANT_THROTTLED,
    WORKERS_BUSY,
)

log = get_logger(__name__)

TRANSIENT_ERRORS: tuple[type[BaseException], ...] = (
    ClientError,
    BotoCoreError,
    SQLAlchemyError,
    RedisError,
    ConnectionError,
    TimeoutError,
)

OutcomeKind = Literal["succeeded", "failed", "noop", "throttled", "retry"]


@dataclass(frozen=True, slots=True)
class Outcome:
    kind: OutcomeKind
    detail: str = ""
    countdown: float = 0.0


class JobFailedError(Exception):
    """A deterministic failure: retrying would produce the same result."""

    def __init__(self, code: str, message: str, **details: Any) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details


@dataclass
class WorkerContext:
    settings: WorkerSettings
    session_factory: async_sessionmaker[AsyncSession]
    store: ObjectStore
    semaphore: TenantSemaphore
    bundle_cache: OrderedDict[str, PublicKeyBundle] = field(default_factory=OrderedDict)
    worker_id: str = field(default_factory=lambda: f"{socket.gethostname()}:{uuid.uuid4().hex[:8]}")

    async def bundle(self, row: KeyBundle) -> PublicKeyBundle:
        """Load (or reuse) a public bundle; bundles are tens to hundreds of MB, so cache by fingerprint."""
        if row.fingerprint is None:
            raise JobFailedError("bundle_integrity", "key bundle has no recorded fingerprint")
        cached = self.bundle_cache.get(row.fingerprint)
        if cached is not None:
            self.bundle_cache.move_to_end(row.fingerprint)
            return cached
        data = await self.store.get_bytes(row.object_key, row.organization_id, max_bytes=self.settings.max_bundle_bytes)
        # [TM:I-1] Second gate: the worker re-runs the secret-key check on what it loaded.
        loaded = await asyncio.to_thread(PublicKeyBundle.load, data)
        if loaded.fingerprint != row.fingerprint or loaded.ring_id != row.ring_id:
            raise JobFailedError(
                "bundle_integrity", "stored key bundle does not match the fingerprint recorded at upload"
            )
        self.bundle_cache[row.fingerprint] = loaded
        while len(self.bundle_cache) > self.settings.bundle_cache_size:
            self.bundle_cache.popitem(last=False)
        return loaded


def sha256_fingerprint(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def backoff_seconds(settings: WorkerSettings, attempt: int) -> float:
    """Exponential backoff with full jitter in [0.5, 1.5) x the base delay."""
    base = min(settings.retry_backoff_max_seconds, settings.retry_backoff_base_seconds * 2 ** max(0, attempt - 1))
    return float(base * (0.5 + random.random()))  # noqa: S311 - jitter, not cryptography


def _context() -> RequestContext:
    from ciphercompute_api.telemetry import current_trace_id

    return RequestContext(trace_id=current_trace_id())


async def _claim(ctx: WorkerContext, session: AsyncSession, job_id: uuid.UUID, org_id: uuid.UUID) -> Job | None:
    # [TM:P-1] Row lock + state check make duplicate deliveries and concurrent workers no-ops.
    stmt = select(Job).where(Job.id == job_id, Job.organization_id == org_id).with_for_update(skip_locked=True)
    job = (await session.execute(stmt)).scalar_one_or_none()
    if job is None:
        return None
    if job.status == JobStatus.QUEUED:
        return job
    stale_after = timedelta(seconds=ctx.settings.job_hard_time_limit_seconds + 60)
    if job.status == JobStatus.RUNNING and job.started_at is not None and job.started_at < utcnow() - stale_after:
        log.warning("reclaiming_stale_job", job_id=str(job.id), worker_id=job.worker_id)
        return job
    return None


async def _finish(
    ctx: WorkerContext,
    job_id: uuid.UUID,
    org_id: uuid.UUID,
    *,
    status: JobStatus,
    action: AuditAction,
    values: dict[str, Any],
    details: dict[str, Any],
) -> None:
    async with ctx.session_factory() as session:
        tenant = TenantScopedSession(session, org_id)
        job = await tenant.get(Job, job_id)
        if job is None:  # project deleted while running
            return
        job.status = status
        for key, value in values.items():
            setattr(job, key, value)
        await record_event(
            tenant,
            actor=Actor.system(),
            action=action,
            resource_type="job",
            resource_id=job_id,
            context=_context(),
            details=details,
        )
        await session.commit()


async def run_job(ctx: WorkerContext, job_id: uuid.UUID, org_id: uuid.UUID) -> Outcome:
    settings = ctx.settings
    async with ctx.session_factory() as session:
        job = await _claim(ctx, session, job_id, org_id)
        if job is None:
            await session.rollback()
            return Outcome("noop", "job is missing, locked by another worker, or no longer queued")
        params = CKKSParams.from_dict(job.plan["params"])
        weight = job_weight(params.poly_modulus_degree)
        if not await ctx.semaphore.acquire(org_id, job_id, weight):
            # read what we need *before* the rollback expires the row
            waited = (utcnow() - job.created_at).total_seconds()
            operation = job.operation
            await session.rollback()
            TENANT_THROTTLED.labels(organization=str(org_id)).inc()
            if waited > settings.max_queue_wait_seconds:
                await _finish(
                    ctx,
                    job_id,
                    org_id,
                    status=JobStatus.FAILED,
                    action=AuditAction.JOB_FAILED,
                    values={
                        "error": {"code": "starved", "message": "job waited too long for a free slot"},
                        "finished_at": utcnow(),
                    },
                    details={"code": "starved"},
                )
                JOBS_FINISHED.labels(operation, "failed", str(org_id)).inc()
                return Outcome("failed", "starved")
            return Outcome("throttled", "tenant at its concurrency limit", countdown=2.0 + random.random() * 3)  # noqa: S311
        job.status = JobStatus.RUNNING
        job.attempts += 1
        job.started_at = utcnow()
        job.worker_id = ctx.worker_id
        attempts = job.attempts
        operation = job.operation
        created_at = job.created_at
        tenant = TenantScopedSession(session, org_id)
        await record_event(
            tenant,
            actor=Actor.system(),
            action=AuditAction.JOB_STARTED,
            resource_type="job",
            resource_id=job_id,
            context=_context(),
            details={"attempt": attempts, "worker_id": ctx.worker_id},
        )
        await session.commit()
        if attempts == 1:
            JOB_QUEUE_WAIT_SECONDS.observe((utcnow() - created_at).total_seconds())

    started = time.perf_counter()
    WORKERS_BUSY.inc()
    try:
        result = await _compute(ctx, job_id, org_id, params)
        elapsed = time.perf_counter() - started
        await _finish(
            ctx,
            job_id,
            org_id,
            status=JobStatus.SUCCEEDED,
            action=AuditAction.JOB_COMPLETED,
            values={**result, "error": None, "finished_at": utcnow(), "compute_seconds": round(elapsed, 4)},
            details={
                "result_fingerprint": result["result_fingerprint"],
                "levels_consumed": result["depth_report"]["levels_consumed"],
            },
        )
        JOB_COMPUTE_SECONDS.labels(operation, str(params.poly_modulus_degree)).observe(elapsed)
        JOB_END_TO_END_SECONDS.labels(operation).observe((utcnow() - created_at).total_seconds())
        LEVELS_CONSUMED_RATIO.labels(operation).observe(
            result["depth_report"]["levels_consumed"] / max(1, params.depth)
        )
        JOBS_FINISHED.labels(operation, "succeeded", str(org_id)).inc()
        log.info("job_succeeded", job_id=str(job_id), operation=operation, seconds=round(elapsed, 3))
        return Outcome("succeeded")
    except JobFailedError as exc:
        return await _fail(ctx, job_id, org_id, operation, exc.code, exc.message, exc.details)
    except CipherComputeError as exc:
        return await _fail(ctx, job_id, org_id, operation, exc.code, exc.message, exc.details)
    except TRANSIENT_ERRORS as exc:
        if attempts >= settings.worker_max_attempts:
            return await _fail(
                ctx,
                job_id,
                org_id,
                operation,
                "retries_exhausted",
                f"gave up after {attempts} attempts: {type(exc).__name__}",
                {},
            )
        countdown = backoff_seconds(settings, attempts)
        JOB_RETRIES.labels(reason=type(exc).__name__).inc()
        log.warning(
            "job_retry", job_id=str(job_id), attempt=attempts, error=type(exc).__name__, countdown=round(countdown, 2)
        )
        async with ctx.session_factory() as session:
            job_row = await TenantScopedSession(session, org_id).get(Job, job_id)
            if job_row is not None:
                job_row.status = JobStatus.QUEUED
                job_row.error = {"code": "transient", "message": type(exc).__name__, "attempt": attempts}
                await session.commit()
        return Outcome("retry", type(exc).__name__, countdown=countdown)
    except Exception as exc:
        code = "time_limit_exceeded" if type(exc).__name__ == "SoftTimeLimitExceeded" else "execution_error"
        log.exception("job_failed_unexpectedly", job_id=str(job_id), code=code)
        return await _fail(
            ctx, job_id, org_id, operation, code, "the computation failed", {"exception": type(exc).__name__}
        )
    finally:
        WORKERS_BUSY.dec()
        await ctx.semaphore.release(org_id, job_id, weight)


async def _fail(
    ctx: WorkerContext,
    job_id: uuid.UUID,
    org_id: uuid.UUID,
    operation: str,
    code: str,
    message: str,
    details: dict[str, Any],
) -> Outcome:
    await _finish(
        ctx,
        job_id,
        org_id,
        status=JobStatus.FAILED,
        action=AuditAction.JOB_FAILED,
        values={"error": {"code": code, "message": message, "details": details}, "finished_at": utcnow()},
        details={"code": code},
    )
    JOBS_FINISHED.labels(operation, "failed", str(org_id)).inc()
    log.warning("job_failed", job_id=str(job_id), code=code)
    return Outcome("failed", code)


async def _compute(ctx: WorkerContext, job_id: uuid.UUID, org_id: uuid.UUID, params: CKKSParams) -> dict[str, Any]:
    async with ctx.session_factory() as session:
        tenant = TenantScopedSession(session, org_id)
        job = await tenant.get(Job, job_id)
        if job is None:
            raise JobFailedError("job_missing", "job disappeared")
        bundle_row = await tenant.get(KeyBundle, job.key_bundle_id)
        if bundle_row is None or bundle_row.status != KeyBundleStatus.ACTIVE:
            raise JobFailedError("bundle_revoked", "the key bundle was revoked or deleted before the job ran")
        input_ids = [uuid.UUID(str(i)) for i in job.input_ids]
        rows = {c.id: c for c in await tenant.scalars(tenant.select(Ciphertext).where(Ciphertext.id.in_(input_ids)))}
        expected_fps = [str(fp) for fp in job.input_fingerprints]
        operation, args = job.operation, dict(job.args)
        planned_levels = int(job.plan["report"]["levels_consumed"])
        project_id = job.project_id

    bundle = await ctx.bundle(bundle_row)
    if bundle.params != params:
        raise JobFailedError("bundle_integrity", "job parameters do not match the key bundle")
    inputs: list[EncryptedVector] = []
    for ct_id, expected in zip(input_ids, expected_fps, strict=True):
        row = rows.get(ct_id)
        if row is None or row.status != CiphertextStatus.READY:
            raise JobFailedError(
                "input_missing", "an input ciphertext was deleted before the job ran", ciphertext_id=str(ct_id)
            )
        data = await ctx.store.get_bytes(row.object_key, org_id, max_bytes=ctx.settings.max_ciphertext_bytes)
        CIPHERTEXT_INPUT_BYTES.observe(len(data))
        # [TM:T-2] The bytes must be exactly what the client uploaded and the job committed to.
        if sha256_fingerprint(data) != expected:
            raise JobFailedError(
                "input_integrity",
                "input ciphertext does not match the fingerprint recorded at upload",
                ciphertext_id=str(ct_id),
            )
        inputs.append(await asyncio.to_thread(EncryptedVector.load, bundle, data))

    # Re-plan against the levels the ciphertexts *actually* carry (the API saw headers only).
    plan(
        params,
        [(operation, args)],
        input_lengths=[ev.length for ev in inputs],
        initial_levels_consumed=max(ev.levels_consumed for ev in inputs),
    )
    out = await asyncio.to_thread(apply_operation, operation, bundle, inputs, args)
    if out.levels_consumed != planned_levels:
        raise JobFailedError(
            "depth_mismatch", f"result consumed {out.levels_consumed} levels but the plan promised {planned_levels}"
        )
    payload = out.to_bytes()
    key = ObjectStore.key_for_result(org_id, project_id, job_id)
    await ctx.store.put_bytes(key, org_id, payload)
    RESULT_BYTES.observe(len(payload))
    return {
        "result_object_key": key,
        "result_fingerprint": sha256_fingerprint(payload),
        "result_length": out.length,
        "result_size_bytes": len(payload),
        "depth_report": out.depth_report().to_dict(),
    }
