"""Celery task: a thin, synchronous shell around :func:`executor.run_job`."""

from __future__ import annotations

import asyncio
import uuid
from collections import OrderedDict

from celery import Task
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import NullPool

from ciphercompute_api.db.base import make_session_factory
from ciphercompute_api.storage.objects import ObjectStore
from ciphercompute_core import PublicKeyBundle

from .celery_app import app, settings
from .concurrency import TenantSemaphore
from .executor import Outcome, WorkerContext, run_job

# Process-wide: boto3 clients are thread-safe and bundles are expensive to load.
_store: ObjectStore | None = None
_bundle_cache: OrderedDict[str, PublicKeyBundle] = OrderedDict()


async def _run(job_id: uuid.UUID, organization_id: uuid.UUID) -> Outcome:
    """Each task gets its own event loop (asyncio.run), so connections must not outlive it."""
    global _store
    _store = _store or ObjectStore(settings)
    engine = create_async_engine(settings.database_url, poolclass=NullPool)
    redis = Redis.from_url(settings.redis_url)
    try:
        ctx = WorkerContext(
            settings=settings,
            session_factory=make_session_factory(engine),
            store=_store,
            semaphore=TenantSemaphore(redis, settings.tenant_max_concurrent_jobs, settings.tenant_slot_lease_seconds),
            bundle_cache=_bundle_cache,
        )
        return await run_job(ctx, job_id, organization_id)
    finally:
        await redis.aclose()
        await engine.dispose()


@app.task(bind=True, name=settings.celery_task_name, max_retries=None)
def execute_job(self: Task, job_id: str, organization_id: str) -> dict[str, str]:
    outcome = asyncio.run(_run(uuid.UUID(job_id), uuid.UUID(organization_id)))
    if outcome.kind in ("retry", "throttled"):
        # Celery re-publishes the same message (same task id = job id) after the countdown.
        raise self.retry(countdown=outcome.countdown)
    return {"job_id": job_id, "outcome": outcome.kind, "detail": outcome.detail}
