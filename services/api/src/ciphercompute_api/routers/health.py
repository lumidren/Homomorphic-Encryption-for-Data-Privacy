"""Liveness, readiness and Prometheus metrics."""

from __future__ import annotations

import asyncio
from typing import Any

from fastapi import APIRouter, Request, Response
from fastapi.responses import JSONResponse
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from sqlalchemy import func, select, text

from ..db.models import Job, JobStatus
from ..deps import get_state
from ..telemetry import QUEUE_DEPTH, registry

router = APIRouter(tags=["health"])


@router.get("/healthz", include_in_schema=True, summary="Liveness: the process is up")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


async def _check(coro: Any, timeout: float = 2.0) -> bool:
    try:
        return bool(await asyncio.wait_for(coro, timeout))
    except Exception:
        return False


@router.get("/readyz", summary="Readiness: dependencies reachable and not draining")
async def readyz(request: Request) -> JSONResponse:
    state = get_state(request)

    async def db() -> bool:
        async with state.session_factory() as session:
            await session.execute(text("SELECT 1"))
        return True

    checks = {
        "database": await _check(db()),
        "redis": await _check(state.redis.ping()),
        "object_storage": await _check(state.store.ping()),
        "queue": await _check(state.queue.ping()),
    }
    ready = all(checks.values()) and not state.draining
    return JSONResponse(
        status_code=200 if ready else 503,
        content={"status": "ready" if ready else "not_ready", "draining": state.draining, "checks": checks},
    )


@router.get("/metrics", include_in_schema=False)
async def metrics(request: Request) -> Response:
    state = get_state(request)
    try:
        async with state.session_factory() as session:
            depth = (
                await session.execute(select(func.count()).select_from(Job).where(Job.status == JobStatus.QUEUED))
            ).scalar_one()
        QUEUE_DEPTH.set(int(depth))
    except Exception:  # noqa: S110 - metrics must render even when the DB is down
        pass
    return Response(generate_latest(registry), media_type=CONTENT_TYPE_LATEST)
