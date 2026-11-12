"""Usage and billing metrics for the caller's organization."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.base import utcnow
from ..db.models import Ciphertext, Job, KeyBundle
from ..deps import Principal, db_session, require

router = APIRouter(prefix="/v1/usage", tags=["usage"])


@router.get("")
async def usage(
    days: int = Query(30, ge=1, le=365),
    principal: Principal = Depends(require("jobs:read")),
    session: AsyncSession = Depends(db_session),
) -> dict[str, Any]:
    org = principal.organization_id
    since = utcnow() - timedelta(days=days)

    status_rows = (
        await session.execute(
            select(Job.status, func.count())
            .where(Job.organization_id == org, Job.created_at >= since)
            .group_by(Job.status)
        )
    ).all()
    by_status = {status: int(count) for status, count in status_rows}
    by_operation = (
        await session.execute(
            select(Job.operation, func.count(), func.coalesce(func.sum(Job.compute_seconds), 0.0))
            .where(Job.organization_id == org, Job.created_at >= since)
            .group_by(Job.operation)
        )
    ).all()
    jobs = list(
        await session.scalars(select(Job.created_at).where(Job.organization_id == org, Job.created_at >= since))
    )
    daily: dict[str, int] = {}
    for created in jobs:
        day = created.date().isoformat()
        daily[day] = daily.get(day, 0) + 1
    ct_bytes = (
        await session.execute(
            select(func.coalesce(func.sum(Ciphertext.size_bytes), 0)).where(Ciphertext.organization_id == org)
        )
    ).scalar_one()
    bundle_bytes = (
        await session.execute(
            select(func.coalesce(func.sum(KeyBundle.size_bytes), 0)).where(KeyBundle.organization_id == org)
        )
    ).scalar_one()
    result_bytes = (
        await session.execute(
            select(func.coalesce(func.sum(Job.result_size_bytes), 0)).where(Job.organization_id == org)
        )
    ).scalar_one()
    compute = sum(float(row[2] or 0.0) for row in by_operation)
    return {
        "window_days": days,
        "jobs_by_status": {getattr(k, "value", str(k)): int(v) for k, v in by_status.items()},
        "jobs_by_operation": [
            {"operation": op, "jobs": int(n), "compute_seconds": round(float(s or 0.0), 3)} for op, n, s in by_operation
        ],
        "jobs_per_day": [{"date": d, "jobs": n} for d, n in sorted(daily.items())],
        "compute_seconds": round(compute, 3),
        "storage_bytes": {
            "ciphertexts": int(ct_bytes or 0),
            "key_bundles": int(bundle_bytes or 0),
            "results": int(result_bytes or 0),
            "total": int(ct_bytes or 0) + int(bundle_bytes or 0) + int(result_bytes or 0),
        },
    }
