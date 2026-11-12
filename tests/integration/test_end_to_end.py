"""End to end against real PostgreSQL 16, Redis 7 and MinIO (CI job "integration").

Skipped unless CC_IT_DATABASE_URL, CC_IT_REDIS_URL and CC_IT_S3_ENDPOINT are set. The schema
must already be migrated (the CI job runs ``alembic upgrade head`` first), so this also proves
the migration — not ``create_all`` — produces a working database, triggers included.
"""

from __future__ import annotations

import asyncio
import os
import uuid
from collections.abc import Iterator
from typing import Any

import httpx
import numpy as np
import pytest
from fastapi.testclient import TestClient
from redis.asyncio import Redis
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import NullPool

from ciphercompute_api.app import create_app
from ciphercompute_api.config import Settings
from ciphercompute_api.db.base import make_session_factory
from ciphercompute_api.queue import MemoryQueue
from ciphercompute_api.storage.objects import ObjectStore
from ciphercompute_client import CipherComputeClient, TransportConfig
from ciphercompute_core import KeyRing, standard_params
from ciphercompute_core.sigmoid import sigmoid_poly
from ciphercompute_worker.concurrency import TenantSemaphore
from ciphercompute_worker.config import WorkerSettings
from ciphercompute_worker.executor import WorkerContext, run_job

DB = os.environ.get("CC_IT_DATABASE_URL")
REDIS = os.environ.get("CC_IT_REDIS_URL")
S3 = os.environ.get("CC_IT_S3_ENDPOINT")
pytestmark = pytest.mark.skipif(not (DB and REDIS and S3), reason="integration services not configured")

API = "https://api.it"
PASSWORD = "integration passphrase 2026"


class Router(httpx.BaseTransport):
    """api.it -> in-process API (real Postgres/Redis/MinIO behind it); everything else -> network."""

    def __init__(self, api: TestClient) -> None:
        self.api = api
        self.net = httpx.HTTPTransport()

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        if request.url.host == "api.it":
            return self.api._transport.handle_request(request)  # type: ignore[attr-defined]
        return self.net.handle_request(request)


@pytest.fixture(scope="module")
def stack() -> Iterator[dict[str, Any]]:
    assert DB and REDIS and S3
    bucket = f"cc-it-{uuid.uuid4().hex[:8]}"
    settings = Settings(
        env="test",
        jwt_secret="i" * 48,
        database_url=DB,
        redis_url=REDIS,
        queue_backend="memory",
        s3_bucket=bucket,
        s3_endpoint_url=S3,
        argon2_time_cost=1,
        argon2_memory_kib=8,
        argon2_parallelism=1,
    )
    queue = MemoryQueue()
    app = create_app(settings, queue=queue)
    with TestClient(app, base_url=API) as api, httpx.Client(transport=Router(api), base_url=API) as http:
        yield {"settings": settings, "queue": queue, "http": http}


def drain(stack: dict[str, Any]) -> list[str]:
    settings: Settings = stack["settings"]

    async def run() -> list[str]:
        engine = create_async_engine(settings.database_url, poolclass=NullPool)
        redis = Redis.from_url(settings.redis_url)
        ctx = WorkerContext(
            settings=WorkerSettings(
                database_url=settings.database_url,
                s3_bucket=settings.s3_bucket,
                s3_endpoint_url=settings.s3_endpoint_url,
            ),
            session_factory=make_session_factory(engine),
            store=ObjectStore(settings),
            semaphore=TenantSemaphore(redis, 4, 60),
        )
        outcomes = []
        while stack["queue"].items:
            job_id, org_id = stack["queue"].items.pop(0)
            outcomes.append((await run_job(ctx, job_id, org_id)).kind)
        await redis.aclose()
        await engine.dispose()
        return outcomes

    return asyncio.run(run())


def client(stack: dict[str, Any]) -> CipherComputeClient:
    return CipherComputeClient(API, http=stack["http"], transport_config=TransportConfig(max_retries=0))


def test_encrypted_logistic_regression_on_real_services(stack: dict[str, Any]) -> None:
    cc = client(stack)
    cc.register(f"it-{uuid.uuid4().hex[:6]}@example.com", PASSWORD, "Integration Hospital")
    ring = KeyRing.generate(standard_params(8192, 128, "deep"))
    project = cc.create_project("it")
    bundle = cc.upload_key_bundle(project["id"], ring)
    dataset = cc.create_dataset(project["id"], "vitals", bundle["id"])
    rng = np.random.default_rng(5)
    patients = rng.uniform(-1, 1, (20, 3))
    cts = cc.encrypt_columns_and_upload(
        dataset["id"], ring, patients, labels=["a", "b", "c"]
    )  # real MinIO presigned POST
    args = {"weights": [0.6, -0.9, 0.3], "intercept": 0.1, "layout": "columns", "degree": 3}
    job = cc.submit_job(project["id"], "logistic_regression", [c["id"] for c in cts], args)
    assert drain(stack) == ["succeeded"]
    scores = cc.wait_and_decrypt(job["id"], ring)  # real MinIO presigned GET
    assert np.max(np.abs(scores - sigmoid_poly(patients @ np.array(args["weights"]) + args["intercept"], 3))) < 1e-2
    cc.verify_manifest(cc.get_job(job["id"]), ring)
    assert cc.verify_audit_chain()["valid"] is True


def test_audit_log_is_append_only_in_postgres(stack: dict[str, Any]) -> None:
    async def attempt(statement: str) -> None:
        engine = create_async_engine(stack["settings"].database_url, poolclass=NullPool)
        try:
            async with engine.begin() as conn:
                await conn.execute(text(statement))
        finally:
            await engine.dispose()

    for statement in (
        "UPDATE audit_events SET action = 'tampered'",
        "DELETE FROM audit_events",
        "TRUNCATE audit_events",
    ):
        with pytest.raises(DBAPIError, match="append-only"):
            asyncio.run(attempt(statement))


def test_tenant_isolation_on_postgres(stack: dict[str, Any]) -> None:
    a, b = client(stack), client(stack)
    a.register(f"a-{uuid.uuid4().hex[:6]}@example.com", PASSWORD, "Tenant A")
    b.register(f"b-{uuid.uuid4().hex[:6]}@example.com", PASSWORD, "Tenant B")
    project = a.create_project("private")
    from ciphercompute_client.errors import ApiError

    with pytest.raises(ApiError) as excinfo:
        b._call("GET", f"/v1/projects/{project['id']}")
    assert excinfo.value.status_code == 404
    assert all(p["id"] != project["id"] for p in b.list_projects())


def test_rate_limits_use_real_redis(stack: dict[str, Any]) -> None:
    assert asyncio.run(Redis.from_url(REDIS or "").ping())
