#!/usr/bin/env python3
"""Run the whole CipherCompute backend locally with no Docker and no external services.

    python scripts/devstack.py            # API on http://127.0.0.1:8000, S3 on http://127.0.0.1:9000

What runs, all in one process:

* the real FastAPI application (``ciphercompute_api``) on uvicorn;
* the real job executor (``ciphercompute_worker.executor.run_job``) draining an in-process queue;
* SQLite instead of PostgreSQL, fakeredis instead of Redis, and a moto S3 server instead of
  S3/MinIO — the same code paths, local stand-ins for the infrastructure.

This is for development, demos and the README quickstart. Production uses docker-compose / Helm
with PostgreSQL 16, Redis 7 and S3 (see infra/).
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import os
import secrets
import sys
import uuid
from pathlib import Path

import fakeredis
import uvicorn
from moto.server import ThreadedMotoServer
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import NullPool

from ciphercompute_api.app import create_app
from ciphercompute_api.config import Settings
from ciphercompute_api.db.base import Base, make_session_factory
from ciphercompute_api.logging import get_logger
from ciphercompute_api.queue import MemoryQueue
from ciphercompute_api.storage.objects import ObjectStore
from ciphercompute_worker.concurrency import TenantSemaphore
from ciphercompute_worker.config import WorkerSettings
from ciphercompute_worker.executor import WorkerContext, run_job

log = get_logger("devstack")


class DrainingQueue(MemoryQueue):
    """In-process queue whose jobs are executed by the real worker code."""

    def __init__(self) -> None:
        super().__init__()
        self.wakeup = asyncio.Event()

    async def enqueue(self, job_id: uuid.UUID, organization_id: uuid.UUID) -> None:
        await super().enqueue(job_id, organization_id)
        self.wakeup.set()


async def worker_loop(queue: DrainingQueue, ctx: WorkerContext) -> None:
    while True:
        await queue.wakeup.wait()
        queue.wakeup.clear()
        while queue.items:
            job_id, org_id = queue.items.pop(0)
            outcome = await run_job(ctx, job_id, org_id)
            if outcome.kind in ("retry", "throttled"):
                await asyncio.sleep(outcome.countdown)
                await queue.enqueue(job_id, org_id)
            log.info("devstack_job", job_id=str(job_id), outcome=outcome.kind, detail=outcome.detail)


async def main_async(ns: argparse.Namespace) -> None:
    data_dir = Path(ns.data_dir).resolve()
    data_dir.mkdir(parents=True, exist_ok=True)
    s3 = ThreadedMotoServer(ip_address="127.0.0.1", port=ns.s3_port, verbose=False)
    s3.start()
    endpoint = f"http://127.0.0.1:{ns.s3_port}"
    os.environ.setdefault("AWS_ACCESS_KEY_ID", "devstack")
    os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "devstack")
    database_url = f"sqlite+aiosqlite:///{(data_dir / 'ciphercompute.db').as_posix()}"
    settings = Settings(
        env="dev",
        jwt_secret=os.environ.get("CC_JWT_SECRET") or secrets.token_urlsafe(48),
        database_url=database_url,
        queue_backend="memory",
        s3_bucket="ciphercompute-dev",
        s3_endpoint_url=endpoint,
        cors_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
        job_poll_interval_seconds=0.5,
        argon2_memory_kib=19456,  # OWASP minimum; the production default is 64 MiB
    )
    engine = create_async_engine(database_url, poolclass=NullPool)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    redis = fakeredis.FakeAsyncRedis()
    store = ObjectStore(settings)
    queue = DrainingQueue()
    app = create_app(settings, redis=redis, store=store, queue=queue)
    ctx = WorkerContext(
        settings=WorkerSettings(database_url=database_url, s3_bucket=settings.s3_bucket, s3_endpoint_url=endpoint),
        session_factory=make_session_factory(engine),
        store=store,
        semaphore=TenantSemaphore(redis, 4, 900),
    )
    worker = asyncio.create_task(worker_loop(queue, ctx))
    print(
        "CipherCompute dev stack\n"
        f"  API      http://{ns.host}:{ns.port}  (docs at /docs)\n"
        f"  S3       {endpoint}\n"
        f"  data     {data_dir}",
        flush=True,
    )
    server = uvicorn.Server(uvicorn.Config(app, host=ns.host, port=ns.port, log_level="warning"))
    try:
        await server.serve()
    finally:
        worker.cancel()
        s3.stop()
        await engine.dispose()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--s3-port", type=int, default=9000)
    parser.add_argument("--data-dir", default=".devstack")
    ns = parser.parse_args()
    with contextlib.suppress(KeyboardInterrupt):
        asyncio.run(main_async(ns))
    return 0


if __name__ == "__main__":
    sys.exit(main())
