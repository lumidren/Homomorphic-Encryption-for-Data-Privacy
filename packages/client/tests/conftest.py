"""SDK test harness: the real API, a fake S3 front end over moto, and the real worker executor.

A single synchronous ``httpx.Client`` routes by host:

* ``api.test``           -> the FastAPI app (via Starlette's TestClient transport, lifespan on)
* ``s3.amazonaws.com``   -> a tiny S3 front end that honours presigned POST policies and serves
                            presigned GETs, backed by moto's in-memory S3

The API's job queue is in-memory; ``drain()`` runs every queued job through the worker's
``run_job`` against the same database and bucket, as a deployed worker would.
"""

from __future__ import annotations

import asyncio
import base64
import json
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import boto3
import fakeredis
import httpx
import pytest
from botocore.client import Config
from fastapi.testclient import TestClient
from moto import mock_aws
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import NullPool
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import PlainTextResponse, Response
from starlette.routing import Route

from ciphercompute_api.app import create_app
from ciphercompute_api.config import Settings
from ciphercompute_api.db.base import Base, make_session_factory
from ciphercompute_api.queue import MemoryQueue
from ciphercompute_api.storage.objects import ObjectStore
from ciphercompute_client import CipherComputeClient, TransportConfig
from ciphercompute_core import KeyRing, standard_params
from ciphercompute_worker.concurrency import TenantSemaphore
from ciphercompute_worker.config import WorkerSettings
from ciphercompute_worker.executor import WorkerContext, run_job

API = "https://api.test"
BUCKET = "cc-test"
PASSWORD = "correct horse battery staple"


def fake_s3_app() -> Starlette:
    s3 = boto3.client(
        "s3", region_name="us-east-1", config=Config(s3={"addressing_style": "path"}, signature_version="s3v4")
    )

    async def post_object(request: Request) -> Response:
        form = await request.form()
        policy = json.loads(base64.b64decode(str(form["policy"])))
        upload = form["file"]
        body = await upload.read()  # type: ignore[union-attr]
        for cond in policy["conditions"]:
            if isinstance(cond, list) and cond[0] == "content-length-range" and not cond[1] <= len(body) <= cond[2]:
                return PlainTextResponse("EntityTooLarge", status_code=400)
        s3.put_object(
            Bucket=request.path_params["bucket"],
            Key=str(form["key"]),
            Body=body,
            ServerSideEncryption=str(form["x-amz-server-side-encryption"]),
        )
        return Response(status_code=204)

    async def get_object(request: Request) -> Response:
        if "X-Amz-Signature" not in request.query_params:
            return PlainTextResponse("AccessDenied", status_code=403)
        obj = s3.get_object(Bucket=request.path_params["bucket"], Key=request.path_params["key"])
        return Response(obj["Body"].read(), media_type="application/octet-stream")

    return Starlette(
        routes=[
            Route("/{bucket}", post_object, methods=["POST"]),
            Route("/{bucket}/{key:path}", get_object, methods=["GET"]),
        ]
    )


class RoutingTransport(httpx.BaseTransport):
    def __init__(self, api: TestClient, storage: TestClient) -> None:
        self.api, self.storage = api, storage
        self.seen: list[httpx.Request] = []

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        self.seen.append(request)
        target = self.api if request.url.host == "api.test" else self.storage
        return target._transport.handle_request(request)  # type: ignore[attr-defined]


@dataclass
class Stack:
    http: httpx.Client
    transport: RoutingTransport
    queue: MemoryQueue
    settings: Settings
    tmp: Path

    def client(self, **kwargs: Any) -> CipherComputeClient:
        return CipherComputeClient(API, http=self.http, transport_config=TransportConfig(max_retries=0), **kwargs)

    def drain(self) -> list[str]:
        """Run every queued job through the real worker executor; return the outcomes."""
        outcomes: list[str] = []

        async def _run_all() -> None:
            engine = create_async_engine(self.settings.database_url, poolclass=NullPool)
            ctx = WorkerContext(
                settings=WorkerSettings(database_url=self.settings.database_url, s3_bucket=BUCKET),
                session_factory=make_session_factory(engine),
                store=ObjectStore(self.settings),
                semaphore=TenantSemaphore(fakeredis.FakeAsyncRedis(), 8, 60),
            )
            while self.queue.items:
                job_id, org_id = self.queue.items.pop(0)
                outcomes.append((await run_job(ctx, job_id, org_id)).kind)
            await engine.dispose()

        asyncio.run(_run_all())
        return outcomes


@pytest.fixture(scope="session")
def ring() -> KeyRing:
    return KeyRing.generate(standard_params(8192, 128))


@pytest.fixture(scope="session")
def deep_ring() -> KeyRing:
    return KeyRing.generate(standard_params(8192, 128, "deep"))


@pytest.fixture
def stack(tmp_path: Path) -> Iterator[Stack]:
    with mock_aws():
        settings = Settings(
            env="test",
            jwt_secret="c" * 48,
            database_url=f"sqlite+aiosqlite:///{(tmp_path / 'cc.db').as_posix()}",
            queue_backend="memory",
            argon2_time_cost=1,
            argon2_memory_kib=8,
            argon2_parallelism=1,
            s3_bucket=BUCKET,
            rate_limit_per_minute=100_000,
            job_poll_interval_seconds=0.05,
        )

        async def _schema() -> None:
            engine = create_async_engine(settings.database_url, poolclass=NullPool)
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
            await engine.dispose()

        asyncio.run(_schema())
        queue = MemoryQueue()
        app = create_app(settings, redis=fakeredis.FakeAsyncRedis(), store=ObjectStore(settings), queue=queue)
        with TestClient(app, base_url=API) as api, TestClient(fake_s3_app()) as storage:
            transport = RoutingTransport(api, storage)
            with httpx.Client(transport=transport, base_url=API) as http:
                yield Stack(http, transport, queue, settings, tmp_path)


@pytest.fixture
def user(stack: Stack) -> CipherComputeClient:
    client = stack.client()
    client.register(f"sdk-{uuid.uuid4().hex[:8]}@example.com", PASSWORD, "SDK Org")
    return client
