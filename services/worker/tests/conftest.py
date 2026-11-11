"""Worker test harness.

Jobs are created through the real API (in-process, SQLite + fakeredis + moto S3); the executor
then runs against the very same database and bucket, exactly as the deployed worker would.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import fakeredis
import httpx
import pytest
from moto import mock_aws

from ciphercompute_api.app import create_app
from ciphercompute_api.config import Settings
from ciphercompute_api.db.base import Base, make_engine, make_session_factory
from ciphercompute_api.queue import MemoryQueue
from ciphercompute_api.storage.objects import ObjectStore
from ciphercompute_core import EncryptedVector, KeyRing, standard_params
from ciphercompute_worker.concurrency import TenantSemaphore
from ciphercompute_worker.config import WorkerSettings
from ciphercompute_worker.executor import WorkerContext

PASSWORD = "correct horse battery staple"


@pytest.fixture(scope="session")
def ring() -> KeyRing:
    return KeyRing.generate(standard_params(8192, 128))


@pytest.fixture(scope="session")
def deep_ring() -> KeyRing:
    return KeyRing.generate(standard_params(8192, 128, "deep"))


@dataclass
class Env:
    client: httpx.AsyncClient
    store: ObjectStore
    ctx: WorkerContext
    redis: Any
    token: str = ""
    org_id: str = ""
    project_id: str = ""

    def headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.token}"}

    async def bundle(self, ring: KeyRing) -> str:
        resp = await self.client.post(
            f"/v1/projects/{self.project_id}/key-bundles",
            content=ring.public_bundle().to_bytes(),
            headers={**self.headers(), "Content-Type": "application/octet-stream"},
        )
        assert resp.status_code == 201, resp.text
        return resp.json()["id"]  # type: ignore[no-any-return]

    async def dataset(self, bundle_id: str, name: str = "vitals") -> str:
        resp = await self.client.post(
            f"/v1/projects/{self.project_id}/datasets",
            json={"name": name, "key_bundle_id": bundle_id},
            headers=self.headers(),
        )
        assert resp.status_code == 201, resp.text
        return resp.json()["id"]  # type: ignore[no-any-return]

    async def ciphertext(self, dataset_id: str, ev: EncryptedVector, label: str = "x") -> dict[str, Any]:
        data = ev.to_bytes()
        created = (
            await self.client.post(
                f"/v1/datasets/{dataset_id}/ciphertexts",
                json={"label": label, "size_bytes": len(data)},
                headers=self.headers(),
            )
        ).json()["ciphertext"]
        await self.store.put_bytes(self.object_key(dataset_id, created["id"]), uuid.UUID(self.org_id), data)
        resp = await self.client.post(f"/v1/ciphertexts/{created['id']}/confirm", headers=self.headers())
        assert resp.status_code == 200, resp.text
        return resp.json()  # type: ignore[no-any-return]

    def object_key(self, dataset_id: str, ciphertext_id: str) -> str:
        return ObjectStore.key_for_ciphertext(
            uuid.UUID(self.org_id), uuid.UUID(self.project_id), uuid.UUID(dataset_id), uuid.UUID(ciphertext_id)
        )

    async def submit(self, operation: str, inputs: list[str], args: dict[str, Any] | None = None) -> dict[str, Any]:
        resp = await self.client.post(
            f"/v1/projects/{self.project_id}/jobs",
            json={"operation": operation, "inputs": inputs, "args": args or {}},
            headers=self.headers(),
        )
        assert resp.status_code == 202, resp.text
        return resp.json()  # type: ignore[no-any-return]

    async def job(self, job_id: str) -> dict[str, Any]:
        return (await self.client.get(f"/v1/jobs/{job_id}", headers=self.headers())).json()  # type: ignore[no-any-return]

    async def result(self, ring: KeyRing, job_id: str) -> EncryptedVector:
        job = await self.job(job_id)
        key = ObjectStore.key_for_result(uuid.UUID(self.org_id), uuid.UUID(self.project_id), uuid.UUID(job_id))
        data = await self.store.get_bytes(key, uuid.UUID(self.org_id), max_bytes=1 << 30)
        assert job["result_fingerprint"] == "sha256:" + __import__("hashlib").sha256(data).hexdigest()
        return EncryptedVector.load(ring, data)


def worker_settings(tmp_path: Path, **overrides: Any) -> WorkerSettings:
    values: dict[str, Any] = {
        "env": "test",
        "database_url": f"sqlite+aiosqlite:///{(tmp_path / 'cc.db').as_posix()}",
        "s3_bucket": "cc-test",
        "tenant_max_concurrent_jobs": 4,
        "retry_backoff_base_seconds": 1.0,
        "worker_max_attempts": 3,
    }
    values.update(overrides)
    return WorkerSettings(**values)


async def build_env(tmp_path: Path, **worker_overrides: Any) -> AsyncIterator[Env]:
    with mock_aws():
        wsettings = worker_settings(tmp_path, **worker_overrides)
        api_settings = Settings(
            env="test",
            jwt_secret="w" * 48,
            database_url=wsettings.database_url,
            queue_backend="memory",
            argon2_time_cost=1,
            argon2_memory_kib=8,
            argon2_parallelism=1,
            s3_bucket="cc-test",
            rate_limit_per_minute=100_000,
        )
        engine = make_engine(wsettings.database_url)
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        redis = fakeredis.FakeAsyncRedis()
        store = ObjectStore(api_settings)
        app = create_app(api_settings, redis=redis, store=store, queue=MemoryQueue())
        async with app.router.lifespan_context(app):
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
                ctx = WorkerContext(
                    settings=wsettings,
                    session_factory=make_session_factory(engine),
                    store=store,
                    semaphore=TenantSemaphore(
                        redis, wsettings.tenant_max_concurrent_jobs, wsettings.tenant_slot_lease_seconds
                    ),
                )
                env = Env(client=client, store=store, ctx=ctx, redis=redis)
                email = f"w-{uuid.uuid4().hex[:8]}@example.com"
                reg = (
                    await client.post(
                        "/v1/auth/register",
                        json={"email": email, "password": PASSWORD, "organization_name": "Worker Org"},
                    )
                ).json()
                env.token, env.org_id = reg["access_token"], reg["organization_id"]
                env.project_id = (await client.post("/v1/projects", json={"name": "p"}, headers=env.headers())).json()[
                    "id"
                ]
                yield env
        await engine.dispose()


@pytest.fixture
async def env(tmp_path: Path) -> AsyncIterator[Env]:
    async for e in build_env(tmp_path):
        yield e
