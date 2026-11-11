"""In-process test harness: SQLite (aiosqlite), fakeredis and moto-mocked S3.

The real dependencies (PostgreSQL 16, Redis 7, MinIO) are exercised by the integration job in
CI against docker-compose; everything here runs without external services.
"""

from __future__ import annotations

import io
import logging
import uuid
from collections.abc import AsyncIterator, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import fakeredis
import httpx
import pytest
from moto import mock_aws

from ciphercompute_api.app import create_app
from ciphercompute_api.config import Settings
from ciphercompute_api.db.base import Base, make_engine
from ciphercompute_api.queue import MemoryQueue
from ciphercompute_api.storage.objects import ObjectStore
from ciphercompute_core import EncryptedVector, KeyRing, standard_params

JWT_SECRET = "test-secret-" + "x" * 40
PASSWORD = "correct horse battery staple"


def make_settings(tmp_path: Path, **overrides: Any) -> Settings:
    base: dict[str, Any] = {
        "env": "test",
        "jwt_secret": JWT_SECRET,
        "database_url": f"sqlite+aiosqlite:///{(tmp_path / 'cc.db').as_posix()}",
        "queue_backend": "memory",
        "argon2_time_cost": 1,
        "argon2_memory_kib": 8,
        "argon2_parallelism": 1,
        "s3_bucket": "cc-test",
        "s3_region": "us-east-1",
        "rate_limit_per_minute": 100_000,
        "login_rate_limit_per_minute": 1_000,
        "job_poll_interval_seconds": 0.05,
        "log_level": "INFO",
    }
    base.update(overrides)
    return Settings(**base)


# ----- crypto fixtures (session scoped: key generation is the slow part) --------------------------


@pytest.fixture(scope="session")
def ring() -> KeyRing:
    return KeyRing.generate(standard_params(8192, 128))


@pytest.fixture(scope="session")
def bundle_bytes(ring: KeyRing) -> bytes:
    return ring.public_bundle().to_bytes()


@pytest.fixture(scope="session")
def deep_ring() -> KeyRing:
    return KeyRing.generate(standard_params(8192, 128, "deep"))


@pytest.fixture(scope="session")
def deep_bundle_bytes(deep_ring: KeyRing) -> bytes:
    return deep_ring.public_bundle().to_bytes()


# ----- app fixtures -----------------------------------------------------------------------------------


@dataclass
class Harness:
    app: Any
    client: httpx.AsyncClient
    settings: Settings
    store: ObjectStore
    queue: MemoryQueue
    redis: Any
    log_buffer: io.StringIO

    @property
    def state(self) -> Any:
        return self.app.state.cc


@pytest.fixture
def aws() -> Iterator[None]:
    with mock_aws():
        yield


async def build_harness(tmp_path: Path, **overrides: Any) -> AsyncIterator[Harness]:
    settings = make_settings(tmp_path, **overrides)
    engine = make_engine(settings.database_url)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    await engine.dispose()
    redis = fakeredis.FakeAsyncRedis()
    store = ObjectStore(settings)
    queue = MemoryQueue()
    app = create_app(settings, redis=redis, store=store, queue=queue)
    # create_app configured logging; tee everything into a buffer for the scrubbing tests
    buffer = io.StringIO()
    handler = logging.StreamHandler(buffer)
    handler.setFormatter(logging.getLogger().handlers[0].formatter)
    logging.getLogger().addHandler(handler)
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            yield Harness(app, client, settings, store, queue, redis, buffer)
    logging.getLogger().removeHandler(handler)


@pytest.fixture
async def h(tmp_path: Path, aws: None) -> AsyncIterator[Harness]:
    async for harness in build_harness(tmp_path):
        yield harness


# ----- API helpers ---------------------------------------------------------------------------------------


def auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def register(client: httpx.AsyncClient, email: str | None = None, org: str = "Acme Health") -> dict[str, Any]:
    email = email or f"user-{uuid.uuid4().hex[:8]}@example.com"
    resp = await client.post("/v1/auth/register", json={"email": email, "password": PASSWORD, "organization_name": org})
    assert resp.status_code == 201, resp.text
    body: dict[str, Any] = resp.json()
    body["email"] = email
    return body


async def create_project(client: httpx.AsyncClient, token: str, name: str = "cardio") -> dict[str, Any]:
    resp = await client.post("/v1/projects", json={"name": name}, headers=auth(token))
    assert resp.status_code == 201, resp.text
    return resp.json()  # type: ignore[no-any-return]


async def upload_bundle(client: httpx.AsyncClient, token: str, project_id: str, data: bytes) -> httpx.Response:
    return await client.post(
        f"/v1/projects/{project_id}/key-bundles",
        content=data,
        headers={**auth(token), "Content-Type": "application/octet-stream"},
    )


async def create_dataset(
    client: httpx.AsyncClient, token: str, project_id: str, bundle_id: str, name: str = "vitals"
) -> dict[str, Any]:
    resp = await client.post(
        f"/v1/projects/{project_id}/datasets", json={"name": name, "key_bundle_id": bundle_id}, headers=auth(token)
    )
    assert resp.status_code == 201, resp.text
    return resp.json()  # type: ignore[no-any-return]


async def upload_ciphertext(
    h: Harness, token: str, dataset_id: str, ev: EncryptedVector, label: str = "x"
) -> dict[str, Any]:
    """Reserve, 'upload' (direct put — what the client's presigned POST does) and confirm."""
    data = ev.to_bytes()
    resp = await h.client.post(
        f"/v1/datasets/{dataset_id}/ciphertexts", json={"label": label, "size_bytes": len(data)}, headers=auth(token)
    )
    assert resp.status_code == 201, resp.text
    created = resp.json()["ciphertext"]
    me = (await h.client.get("/v1/auth/me", headers=auth(token))).json()
    project = (await h.client.get(f"/v1/datasets/{dataset_id}", headers=auth(token))).json()["project_id"]
    key = ObjectStore.key_for_ciphertext(
        uuid.UUID(me["organization_id"]), uuid.UUID(project), uuid.UUID(dataset_id), uuid.UUID(created["id"])
    )
    await h.store.put_bytes(key, uuid.UUID(me["organization_id"]), data)
    resp = await h.client.post(f"/v1/ciphertexts/{created['id']}/confirm", headers=auth(token))
    assert resp.status_code == 200, resp.text
    return resp.json()  # type: ignore[no-any-return]


@dataclass
class World:
    token: str
    org_id: str
    project_id: str
    bundle_id: str
    dataset_id: str


async def make_world(h: Harness, data: bytes) -> World:
    user = await register(h.client)
    project = await create_project(h.client, user["access_token"])
    resp = await upload_bundle(h.client, user["access_token"], project["id"], data)
    assert resp.status_code == 201, resp.text
    dataset = await create_dataset(h.client, user["access_token"], project["id"], resp.json()["id"])
    return World(user["access_token"], user["organization_id"], project["id"], resp.json()["id"], dataset["id"])
