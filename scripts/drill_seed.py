#!/usr/bin/env python3
"""Seed and verify helper for scripts/restore_drill.sh.

``seed``   creates an organization, uploads a public bundle and two ciphertexts through the API
           code (so rows, objects and audit events are all real) and prints a JSON summary.
``verify`` checks that the restored database and bucket match the summary: row counts, every
           object's SHA-256 against its recorded fingerprint, and the audit hash chain.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import sys
import uuid

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import NullPool

from ciphercompute_api.audit.chain import verify_chain
from ciphercompute_api.config import Settings
from ciphercompute_api.db.base import make_session_factory
from ciphercompute_api.db.models import AuditEvent, Ciphertext, KeyBundle, Organization
from ciphercompute_api.storage.objects import ObjectStore

TABLES = {
    "organizations": Organization,
    "key_bundles": KeyBundle,
    "ciphertexts": Ciphertext,
    "audit_events": AuditEvent,
}


def settings(bucket: str, endpoint: str) -> Settings:
    return Settings(
        env="test",
        jwt_secret=os.environ["CC_JWT_SECRET"],
        database_url=os.environ["CC_DATABASE_URL"],
        s3_bucket=bucket,
        s3_endpoint_url=endpoint,
        queue_backend="memory",
        argon2_time_cost=1,
        argon2_memory_kib=8,
        argon2_parallelism=1,
    )


def seed(bucket: str, endpoint: str) -> dict[str, object]:
    import fakeredis
    from fastapi.testclient import TestClient

    from ciphercompute_api.app import create_app
    from ciphercompute_core import EncryptedVector, KeyRing, standard_params

    cfg = settings(bucket, endpoint)
    app = create_app(cfg, redis=fakeredis.FakeAsyncRedis())
    ring = KeyRing.generate(standard_params(8192, 128))
    with TestClient(app) as api:
        token = api.post(
            "/v1/auth/register",
            json={
                "email": f"drill-{uuid.uuid4().hex[:6]}@example.com",
                "password": "restore drill passphrase",
                "organization_name": "Drill",
            },
        ).json()["access_token"]
        auth = {"Authorization": f"Bearer {token}"}
        project = api.post("/v1/projects", json={"name": "drill"}, headers=auth).json()
        bundle = api.post(
            f"/v1/projects/{project['id']}/key-bundles",
            content=ring.public_bundle().to_bytes(),
            headers={**auth, "Content-Type": "application/octet-stream"},
        ).json()
        dataset = api.post(
            f"/v1/projects/{project['id']}/datasets", json={"name": "d", "key_bundle_id": bundle["id"]}, headers=auth
        ).json()
        store = ObjectStore(cfg)
        me = api.get("/v1/auth/me", headers=auth).json()
        for label, values in (("x", [1.0, 2.0, 3.0]), ("y", [4.0, 5.0])):
            data = EncryptedVector.encrypt(ring.public_bundle(), values).to_bytes()
            ct = api.post(
                f"/v1/datasets/{dataset['id']}/ciphertexts",
                json={"label": label, "size_bytes": len(data)},
                headers=auth,
            ).json()["ciphertext"]
            key = ObjectStore.key_for_ciphertext(
                uuid.UUID(me["organization_id"]),
                uuid.UUID(project["id"]),
                uuid.UUID(dataset["id"]),
                uuid.UUID(ct["id"]),
            )
            asyncio.run(store.put_bytes(key, uuid.UUID(me["organization_id"]), data))
            confirmed = api.post(f"/v1/ciphertexts/{ct['id']}/confirm", headers=auth)
            if confirmed.status_code != 200:
                raise SystemExit(f"seeding failed: confirm returned {confirmed.status_code}: {confirmed.text}")
    return asyncio.run(summarize(cfg))


async def summarize(cfg: Settings) -> dict[str, object]:
    engine = create_async_engine(cfg.database_url, poolclass=NullPool)
    factory = make_session_factory(engine)
    async with factory() as session:
        counts = {
            name: int((await session.execute(select(func.count()).select_from(model))).scalar_one())
            for name, model in TABLES.items()
        }
    await engine.dispose()
    return {"counts": counts}


async def verify(cfg: Settings, expected: dict[str, object]) -> list[str]:
    problems: list[str] = []
    actual = await summarize(cfg)
    if actual["counts"] != expected["counts"]:
        problems.append(f"row counts differ: before={expected['counts']} after={actual['counts']}")
    engine = create_async_engine(cfg.database_url, poolclass=NullPool)
    factory = make_session_factory(engine)
    store = ObjectStore(cfg)
    async with factory() as session:
        for ct in (await session.execute(select(Ciphertext))).scalars():
            data = await store.get_bytes(ct.object_key, ct.organization_id, max_bytes=1 << 30)
            if "sha256:" + hashlib.sha256(data).hexdigest() != ct.fingerprint:
                problems.append(f"ciphertext {ct.id}: object does not match its fingerprint")
        for bundle in (await session.execute(select(KeyBundle))).scalars():
            if await store.head(bundle.object_key, bundle.organization_id) is None:
                problems.append(f"key bundle {bundle.id}: object missing")
        orgs = (await session.execute(select(Organization.id))).scalars().all()
        for org in orgs:
            events = (
                await session.execute(
                    select(AuditEvent).where(AuditEvent.organization_id == org).order_by(AuditEvent.seq)
                )
            ).scalars()
            result = verify_chain(events)
            if not result.valid:
                problems.append(f"audit chain of {org} broken at {result.first_broken_seq}: {result.reason}")
    await engine.dispose()
    return problems


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["seed", "verify"])
    parser.add_argument("--bucket", required=True)
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--expect")
    ns = parser.parse_args()
    if ns.mode == "seed":
        print(json.dumps(seed(ns.bucket, ns.endpoint)))
        return 0
    with open(ns.expect, encoding="utf-8") as fh:
        expected = json.load(fh)
    problems = asyncio.run(verify(settings(ns.bucket, ns.endpoint), expected))
    for p in problems:
        print(f"FAIL {p}", file=sys.stderr)
    print(
        "verified: counts, object fingerprints, bundles present, audit chains intact"
        if not problems
        else "restore verification failed"
    )
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
