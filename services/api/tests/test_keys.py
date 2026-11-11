"""Key bundle upload: the secret-key gate runs before anything is stored."""

from __future__ import annotations

import uuid

from sqlalchemy import select

from ciphercompute_api.db.models import KeyBundle
from ciphercompute_api.storage.objects import ObjectStore
from ciphercompute_core import KeyRing
from ciphercompute_core.envelope import MAGIC_BUNDLE, pack
from ciphercompute_core.keys import BUNDLE_KIND

from .conftest import Harness, auth, create_project, register, upload_bundle


def _private_bundle(ring: KeyRing) -> bytes:
    raw = ring.context().serialize(
        save_public_key=True, save_secret_key=True, save_galois_keys=True, save_relin_keys=True
    )
    return pack(MAGIC_BUNDLE, {"kind": BUNDLE_KIND, "ring_id": ring.ring_id, "params": ring.params.to_dict()}, raw)


async def _objects_under(h: Harness, org_id: str) -> int:
    return await h.store.total_bytes(ObjectStore.tenant_prefix(uuid.UUID(org_id)), uuid.UUID(org_id))


async def test_upload_valid_bundle(h: Harness, ring: KeyRing, bundle_bytes: bytes) -> None:
    user = await register(h.client)
    project = await create_project(h.client, user["access_token"])
    resp = await upload_bundle(h.client, user["access_token"], project["id"], bundle_bytes)
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["ring_id"] == ring.ring_id and body["status"] == "active"
    assert body["params"] == ring.params.to_dict() and body["size_bytes"] == len(bundle_bytes)
    assert body["fingerprint"].startswith("sha256:")
    assert await _objects_under(h, user["organization_id"]) == len(bundle_bytes)
    listed = (
        await h.client.get(f"/v1/projects/{project['id']}/key-bundles", headers=auth(user["access_token"]))
    ).json()
    assert [b["id"] for b in listed] == [body["id"]]
    one = await h.client.get(f"/v1/key-bundles/{body['id']}", headers=auth(user["access_token"]))
    assert one.status_code == 200

    dup = await upload_bundle(h.client, user["access_token"], project["id"], bundle_bytes)
    assert dup.status_code == 409


async def test_private_context_rejected_before_storage(h: Harness, ring: KeyRing) -> None:
    user = await register(h.client)
    project = await create_project(h.client, user["access_token"])
    resp = await upload_bundle(h.client, user["access_token"], project["id"], _private_bundle(ring))
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "secret_key_leak"
    # nothing persisted: no object, no row; but the attempt is audited
    assert await _objects_under(h, user["organization_id"]) == 0
    async with h.state.session_factory() as session:
        assert (await session.execute(select(KeyBundle))).first() is None
    events = (await h.client.get("/v1/audit?action=key_bundle.rejected", headers=auth(user["access_token"]))).json()[
        "items"
    ]
    assert len(events) == 1 and events[0]["details"]["reason"] == "secret_key_leak"


async def test_malformed_and_empty_bundles(h: Harness) -> None:
    user = await register(h.client)
    project = await create_project(h.client, user["access_token"])
    resp = await upload_bundle(h.client, user["access_token"], project["id"], b"not a bundle at all")
    assert resp.status_code == 422 and resp.json()["error"]["code"] == "serialization_error"
    resp = await upload_bundle(h.client, user["access_token"], project["id"], b"")
    assert resp.status_code == 422


async def test_oversized_bundle(h: Harness, bundle_bytes: bytes) -> None:
    h.state.settings.max_bundle_bytes = 1024
    user = await register(h.client)
    project = await create_project(h.client, user["access_token"])
    resp = await upload_bundle(h.client, user["access_token"], project["id"], bundle_bytes)
    assert resp.status_code == 413


async def test_revoke_bundle_requires_admin(h: Harness, bundle_bytes: bytes) -> None:
    user = await register(h.client)
    project = await create_project(h.client, user["access_token"])
    bundle = (await upload_bundle(h.client, user["access_token"], project["id"], bundle_bytes)).json()
    resp = await h.client.post(f"/v1/key-bundles/{bundle['id']}/revoke", headers=auth(user["access_token"]))
    assert resp.status_code == 200 and resp.json()["status"] == "revoked"
    again = await h.client.post(f"/v1/key-bundles/{bundle['id']}/revoke", headers=auth(user["access_token"]))
    assert again.status_code == 200
    # a revoked bundle cannot back a new dataset
    resp = await h.client.post(
        f"/v1/projects/{project['id']}/datasets",
        json={"name": "d", "key_bundle_id": bundle["id"]},
        headers=auth(user["access_token"]),
    )
    assert resp.status_code == 422
