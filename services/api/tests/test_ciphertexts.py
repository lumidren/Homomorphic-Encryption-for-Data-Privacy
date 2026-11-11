from __future__ import annotations

import base64
import json
import uuid

from ciphercompute_api.storage.objects import ObjectStore
from ciphercompute_core import EncryptedVector, KeyRing

from .conftest import Harness, auth, make_world, upload_ciphertext


async def test_presigned_upload_policy(h: Harness, bundle_bytes: bytes) -> None:
    w = await make_world(h, bundle_bytes)
    resp = await h.client.post(
        f"/v1/datasets/{w.dataset_id}/ciphertexts", json={"label": "bp", "size_bytes": 5000}, headers=auth(w.token)
    )
    assert resp.status_code == 201
    upload = resp.json()["upload"]
    assert upload["max_bytes"] == 5000
    assert upload["fields"]["x-amz-server-side-encryption"] == "AES256"
    assert upload["fields"]["key"].startswith(f"org/{w.org_id}/projects/{w.project_id}/datasets/{w.dataset_id}/")
    policy = json.loads(base64.b64decode(upload["fields"]["policy"]))
    assert ["content-length-range", 1, 5000] in policy["conditions"]
    assert {"x-amz-server-side-encryption": "AES256"} in policy["conditions"]


async def test_oversized_declaration_rejected(h: Harness, bundle_bytes: bytes) -> None:
    w = await make_world(h, bundle_bytes)
    resp = await h.client.post(
        f"/v1/datasets/{w.dataset_id}/ciphertexts",
        json={"label": "bp", "size_bytes": h.settings.max_ciphertext_bytes + 1},
        headers=auth(w.token),
    )
    assert resp.status_code == 413 and resp.json()["error"]["code"] == "payload_too_large"


async def test_confirm_flow(h: Harness, ring: KeyRing, bundle_bytes: bytes) -> None:
    w = await make_world(h, bundle_bytes)
    ev = EncryptedVector.encrypt(ring.public_bundle(), [1.0, 2.0, 3.0])
    ct = await upload_ciphertext(h, w.token, w.dataset_id, ev, "systolic")
    assert ct["status"] == "ready" and ct["length"] == 3 and ct["levels_consumed"] == 0
    assert ct["fingerprint"].startswith("sha256:") and ct["size_bytes"] == len(ev.to_bytes())
    # confirming twice is a no-op
    again = await h.client.post(f"/v1/ciphertexts/{ct['id']}/confirm", headers=auth(w.token))
    assert again.status_code == 200 and again.json()["fingerprint"] == ct["fingerprint"]
    listed = (await h.client.get(f"/v1/datasets/{w.dataset_id}/ciphertexts", headers=auth(w.token))).json()
    assert [c["id"] for c in listed["items"]] == [ct["id"]]
    dl = await h.client.get(f"/v1/ciphertexts/{ct['id']}/download", headers=auth(w.token))
    assert dl.status_code == 200 and "X-Amz-Signature" in dl.json()["url"]
    assert (await h.client.get("/v1/audit?action=ciphertext.accessed", headers=auth(w.token))).json()["items"]


async def test_confirm_before_upload(h: Harness, bundle_bytes: bytes) -> None:
    w = await make_world(h, bundle_bytes)
    created = (
        await h.client.post(
            f"/v1/datasets/{w.dataset_id}/ciphertexts", json={"label": "x", "size_bytes": 100}, headers=auth(w.token)
        )
    ).json()
    resp = await h.client.post(f"/v1/ciphertexts/{created['ciphertext']['id']}/confirm", headers=auth(w.token))
    assert resp.status_code == 409
    dl = await h.client.get(f"/v1/ciphertexts/{created['ciphertext']['id']}/download", headers=auth(w.token))
    assert dl.status_code == 409


async def _reserve_and_put(h: Harness, w, data: bytes) -> str:  # type: ignore[no-untyped-def]
    created = (
        await h.client.post(
            f"/v1/datasets/{w.dataset_id}/ciphertexts",
            json={"label": "x", "size_bytes": max(len(data), 1)},
            headers=auth(w.token),
        )
    ).json()
    ct_id = created["ciphertext"]["id"]
    key = ObjectStore.key_for_ciphertext(
        uuid.UUID(w.org_id), uuid.UUID(w.project_id), uuid.UUID(w.dataset_id), uuid.UUID(ct_id)
    )
    await h.store.put_bytes(key, uuid.UUID(w.org_id), data)
    return ct_id  # type: ignore[no-any-return]


async def test_confirm_rejects_foreign_ring(h: Harness, ring: KeyRing, bundle_bytes: bytes) -> None:
    w = await make_world(h, bundle_bytes)
    other = KeyRing.generate(ring.params)
    ct_id = await _reserve_and_put(h, w, EncryptedVector.encrypt(other.public_bundle(), [1.0]).to_bytes())
    resp = await h.client.post(f"/v1/ciphertexts/{ct_id}/confirm", headers=auth(w.token))
    assert resp.status_code == 422 and "different key ring" in resp.json()["error"]["message"]


async def test_confirm_rejects_garbage_and_oversize(h: Harness, bundle_bytes: bytes) -> None:
    w = await make_world(h, bundle_bytes)
    ct_id = await _reserve_and_put(h, w, b"definitely not an envelope")
    assert (await h.client.post(f"/v1/ciphertexts/{ct_id}/confirm", headers=auth(w.token))).status_code == 422
    ct_id = await _reserve_and_put(h, w, b"tiny")
    assert (await h.client.post(f"/v1/ciphertexts/{ct_id}/confirm", headers=auth(w.token))).status_code == 422
    # declared 10 bytes but 100 were stored: refused and the object is deleted
    created = (
        await h.client.post(
            f"/v1/datasets/{w.dataset_id}/ciphertexts", json={"label": "x", "size_bytes": 10}, headers=auth(w.token)
        )
    ).json()
    ct = created["ciphertext"]["id"]
    key = ObjectStore.key_for_ciphertext(
        uuid.UUID(w.org_id), uuid.UUID(w.project_id), uuid.UUID(w.dataset_id), uuid.UUID(ct)
    )
    await h.store.put_bytes(key, uuid.UUID(w.org_id), b"x" * 100)
    assert (await h.client.post(f"/v1/ciphertexts/{ct}/confirm", headers=auth(w.token))).status_code == 413
    assert await h.store.head(key, uuid.UUID(w.org_id)) is None


async def test_delete_ciphertext_and_dataset(h: Harness, ring: KeyRing, bundle_bytes: bytes) -> None:
    w = await make_world(h, bundle_bytes)
    ct = await upload_ciphertext(h, w.token, w.dataset_id, EncryptedVector.encrypt(ring.public_bundle(), [1.0]))
    assert (await h.client.delete(f"/v1/ciphertexts/{ct['id']}", headers=auth(w.token))).status_code == 204
    assert (await h.client.get(f"/v1/ciphertexts/{ct['id']}", headers=auth(w.token))).status_code == 404
    await upload_ciphertext(h, w.token, w.dataset_id, EncryptedVector.encrypt(ring.public_bundle(), [2.0]))
    assert (await h.client.delete(f"/v1/datasets/{w.dataset_id}", headers=auth(w.token))).status_code == 204
    prefix = f"{ObjectStore.tenant_prefix(uuid.UUID(w.org_id))}projects/{w.project_id}/datasets/"
    assert await h.store.total_bytes(prefix, uuid.UUID(w.org_id)) == 0
