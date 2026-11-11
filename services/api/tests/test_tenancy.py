"""Two organizations, every resource type: nothing of A is visible or mutable from B."""

from __future__ import annotations

import uuid

import pytest

from ciphercompute_api.db.models import Organization, Project, User
from ciphercompute_api.db.tenancy import TenantScopedSession, TenantViolationError
from ciphercompute_api.storage.objects import ObjectStore, TenantKeyViolationError
from ciphercompute_core import EncryptedVector, KeyRing

from .conftest import Harness, auth, make_world, register, upload_ciphertext


async def test_cross_tenant_reads_and_writes_are_404(h: Harness, ring: KeyRing, bundle_bytes: bytes) -> None:
    a = await make_world(h, bundle_bytes)
    ct = await upload_ciphertext(h, a.token, a.dataset_id, EncryptedVector.encrypt(ring.public_bundle(), [1.0, 2.0]))
    job = (
        await h.client.post(
            f"/v1/projects/{a.project_id}/jobs", json={"operation": "sum", "inputs": [ct["id"]]}, headers=auth(a.token)
        )
    ).json()
    b = (await register(h.client, org="Rival Clinic"))["access_token"]

    reads = [
        f"/v1/projects/{a.project_id}",
        f"/v1/projects/{a.project_id}/key-bundles",
        f"/v1/key-bundles/{a.bundle_id}",
        f"/v1/projects/{a.project_id}/datasets",
        f"/v1/datasets/{a.dataset_id}",
        f"/v1/datasets/{a.dataset_id}/ciphertexts",
        f"/v1/ciphertexts/{ct['id']}",
        f"/v1/ciphertexts/{ct['id']}/download",
        f"/v1/jobs/{job['id']}",
        f"/v1/jobs/{job['id']}/result",
        f"/v1/jobs/{job['id']}/events",
    ]
    for url in reads:
        resp = await h.client.get(url, headers=auth(b))
        assert resp.status_code == 404, url
    writes = [
        ("PATCH", f"/v1/projects/{a.project_id}", {"name": "pwned"}),
        ("DELETE", f"/v1/projects/{a.project_id}", None),
        ("POST", f"/v1/key-bundles/{a.bundle_id}/revoke", None),
        ("POST", f"/v1/projects/{a.project_id}/datasets", {"name": "x", "key_bundle_id": a.bundle_id}),
        ("POST", f"/v1/datasets/{a.dataset_id}/ciphertexts", {"label": "x", "size_bytes": 10}),
        ("POST", f"/v1/ciphertexts/{ct['id']}/confirm", None),
        ("DELETE", f"/v1/ciphertexts/{ct['id']}", None),
        ("POST", f"/v1/projects/{a.project_id}/jobs", {"operation": "sum", "inputs": [ct["id"]]}),
        ("POST", f"/v1/jobs/{job['id']}/cancel", None),
        ("DELETE", f"/v1/datasets/{a.dataset_id}", None),
    ]
    for method, url, body in writes:
        resp = await h.client.request(method, url, json=body, headers=auth(b))
        assert resp.status_code == 404, (method, url, resp.status_code)

    # B's own project cannot reference A's ciphertexts or bundles either
    b_project = (await h.client.post("/v1/projects", json={"name": "b"}, headers=auth(b))).json()
    resp = await h.client.post(
        f"/v1/projects/{b_project['id']}/jobs", json={"operation": "sum", "inputs": [ct["id"]]}, headers=auth(b)
    )
    assert resp.status_code == 422 and resp.json()["error"]["details"]["missing"] == [ct["id"]]
    resp = await h.client.post(
        f"/v1/projects/{b_project['id']}/datasets", json={"name": "x", "key_bundle_id": a.bundle_id}, headers=auth(b)
    )
    assert resp.status_code == 404

    # list endpoints never leak
    for url in ("/v1/projects", "/v1/jobs", "/v1/audit", "/v1/api-keys", "/v1/organization/members"):
        body = (await h.client.get(url, headers=auth(b))).json()
        items = body["items"] if isinstance(body, dict) else body
        flat = str(items)
        assert a.project_id not in flat and a.org_id not in flat and job["id"] not in flat, url
    usage = (await h.client.get("/v1/usage", headers=auth(b))).json()
    assert usage["jobs_by_status"] == {} and usage["storage_bytes"]["total"] == 0

    # and A is untouched
    assert (await h.client.get(f"/v1/projects/{a.project_id}", headers=auth(a.token))).json()["name"] == "cardio"


async def test_scoped_session_guards(h: Harness) -> None:
    async with h.state.session_factory() as session:
        org_a = Organization(name="A", slug=f"a-{uuid.uuid4().hex[:6]}")
        org_b = Organization(name="B", slug=f"b-{uuid.uuid4().hex[:6]}")
        session.add_all([org_a, org_b])
        await session.flush()
        tenant = TenantScopedSession(session, org_a.id)
        added = tenant.add(Project(name="auto"))
        assert added.organization_id == org_a.id
        with pytest.raises(TenantViolationError):
            tenant.add(Project(name="foreign", organization_id=org_b.id))
        with pytest.raises(TenantViolationError):
            tenant.select(User)  # type: ignore[type-var]
        foreign = Project(name="theirs", organization_id=org_b.id)
        session.add(foreign)
        await session.flush()
        assert await tenant.get(Project, foreign.id) is None
        with pytest.raises(TenantViolationError):
            await tenant.delete(foreign)
        assert await tenant.count(tenant.select(Project)) == 1
        await session.rollback()


def test_object_keys_are_tenant_prefixed() -> None:
    org, other = uuid.uuid4(), uuid.uuid4()
    key = ObjectStore.key_for_result(org, uuid.uuid4(), uuid.uuid4())
    assert ObjectStore.assert_tenant_key(key, org) == key
    with pytest.raises(TenantKeyViolationError):
        ObjectStore.assert_tenant_key(key, other)
    with pytest.raises(TenantKeyViolationError):
        ObjectStore.assert_tenant_key(f"org/{org}/../{other}/x", org)


async def test_store_refuses_foreign_prefix(h: Harness) -> None:
    org, other = uuid.uuid4(), uuid.uuid4()
    key = ObjectStore.key_for_result(other, uuid.uuid4(), uuid.uuid4())
    for call in (
        h.store.presign_download(key, org),
        h.store.presign_upload(key, org, max_bytes=10),
        h.store.put_bytes(key, org, b"x"),
        h.store.get_bytes(key, org, max_bytes=10),
    ):
        with pytest.raises(TenantKeyViolationError):
            await call
