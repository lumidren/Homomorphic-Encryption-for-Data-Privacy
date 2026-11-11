"""SDK end to end: keys stay local, data is computed on encrypted, results decrypt correctly."""

from __future__ import annotations

import random
import uuid

import numpy as np
import pytest

from ciphercompute_api.storage.objects import ObjectStore
from ciphercompute_client import CipherComputeClient, JobFailedError, VerificationError, verify_sample
from ciphercompute_client.client import IntegrityError
from ciphercompute_client.errors import ApiError
from ciphercompute_client.verify import check_result
from ciphercompute_core import KeyRing
from ciphercompute_core.envelope import MAGIC_BUNDLE, pack
from ciphercompute_core.errors import SecretKeyLeakError
from ciphercompute_core.keys import BUNDLE_KIND
from ciphercompute_core.sigmoid import sigmoid_poly

from .conftest import PASSWORD, Stack


def _setup(client: CipherComputeClient, ring: KeyRing) -> tuple[str, str]:
    project = client.create_project(f"p-{uuid.uuid4().hex[:6]}")
    bundle = client.upload_key_bundle(project["id"], ring)
    dataset = client.create_dataset(project["id"], "vitals", bundle["id"])
    return project["id"], dataset["id"]


def test_full_flow_mean_and_variance(stack: Stack, user: CipherComputeClient, ring: KeyRing) -> None:
    project_id, dataset_id = _setup(user, ring)
    values = [118.0, 131.5, 142.25, 127.0, 150.5]
    ct = user.encrypt_and_upload(dataset_id, ring, values, label="systolic")
    assert ct["status"] == "ready" and ct["length"] == 5
    mean_job = user.submit_job(project_id, "mean", [ct["id"]])
    var_job = user.submit_job(project_id, "variance", [ct["id"]], {"ddof": 1})
    assert stack.drain() == ["succeeded", "succeeded"]
    assert user.wait_and_decrypt(mean_job["id"], ring)[0] == pytest.approx(np.mean(values), abs=1e-3)
    assert user.decrypt_result(var_job["id"], ring)[0] == pytest.approx(np.var(values, ddof=1), abs=1e-2)
    # nothing but ciphertext ever went to object storage, and no request carried decrypted values
    storage_requests = [r for r in stack.transport.seen if r.url.host != "api.test"]
    assert storage_requests and all(r.url.host == "s3.amazonaws.com" for r in storage_requests)
    assert all("Authorization" not in r.headers for r in storage_requests)


def test_batched_logistic_regression_and_verification(
    stack: Stack, user: CipherComputeClient, deep_ring: KeyRing
) -> None:
    project_id, dataset_id = _setup(user, deep_ring)
    rng = np.random.default_rng(11)
    patients = rng.uniform(-1, 1, (12, 3))
    cts = user.encrypt_columns_and_upload(dataset_id, deep_ring, patients, labels=["age_z", "bp_z", "chol_z"])
    args = {"weights": [0.7, 1.1, -0.4], "intercept": -0.3, "layout": "columns", "degree": 3}
    job = user.submit_job(project_id, "logistic_regression", [c["id"] for c in cts], args)
    stack.drain()
    scores = user.wait_and_decrypt(job["id"], deep_ring)
    assert np.max(np.abs(scores - sigmoid_poly(patients @ np.array(args["weights"]) + args["intercept"], 3))) < 1e-2
    finished = user.get_job(job["id"])
    user.verify_manifest(finished, deep_ring)
    assert verify_sample(user, deep_ring, job["id"], [patients[:, i] for i in range(3)])
    assert not verify_sample(
        user, deep_ring, job["id"], [patients[:, i] for i in range(3)], probability=0.0, rng=random.Random(1)
    )


def test_tampering_is_detected(stack: Stack, user: CipherComputeClient, ring: KeyRing) -> None:
    project_id, dataset_id = _setup(user, ring)
    ct = user.encrypt_and_upload(dataset_id, ring, [1.0, 2.0, 3.0], label="x")
    job = user.submit_job(project_id, "sum", [ct["id"]])
    stack.drain()
    done = user.wait(job["id"])

    # a server that ran a different operation or arguments than requested
    with pytest.raises(IntegrityError, match="manifest"):
        user.verify_manifest({**done, "args": {"forged": True}}, ring)
    # a result that differs from the plaintext recomputation
    with pytest.raises(VerificationError, match="differs") as excinfo:
        check_result(done, np.array([999.0]), [[1.0, 2.0, 3.0]])
    assert excinfo.value.max_error > excinfo.value.tolerance
    with pytest.raises(VerificationError, match="values"):
        check_result(done, np.array([]), [[1.0, 2.0, 3.0]])
    # a stored result swapped after the worker recorded its fingerprint
    me = user.me()
    store = ObjectStore(stack.settings)
    key = ObjectStore.key_for_result(uuid.UUID(me["organization_id"]), uuid.UUID(project_id), uuid.UUID(job["id"]))
    import asyncio

    asyncio.run(store.put_bytes(key, uuid.UUID(me["organization_id"]), b"swapped"))
    with pytest.raises(IntegrityError, match="fingerprint"):
        user.download_result(job["id"], ring)
    # inputs this client did not upload cannot be verified
    with pytest.raises(IntegrityError, match="not uploaded by this client"):
        stack.client(access_token=user.access_token).verify_manifest(done, ring)


def test_secret_key_never_uploaded(user: CipherComputeClient, ring: KeyRing) -> None:
    project = user.create_project("secret-check")
    raw = ring.context().serialize(
        save_public_key=True, save_secret_key=True, save_galois_keys=True, save_relin_keys=True
    )
    private = pack(MAGIC_BUNDLE, {"kind": BUNDLE_KIND, "ring_id": ring.ring_id, "params": ring.params.to_dict()}, raw)
    with pytest.raises(SecretKeyLeakError):
        user.upload_key_bundle(project["id"], private)  # refused locally, before any network call
    assert user.list_key_bundles(project["id"]) == []
    ok = user.upload_key_bundle(project["id"], ring.public_bundle().to_bytes())
    assert ok["ring_id"] == ring.ring_id


def test_depth_refusal_surfaces_advice(user: CipherComputeClient, ring: KeyRing) -> None:
    project_id, dataset_id = _setup(user, ring)
    ct = user.encrypt_and_upload(dataset_id, ring, [0.1, 0.2], label="x")
    with pytest.raises(ApiError) as excinfo:
        user.submit_job(project_id, "logistic_regression", [ct["id"]], {"weights": [1.0, 1.0], "degree": 5})
    assert excinfo.value.status_code == 422 and excinfo.value.code == "depth_exhausted"
    assert excinfo.value.details["suggested_profile"] == "deep"
    advice = user.advise([("logistic_regression", {"weights": [1.0, 1.0], "degree": 5})], [2])
    assert advice["required_depth"] == 4 and advice["params"]["poly_modulus_degree"] == 8192


def test_wait_failures_and_cancel(stack: Stack, user: CipherComputeClient, ring: KeyRing) -> None:
    project_id, dataset_id = _setup(user, ring)
    ct = user.encrypt_and_upload(dataset_id, ring, [1.0], label="x")
    job = user.submit_job(project_id, "sum", [ct["id"]])
    with pytest.raises(TimeoutError):
        user.wait(job["id"], timeout=0.0, poll_interval=0.0)
    assert user.cancel_job(job["id"])["status"] == "cancelled"
    with pytest.raises(JobFailedError, match="cancelled"):
        user.wait(job["id"], poll_interval=0.0)
    assert [j["id"] for j in user.list_jobs(status="cancelled")] == [job["id"]]


def test_idempotent_submission(stack: Stack, user: CipherComputeClient, ring: KeyRing) -> None:
    project_id, dataset_id = _setup(user, ring)
    ct = user.encrypt_and_upload(dataset_id, ring, [1.0], label="x")
    first = user.submit_job(project_id, "sum", [ct["id"]], idempotency_key="retry-safe-0001")
    again = user.submit_job(project_id, "sum", [ct["id"]], idempotency_key="retry-safe-0001")
    assert first["id"] == again["id"] and len(stack.queue.items) == 1
    request = next(r for r in stack.transport.seen if r.url.path.endswith("/jobs"))
    assert request.headers["Idempotency-Key"] == "retry-safe-0001"
    user.submit_job(project_id, "sum", [ct["id"]])
    auto = [r for r in stack.transport.seen if r.url.path.endswith("/jobs")][-1]
    assert auto.headers["Idempotency-Key"].startswith("sdk-")


def test_events_stream(stack: Stack, user: CipherComputeClient, ring: KeyRing) -> None:
    project_id, dataset_id = _setup(user, ring)
    ct = user.encrypt_and_upload(dataset_id, ring, [1.0, 1.0], label="x")
    job = user.submit_job(project_id, "sum", [ct["id"]])
    stack.drain()
    updates = list(user.events(job["id"]))
    assert updates[-1]["status"] == "succeeded"
    with pytest.raises(ApiError) as excinfo:
        list(user.events(str(uuid.uuid4())))
    assert excinfo.value.status_code == 404


def test_token_refresh_and_logout(stack: Stack, ring: KeyRing) -> None:
    client = stack.client()
    email = f"r-{uuid.uuid4().hex[:6]}@example.com"
    client.register(email, PASSWORD, "Refresh Org")
    first_refresh = client.refresh_token
    client.access_token = "expired-or-garbage"
    assert client.me()["email"] == email  # 401 -> refresh -> retry
    assert client.refresh_token != first_refresh
    client.logout()
    assert client.access_token is None
    with pytest.raises(ValueError, match="log in first"):
        client.refresh()
    again = stack.client()
    again.login(email, PASSWORD)
    assert again.me()["email"] == email


def test_api_key_auth_and_admin_calls(stack: Stack, user: CipherComputeClient, ring: KeyRing) -> None:
    created = user.create_api_key("ci", ["projects:read", "jobs:read", "audit:read"])
    keyed = stack.client(api_key=created["secret"])
    assert keyed.me()["principal_type"] == "api_key"
    keyed.access_token = "ignored"
    assert keyed.list_projects() == []
    with pytest.raises(ApiError) as excinfo:
        keyed.create_project("nope")
    assert excinfo.value.status_code == 403
    assert [k["id"] for k in user.list_api_keys()] == [created["api_key"]["id"]]
    assert user.revoke_api_key(created["api_key"]["id"])["revoked_at"]
    assert user.verify_audit_chain()["valid"] is True
    assert any(e["action"] == "api_key.created" for e in user.audit_events(action="api_key.created"))
    assert user.usage()["window_days"] == 30
    assert {o["name"] for o in user.operations()} >= {"mean", "logistic_regression"}
    assert len(user.parameter_sets()) == 17


def test_pagination(user: CipherComputeClient) -> None:
    names = [f"p{i:03d}" for i in range(105)]
    for name in names:
        user.create_project(name)
    assert sorted(p["name"] for p in user.list_projects()) == names


def test_listing_helpers(stack: Stack, user: CipherComputeClient, ring: KeyRing) -> None:
    project_id, dataset_id = _setup(user, ring)
    user.encrypt_and_upload(dataset_id, ring, [1.0], label="a", pad_to=16)
    assert [d["id"] for d in user.list_datasets(project_id)] == [dataset_id]
    listed = user.list_ciphertexts(dataset_id)
    assert listed[0]["length"] == 16  # padding hides the true count
    with pytest.raises(ValueError, match="features"):
        user.encrypt_columns_and_upload(dataset_id, ring, np.ones((3, 2)), labels=["only-one"])
