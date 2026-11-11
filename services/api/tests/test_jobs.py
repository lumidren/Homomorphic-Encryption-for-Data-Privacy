from __future__ import annotations

import asyncio
import uuid

from ciphercompute_api.db.base import utcnow
from ciphercompute_api.db.models import Job, JobStatus
from ciphercompute_core import EncryptedVector, KeyRing, standard_params

from .conftest import Harness, auth, make_world, upload_ciphertext


async def _two_inputs(h: Harness, ring: KeyRing, bundle_bytes: bytes):  # type: ignore[no-untyped-def]
    w = await make_world(h, bundle_bytes)
    pub = ring.public_bundle()
    a = await upload_ciphertext(h, w.token, w.dataset_id, EncryptedVector.encrypt(pub, [1.0, 2.0, 3.0]), "a")
    b = await upload_ciphertext(h, w.token, w.dataset_id, EncryptedVector.encrypt(pub, [4.0, 5.0, 6.0]), "b")
    return w, a, b


async def test_submit_and_read(h: Harness, ring: KeyRing, bundle_bytes: bytes) -> None:
    w, a, _ = await _two_inputs(h, ring, bundle_bytes)
    resp = await h.client.post(
        f"/v1/projects/{w.project_id}/jobs", json={"operation": "mean", "inputs": [a["id"]]}, headers=auth(w.token)
    )
    assert resp.status_code == 202, resp.text
    job = resp.json()
    assert job["status"] == "queued" and job["args"] == {"count": 3}
    assert job["depth_report"]["levels_consumed"] == 1 and job["depth_report"]["levels_remaining"] == 1
    assert job["input_fingerprints"] == [a["fingerprint"]] and len(job["manifest_hash"]) == 64
    assert h.queue.items == [(uuid.UUID(job["id"]), uuid.UUID(w.org_id))]
    got = await h.client.get(f"/v1/jobs/{job['id']}", headers=auth(w.token))
    assert got.status_code == 200 and got.json()["id"] == job["id"]
    listed = (await h.client.get(f"/v1/jobs?project_id={w.project_id}&status=queued", headers=auth(w.token))).json()
    assert [j["id"] for j in listed["items"]] == [job["id"]]
    assert (await h.client.get("/v1/jobs?status=succeeded", headers=auth(w.token))).json()["items"] == []


async def test_depth_exhausted_names_working_params(h: Harness, ring: KeyRing, bundle_bytes: bytes) -> None:
    w, a, b = await _two_inputs(h, ring, bundle_bytes)
    body = {
        "operation": "logistic_regression",
        "inputs": [a["id"], b["id"]],
        "args": {"weights": [0.5, -0.5], "layout": "columns", "degree": 3},
    }
    resp = await h.client.post(f"/v1/projects/{w.project_id}/jobs", json=body, headers=auth(w.token))
    assert resp.status_code == 422
    err = resp.json()["error"]
    assert err["code"] == "depth_exhausted"
    assert err["details"]["required_depth"] == 3 and err["details"]["available_depth"] == 2
    assert err["details"]["suggested_params"] == standard_params(8192, 128, "deep").to_dict()
    assert h.queue.items == []


async def test_invalid_jobs(h: Harness, ring: KeyRing, bundle_bytes: bytes) -> None:
    w, a, b = await _two_inputs(h, ring, bundle_bytes)
    url = f"/v1/projects/{w.project_id}/jobs"
    cases = [
        ({"operation": "nope", "inputs": [a["id"]]}, "unsupported_operation"),
        ({"operation": "sum", "inputs": [a["id"], b["id"]]}, "unprocessable"),
        ({"operation": "scalar_multiply", "inputs": [a["id"]], "args": {}}, "invalid_argument"),
        ({"operation": "sum", "inputs": [str(uuid.uuid4())]}, "unprocessable"),
    ]
    for body, code in cases:
        resp = await h.client.post(url, json=body, headers=auth(w.token))
        assert resp.status_code == 422, body
        assert resp.json()["error"]["code"] == code, (body, resp.json())
    pending = (
        await h.client.post(
            f"/v1/datasets/{w.dataset_id}/ciphertexts", json={"label": "p", "size_bytes": 10}, headers=auth(w.token)
        )
    ).json()
    resp = await h.client.post(
        url, json={"operation": "sum", "inputs": [pending["ciphertext"]["id"]]}, headers=auth(w.token)
    )
    assert resp.status_code == 422 and "not confirmed" in resp.json()["error"]["message"]


async def test_inputs_must_share_a_bundle(
    h: Harness, ring: KeyRing, bundle_bytes: bytes, deep_ring: KeyRing, deep_bundle_bytes: bytes
) -> None:
    w, a, _ = await _two_inputs(h, ring, bundle_bytes)
    from .conftest import create_dataset, upload_bundle

    deep_bundle = (await upload_bundle(h.client, w.token, w.project_id, deep_bundle_bytes)).json()
    deep_ds = await create_dataset(h.client, w.token, w.project_id, deep_bundle["id"], "deep")
    c = await upload_ciphertext(
        h, w.token, deep_ds["id"], EncryptedVector.encrypt(deep_ring.public_bundle(), [1.0, 1.0, 1.0])
    )
    resp = await h.client.post(
        f"/v1/projects/{w.project_id}/jobs",
        json={"operation": "vector_add", "inputs": [a["id"], c["id"]]},
        headers=auth(w.token),
    )
    assert resp.status_code == 422 and "same key bundle" in resp.json()["error"]["message"]
    # logistic regression *does* fit the deep set
    body = {"operation": "logistic_regression", "inputs": [c["id"]], "args": {"weights": [0.2, 0.1, -0.3], "degree": 3}}
    resp = await h.client.post(f"/v1/projects/{w.project_id}/jobs", json=body, headers=auth(w.token))
    assert resp.status_code == 202 and resp.json()["depth_report"]["levels_consumed"] == 3


async def test_idempotency(h: Harness, ring: KeyRing, bundle_bytes: bytes) -> None:
    w, a, _ = await _two_inputs(h, ring, bundle_bytes)
    url = f"/v1/projects/{w.project_id}/jobs"
    headers = {**auth(w.token), "Idempotency-Key": "run-2026-11-11-0001"}
    first = await h.client.post(url, json={"operation": "sum", "inputs": [a["id"]]}, headers=headers)
    replay = await h.client.post(url, json={"operation": "sum", "inputs": [a["id"]]}, headers=headers)
    assert first.status_code == 202 and replay.status_code == 200
    assert replay.json()["id"] == first.json()["id"]
    assert len(h.queue.items) == 1
    conflict = await h.client.post(url, json={"operation": "mean", "inputs": [a["id"]]}, headers=headers)
    assert conflict.status_code == 409
    bad = await h.client.post(
        url, json={"operation": "sum", "inputs": [a["id"]]}, headers={**auth(w.token), "Idempotency-Key": "x"}
    )
    assert bad.status_code == 422


async def test_queue_failure_marks_job_failed(h: Harness, ring: KeyRing, bundle_bytes: bytes) -> None:
    w, a, _ = await _two_inputs(h, ring, bundle_bytes)
    h.queue.fail_next = True
    resp = await h.client.post(
        f"/v1/projects/{w.project_id}/jobs", json={"operation": "sum", "inputs": [a["id"]]}, headers=auth(w.token)
    )
    assert resp.status_code == 503 and resp.json()["error"]["code"] == "queue_unavailable"
    job_id = resp.json()["error"]["details"]["job_id"]
    job = (await h.client.get(f"/v1/jobs/{job_id}", headers=auth(w.token))).json()
    assert job["status"] == "failed" and job["error"]["code"] == "queue_unavailable"


async def test_cancel_and_result(h: Harness, ring: KeyRing, bundle_bytes: bytes) -> None:
    w, a, _ = await _two_inputs(h, ring, bundle_bytes)
    job = (
        await h.client.post(
            f"/v1/projects/{w.project_id}/jobs", json={"operation": "sum", "inputs": [a["id"]]}, headers=auth(w.token)
        )
    ).json()
    assert (await h.client.get(f"/v1/jobs/{job['id']}/result", headers=auth(w.token))).status_code == 409
    resp = await h.client.post(f"/v1/jobs/{job['id']}/cancel", headers=auth(w.token))
    assert resp.status_code == 200 and resp.json()["status"] == "cancelled"
    assert (await h.client.post(f"/v1/jobs/{job['id']}/cancel", headers=auth(w.token))).status_code == 200

    other = (
        await h.client.post(
            f"/v1/projects/{w.project_id}/jobs", json={"operation": "sum", "inputs": [a["id"]]}, headers=auth(w.token)
        )
    ).json()
    await _finish(h, other["id"], w.org_id, w.project_id)
    assert (await h.client.post(f"/v1/jobs/{other['id']}/cancel", headers=auth(w.token))).status_code == 409
    result = await h.client.get(f"/v1/jobs/{other['id']}/result", headers=auth(w.token))
    assert result.status_code == 200
    body = result.json()
    assert body["manifest_hash"] == other["manifest_hash"] and body["result_length"] == 1
    assert "X-Amz-Signature" in body["download"]["url"]


async def _finish(h: Harness, job_id: str, org_id: str, project_id: str) -> None:
    """What the worker does on success (the worker has its own tests)."""
    from ciphercompute_api.storage.objects import ObjectStore

    async with h.state.session_factory() as session:
        job = await session.get(Job, uuid.UUID(job_id))
        assert job is not None
        job.status = JobStatus.SUCCEEDED
        job.result_object_key = ObjectStore.key_for_result(uuid.UUID(org_id), uuid.UUID(project_id), job.id)
        job.result_length = 1
        job.result_fingerprint = "sha256:" + "0" * 64
        job.finished_at = utcnow()
        await session.commit()


async def test_sse_streams_until_terminal(h: Harness, ring: KeyRing, bundle_bytes: bytes) -> None:
    w, a, _ = await _two_inputs(h, ring, bundle_bytes)
    job = (
        await h.client.post(
            f"/v1/projects/{w.project_id}/jobs", json={"operation": "sum", "inputs": [a["id"]]}, headers=auth(w.token)
        )
    ).json()

    async def complete_later() -> None:
        await asyncio.sleep(0.2)
        await _finish(h, job["id"], w.org_id, w.project_id)

    task = asyncio.create_task(complete_later())
    events: list[str] = []
    async with h.client.stream("GET", f"/v1/jobs/{job['id']}/events", headers=auth(w.token)) as resp:
        assert resp.status_code == 200 and resp.headers["content-type"].startswith("text/event-stream")
        async for line in resp.aiter_lines():
            if line.startswith("event:"):
                events.append(line.split(":", 1)[1].strip())
            if line.startswith("data:") and '"succeeded"' in line:
                break
    await task
    assert events[0] == "status" and len(events) >= 2


async def test_usage(h: Harness, ring: KeyRing, bundle_bytes: bytes) -> None:
    w, a, _ = await _two_inputs(h, ring, bundle_bytes)
    await h.client.post(
        f"/v1/projects/{w.project_id}/jobs", json={"operation": "sum", "inputs": [a["id"]]}, headers=auth(w.token)
    )
    usage = (await h.client.get("/v1/usage", headers=auth(w.token))).json()
    assert usage["jobs_by_status"] == {"queued": 1}
    assert usage["jobs_by_operation"][0]["operation"] == "sum"
    assert usage["storage_bytes"]["key_bundles"] == len(bundle_bytes)
    assert usage["storage_bytes"]["total"] > len(bundle_bytes)
    assert sum(d["jobs"] for d in usage["jobs_per_day"]) == 1
