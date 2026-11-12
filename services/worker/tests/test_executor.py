"""End to end through the executor: real CKKS computation, decrypted client-side."""

from __future__ import annotations

import uuid
from datetime import timedelta
from pathlib import Path

import numpy as np
import pytest
from botocore.exceptions import ClientError

from ciphercompute_api.db.base import utcnow
from ciphercompute_api.db.models import Job, JobStatus
from ciphercompute_core import EncryptedVector, KeyRing, PublicKeyBundle
from ciphercompute_core.sigmoid import sigmoid_poly
from ciphercompute_worker import executor, tasks
from ciphercompute_worker.executor import backoff_seconds, run_job

from .conftest import Env, build_env


def ids(env: Env, job: dict[str, object]) -> tuple[uuid.UUID, uuid.UUID]:
    return uuid.UUID(str(job["id"])), uuid.UUID(env.org_id)


async def _mean_job(env: Env, ring: KeyRing, values: list[float]) -> dict[str, object]:
    ds = await env.dataset(await env.bundle(ring))
    ct = await env.ciphertext(ds, EncryptedVector.encrypt(ring.public_bundle(), values))
    return await env.submit("mean", [ct["id"]])


async def test_mean_end_to_end(env: Env, ring: KeyRing) -> None:
    values = [120.0, 135.5, 142.0, 118.25]
    job = await _mean_job(env, ring, values)
    outcome = await run_job(env.ctx, *ids(env, job))
    assert outcome.kind == "succeeded", outcome

    done = await env.job(str(job["id"]))
    assert done["status"] == "succeeded" and done["attempts"] == 1 and done["compute_seconds"] > 0
    assert done["depth_report"]["levels_consumed"] == 1 and done["depth_report"]["precision_measured"] is True
    result = await env.result(ring, str(job["id"]))
    assert ring.decrypt(result)[0] == pytest.approx(np.mean(values), abs=1e-4)
    actions = [e["action"] for e in (await env.client.get("/v1/audit", headers=env.headers())).json()["items"]]
    assert "job.started" in actions and "job.completed" in actions
    # the API can now hand out the result
    assert (await env.client.get(f"/v1/jobs/{job['id']}/result", headers=env.headers())).status_code == 200


async def test_logistic_regression_columns_on_deep_params(env: Env, deep_ring: KeyRing) -> None:
    rng = np.random.default_rng(3)
    features = rng.uniform(-1, 1, (3, 16))  # 3 features x 16 patients
    weights, intercept = [0.9, -0.6, 0.4], -0.2
    ds = await env.dataset(await env.bundle(deep_ring))
    pub = deep_ring.public_bundle()
    cts = [await env.ciphertext(ds, EncryptedVector.encrypt(pub, col), f"f{i}") for i, col in enumerate(features)]
    job = await env.submit(
        "logistic_regression",
        [c["id"] for c in cts],
        {"weights": weights, "intercept": intercept, "layout": "columns", "degree": 3},
    )
    assert (await run_job(env.ctx, *ids(env, job))).kind == "succeeded"
    scores = deep_ring.decrypt(await env.result(deep_ring, str(job["id"])))
    expected = sigmoid_poly(np.asarray(weights) @ features + intercept, 3)
    assert scores.shape == (16,)
    assert np.max(np.abs(scores - expected)) < 1e-2


async def test_duplicate_delivery_noop(env: Env, ring: KeyRing) -> None:
    job = await _mean_job(env, ring, [1.0, 2.0])
    assert (await run_job(env.ctx, *ids(env, job))).kind == "succeeded"
    again = await run_job(env.ctx, *ids(env, job))
    assert again.kind == "noop"
    assert (await env.job(str(job["id"])))["attempts"] == 1


async def test_cancelled_and_missing_jobs_noop(env: Env, ring: KeyRing) -> None:
    job = await _mean_job(env, ring, [1.0])
    await env.client.post(f"/v1/jobs/{job['id']}/cancel", headers=env.headers())
    assert (await run_job(env.ctx, *ids(env, job))).kind == "noop"
    assert (await run_job(env.ctx, uuid.uuid4(), uuid.UUID(env.org_id))).kind == "noop"
    # a job id from another organization is invisible
    assert (await run_job(env.ctx, uuid.UUID(str(job["id"])), uuid.uuid4())).kind == "noop"


async def test_tampered_input_fails_integrity(env: Env, ring: KeyRing) -> None:
    ds = await env.dataset(await env.bundle(ring))
    pub = ring.public_bundle()
    ct = await env.ciphertext(ds, EncryptedVector.encrypt(pub, [1.0, 2.0]))
    job = await env.submit("sum", [ct["id"]])
    # a malicious storage layer swaps in a different (valid!) ciphertext under the same key
    await env.store.put_bytes(
        env.object_key(ds, ct["id"]), uuid.UUID(env.org_id), EncryptedVector.encrypt(pub, [999.0, 999.0]).to_bytes()
    )
    outcome = await run_job(env.ctx, *ids(env, job))
    assert outcome == executor.Outcome("failed", "input_integrity")
    failed = await env.job(str(job["id"]))
    assert failed["status"] == "failed" and failed["error"]["code"] == "input_integrity"


async def test_revoked_bundle_fails(env: Env, ring: KeyRing) -> None:
    job = await _mean_job(env, ring, [1.0])
    bundle_id = (await env.client.get(f"/v1/projects/{env.project_id}/key-bundles", headers=env.headers())).json()[0][
        "id"
    ]
    await env.client.post(f"/v1/key-bundles/{bundle_id}/revoke", headers=env.headers())
    assert (await run_job(env.ctx, *ids(env, job))).detail == "bundle_revoked"


async def test_deleted_input_fails(env: Env, ring: KeyRing) -> None:
    ds = await env.dataset(await env.bundle(ring))
    ct = await env.ciphertext(ds, EncryptedVector.encrypt(ring.public_bundle(), [1.0]))
    job = await env.submit("sum", [ct["id"]])
    await env.client.delete(f"/v1/ciphertexts/{ct['id']}", headers=env.headers())
    assert (await run_job(env.ctx, *ids(env, job))).detail == "input_missing"


async def test_transient_error_retries_then_succeeds(env: Env, ring: KeyRing, monkeypatch: pytest.MonkeyPatch) -> None:
    job = await _mean_job(env, ring, [2.0, 4.0])
    real = env.store.get_bytes
    calls = {"n": 0}

    async def flaky(*args, **kwargs):  # type: ignore[no-untyped-def]
        calls["n"] += 1
        if calls["n"] == 1:
            raise ClientError({"Error": {"Code": "SlowDown", "Message": "slow down"}}, "GetObject")
        return await real(*args, **kwargs)

    monkeypatch.setattr(env.store, "get_bytes", flaky)
    first = await run_job(env.ctx, *ids(env, job))
    assert first.kind == "retry" and 0.5 <= first.countdown < 1.5
    queued = await env.job(str(job["id"]))
    assert queued["status"] == "queued" and queued["error"]["code"] == "transient" and queued["attempts"] == 1
    assert (await run_job(env.ctx, *ids(env, job))).kind == "succeeded"
    done = await env.job(str(job["id"]))
    assert done["attempts"] == 2 and done["error"] is None


async def test_retries_exhausted(env: Env, ring: KeyRing, monkeypatch: pytest.MonkeyPatch) -> None:
    job = await _mean_job(env, ring, [1.0])

    async def down(*args, **kwargs):  # type: ignore[no-untyped-def]
        raise ConnectionError("storage unreachable")

    monkeypatch.setattr(env.store, "get_bytes", down)
    kinds = [(await run_job(env.ctx, *ids(env, job))).kind for _ in range(3)]
    assert kinds == ["retry", "retry", "failed"]
    assert (await env.job(str(job["id"])))["error"]["code"] == "retries_exhausted"


async def test_unexpected_error_fails_without_retry(env: Env, ring: KeyRing, monkeypatch: pytest.MonkeyPatch) -> None:
    job = await _mean_job(env, ring, [1.0])

    def boom(*args, **kwargs):  # type: ignore[no-untyped-def]
        raise RuntimeError("scale out of bounds")

    monkeypatch.setattr(executor, "apply_operation", boom)
    outcome = await run_job(env.ctx, *ids(env, job))
    assert outcome == executor.Outcome("failed", "execution_error")


async def test_depth_mismatch_is_refused(env: Env, ring: KeyRing) -> None:
    job = await _mean_job(env, ring, [1.0])
    async with env.ctx.session_factory() as session:
        row = await session.get(Job, uuid.UUID(str(job["id"])))
        assert row is not None
        row.plan = {**row.plan, "report": {**row.plan["report"], "levels_consumed": 0}}
        await session.commit()
    assert (await run_job(env.ctx, *ids(env, job))).detail == "depth_mismatch"


async def test_forged_header_depth_is_caught(env: Env, ring: KeyRing) -> None:
    """A ciphertext whose header under-reports its consumed levels is rejected by the worker."""
    ds = await env.dataset(await env.bundle(ring))
    ct = await env.ciphertext(ds, EncryptedVector.encrypt(ring.public_bundle(), [1.0, 2.0]))
    job = await env.submit("mean", [ct["id"]])
    # swap the bytes for a deeper ciphertext *and* forge the recorded fingerprint, as a full
    # storage+DB compromise could; the ciphertext's real level now exceeds what was planned
    deeper = EncryptedVector.encrypt(ring.public_bundle(), [1.0, 2.0])
    deeper = deeper.spawn(deeper.raw() * 1.0, 2)
    data = deeper.to_bytes()
    await env.store.put_bytes(env.object_key(ds, ct["id"]), uuid.UUID(env.org_id), data)
    async with env.ctx.session_factory() as session:
        row = await session.get(Job, uuid.UUID(str(job["id"])))
        assert row is not None
        row.input_fingerprints = [executor.sha256_fingerprint(data)]
        await session.commit()
    outcome = await run_job(env.ctx, *ids(env, job))
    assert outcome.kind == "failed" and outcome.detail == "depth_mismatch"


async def test_tenant_throttling_and_starvation(tmp_path: Path, ring: KeyRing) -> None:
    async for env in build_env(tmp_path, tenant_max_concurrent_jobs=1, max_queue_wait_seconds=60):
        job = await _mean_job(env, ring, [1.0])
        org = uuid.UUID(env.org_id)
        assert await env.ctx.semaphore.acquire(org, uuid.uuid4(), 1)  # another job holds the only slot
        throttled = await run_job(env.ctx, *ids(env, job))
        assert throttled.kind == "throttled" and throttled.countdown >= 2
        assert (await env.job(str(job["id"])))["status"] == "queued"
        async with env.ctx.session_factory() as session:
            row = await session.get(Job, uuid.UUID(str(job["id"])))
            assert row is not None
            row.created_at = utcnow() - timedelta(hours=2)
            await session.commit()
        starved = await run_job(env.ctx, *ids(env, job))
        assert starved == executor.Outcome("failed", "starved")


async def test_stale_running_job_is_reclaimed(env: Env, ring: KeyRing) -> None:
    job = await _mean_job(env, ring, [5.0])
    async with env.ctx.session_factory() as session:
        row = await session.get(Job, uuid.UUID(str(job["id"])))
        assert row is not None
        row.status, row.worker_id = JobStatus.RUNNING, "dead-worker"
        row.started_at = utcnow()
        await session.commit()
    assert (await run_job(env.ctx, *ids(env, job))).kind == "noop"  # still fresh: someone else owns it
    async with env.ctx.session_factory() as session:
        row = await session.get(Job, uuid.UUID(str(job["id"])))
        assert row is not None
        row.started_at = utcnow() - timedelta(hours=1)
        await session.commit()
    assert (await run_job(env.ctx, *ids(env, job))).kind == "succeeded"


async def test_bundle_cache_reuses_and_evicts(
    env: Env, ring: KeyRing, deep_ring: KeyRing, monkeypatch: pytest.MonkeyPatch
) -> None:
    loads = {"n": 0}
    real = PublicKeyBundle.load

    def counting(data: bytes) -> PublicKeyBundle:
        loads["n"] += 1
        return real(data)

    class CountingBundle:
        load = staticmethod(counting)

    # only the worker's reference is swapped; the API keeps the real class
    monkeypatch.setattr(executor, "PublicKeyBundle", CountingBundle)
    env.ctx.settings.bundle_cache_size = 1
    job1 = await _mean_job(env, ring, [1.0])
    ds = (await env.client.get(f"/v1/projects/{env.project_id}/datasets", headers=env.headers())).json()["items"][0][
        "id"
    ]
    ct = await env.ciphertext(ds, EncryptedVector.encrypt(ring.public_bundle(), [2.0]))
    job2 = await env.submit("sum", [ct["id"]])
    for job in (job1, job2):
        assert (await run_job(env.ctx, *ids(env, job))).kind == "succeeded"
    assert loads["n"] == 1  # second job served from cache
    deep_ds = await env.dataset(await env.bundle(deep_ring), "deep")
    deep_ct = await env.ciphertext(deep_ds, EncryptedVector.encrypt(deep_ring.public_bundle(), [1.0]))
    job3 = await env.submit("sum", [deep_ct["id"]])
    assert (await run_job(env.ctx, *ids(env, job3))).kind == "succeeded"
    assert loads["n"] == 2 and len(env.ctx.bundle_cache) == 1


def test_backoff_bounds() -> None:
    from ciphercompute_worker.config import WorkerSettings

    s = WorkerSettings(retry_backoff_base_seconds=2, retry_backoff_max_seconds=30)
    for attempt, base in [(1, 2), (2, 4), (3, 8), (10, 30)]:
        for _ in range(20):
            assert 0.5 * base <= backoff_seconds(s, attempt) < 1.5 * base


async def test_task_runner_builds_its_own_context(env: Env, ring: KeyRing, monkeypatch: pytest.MonkeyPatch) -> None:
    """``tasks._run`` is what Celery calls: fresh engine and Redis per event loop."""
    import fakeredis

    job = await _mean_job(env, ring, [3.0, 5.0])
    monkeypatch.setattr(tasks.settings, "database_url", env.ctx.settings.database_url)
    monkeypatch.setattr(tasks, "_store", env.store)
    monkeypatch.setattr(tasks.Redis, "from_url", staticmethod(lambda url: fakeredis.FakeAsyncRedis()))
    outcome = await tasks._run(*ids(env, job))
    assert outcome.kind == "succeeded"
    assert ring.decrypt(await env.result(ring, str(job["id"])))[0] == pytest.approx(4.0, abs=1e-4)
