"""Errors, health, metrics, middleware, storage, rate limiting, catalog, projects."""

from __future__ import annotations

import uuid
from pathlib import Path

import fakeredis
import httpx
import pytest

from ciphercompute_api.errors import RateLimitedError
from ciphercompute_api.ratelimit import RateLimiter
from ciphercompute_api.storage.objects import ObjectStore
from ciphercompute_core import standard_params

from .conftest import Harness, auth, build_harness, create_project, register


async def test_500_has_no_traceback(h: Harness) -> None:
    @h.app.get("/boom")
    async def boom() -> None:
        raise RuntimeError("internal detail: /etc/secret-path")

    # Starlette re-raises after sending the 500 (so servers can log it); a real client only sees the response.
    transport = httpx.ASGITransport(app=h.app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        resp = await client.get("/boom")
    assert resp.status_code == 500
    body = resp.json()
    assert body == {
        "error": {
            "code": "internal_error",
            "message": "an internal error occurred",
            "request_id": resp.headers["X-Request-ID"],
        }
    }
    assert "secret-path" not in resp.text and "Traceback" not in resp.text
    assert "Traceback" in h.log_buffer.getvalue()  # it is in the logs instead


async def test_error_envelope_and_headers(h: Harness) -> None:
    resp = await h.client.get("/v1/projects/not-a-uuid", headers={"X-Request-ID": "abcdef12-3456"})
    assert resp.status_code in (401, 422)
    assert resp.headers["X-Request-ID"] == "abcdef12-3456"
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["X-Frame-Options"] == "DENY"
    user = await register(h.client)
    resp = await h.client.get(f"/v1/projects/{uuid.uuid4()}", headers=auth(user["access_token"]))
    assert resp.status_code == 404 and resp.json()["error"]["code"] == "not_found"
    assert (await h.client.put("/v1/projects", headers=auth(user["access_token"]))).status_code == 405
    # injected request ids are not echoed verbatim
    resp = await h.client.get("/healthz", headers={"X-Request-ID": "<script>alert(1)</script>"})
    assert "<" not in resp.headers["X-Request-ID"]


async def test_oversized_json_body(h: Harness) -> None:
    user = await register(h.client)
    resp = await h.client.post(
        "/v1/projects",
        content=b"{" + b" " * (1024 * 1024 + 10) + b"}",
        headers={**auth(user["access_token"]), "Content-Type": "application/json"},
    )
    assert resp.status_code == 413 and resp.json()["error"]["code"] == "payload_too_large"


async def test_health_ready_metrics(h: Harness) -> None:
    assert (await h.client.get("/healthz")).json() == {"status": "ok"}
    ready = await h.client.get("/readyz")
    assert ready.status_code == 200, ready.text
    assert ready.json()["checks"] == {"database": True, "redis": True, "object_storage": True, "queue": True}
    await register(h.client)
    metrics = await h.client.get("/metrics")
    assert metrics.status_code == 200
    for name in (
        "ciphercompute_http_requests_total",
        "ciphercompute_http_request_duration_seconds",
        "ciphercompute_queue_depth",
    ):
        assert name in metrics.text
    h.state.draining = True
    drained = await h.client.get("/readyz")
    assert drained.status_code == 503 and drained.json()["draining"] is True


async def test_readiness_reports_failed_dependency(h: Harness) -> None:
    async def broken() -> bool:
        raise ConnectionError

    h.state.redis.ping = broken
    resp = await h.client.get("/readyz")
    assert resp.status_code == 503 and resp.json()["checks"]["redis"] is False


async def test_storage_sse_and_reads(h: Harness) -> None:
    org = uuid.uuid4()
    key = ObjectStore.key_for_result(org, uuid.uuid4(), uuid.uuid4())
    await h.store.put_bytes(key, org, b"ciphertext-bytes")
    info = await h.store.head(key, org)
    assert info is not None and info.size == 16 and info.sse == "AES256"
    assert await h.store.get_bytes(key, org, max_bytes=100) == b"ciphertext-bytes"
    assert await h.store.get_range(key, org, 0, 9) == b"ciphertext"
    digest, size = await h.store.sha256_of(key, org, max_bytes=100)
    assert digest.startswith("sha256:") and size == 16
    from ciphercompute_api.errors import PayloadTooLargeError

    with pytest.raises(PayloadTooLargeError):
        await h.store.get_bytes(key, org, max_bytes=4)
    with pytest.raises(PayloadTooLargeError):
        await h.store.sha256_of(key, org, max_bytes=4)
    assert await h.store.head(ObjectStore.key_for_result(org, uuid.uuid4(), uuid.uuid4()), org) is None
    assert await h.store.ping()


async def test_kms_settings_produce_kms_headers(tmp_path: Path, aws: None) -> None:
    async for h in build_harness(
        tmp_path, s3_sse="aws:kms", s3_kms_key_id="arn:aws:kms:us-east-1:111122223333:key/abc"
    ):
        org = uuid.uuid4()
        upload = await h.store.presign_upload(
            ObjectStore.key_for_result(org, uuid.uuid4(), uuid.uuid4()), org, max_bytes=10
        )
        assert upload.fields["x-amz-server-side-encryption"] == "aws:kms"
        assert upload.fields["x-amz-server-side-encryption-aws-kms-key-id"].endswith("key/abc")


async def test_rate_limiter() -> None:
    limiter = RateLimiter(fakeredis.FakeAsyncRedis(), 3)
    assert [await limiter.check("k") for _ in range(3)] == [2, 1, 0]
    with pytest.raises(RateLimitedError) as excinfo:
        await limiter.check("k")
    assert 0 <= excinfo.value.details["retry_after"] <= 60
    assert await limiter.check("other", limit=1) == 0


async def test_per_principal_rate_limit(tmp_path: Path, aws: None) -> None:
    async for h in build_harness(tmp_path, rate_limit_per_minute=3):
        user = await register(h.client)
        codes = [(await h.client.get("/v1/projects", headers=auth(user["access_token"]))).status_code for _ in range(4)]
        assert codes == [200, 200, 200, 429]


async def test_catalog_and_advisor(h: Harness) -> None:
    token = (await register(h.client))["access_token"]
    ops = (await h.client.get("/v1/operations", headers=auth(token))).json()
    assert {o["name"] for o in ops} >= {"mean", "variance", "logistic_regression", "matvec_multiply"}
    logistic = next(o for o in ops if o["name"] == "logistic_regression")
    assert logistic["sigmoid"]["domain"] == [-8.0, 8.0]
    sets = (await h.client.get("/v1/parameter-sets", headers=auth(token))).json()
    assert len(sets) == 17
    first = sets[0]
    assert (
        first["poly_modulus_degree"] == 8192
        and first["precision_measured"]
        and set(first["precision_bits_by_level"]) == {"slotwise", "rotations"}
        and set(first["precision_bits_by_level"]["rotations"]) == {"0", "1", "2"}
    )
    advice = await h.client.post(
        "/v1/advisor",
        json={
            "steps": [{"operation": "logistic_regression", "args": {"weights": [0.5, -0.2], "degree": 5}}],
            "input_lengths": [2],
        },
        headers=auth(token),
    )
    assert advice.status_code == 200
    assert (
        advice.json()["params"] == standard_params(8192, 128, "deep").to_dict() and advice.json()["required_depth"] == 4
    )
    impossible = await h.client.post(
        "/v1/advisor",
        json={"steps": [{"operation": "scalar_multiply", "args": {"scalar": 2}}] * 20, "input_lengths": [2]},
        headers=auth(token),
    )
    assert impossible.status_code == 422 and impossible.json()["error"]["code"] == "depth_exhausted"


async def test_project_crud_and_pagination(h: Harness) -> None:
    token = (await register(h.client))["access_token"]
    ids = [(await create_project(h.client, token, f"p{i}"))["id"] for i in range(5)]
    assert (await h.client.post("/v1/projects", json={"name": "p0"}, headers=auth(token))).status_code == 409
    page1 = (await h.client.get("/v1/projects?limit=2", headers=auth(token))).json()
    assert [p["id"] for p in page1["items"]] == ids[::-1][:2] and page1["next_cursor"]
    page2 = (await h.client.get(f"/v1/projects?limit=2&before={page1['next_cursor']}", headers=auth(token))).json()
    assert [p["id"] for p in page2["items"]] == ids[::-1][2:4]
    assert (await h.client.get("/v1/projects?limit=0", headers=auth(token))).status_code == 422
    assert (await h.client.get("/v1/projects?before=zzz", headers=auth(token))).status_code == 422
    resp = await h.client.patch(f"/v1/projects/{ids[0]}", json={"name": "p1"}, headers=auth(token))
    assert resp.status_code == 409
    resp = await h.client.patch(
        f"/v1/projects/{ids[0]}", json={"name": "renamed", "description": "d"}, headers=auth(token)
    )
    assert resp.json()["name"] == "renamed" and resp.json()["description"] == "d"
    assert (await h.client.delete(f"/v1/projects/{ids[0]}", headers=auth(token))).status_code == 204
    assert (await h.client.get(f"/v1/projects/{ids[0]}", headers=auth(token))).status_code == 404


async def test_openapi_documents_every_route(h: Harness) -> None:
    spec = (await h.client.get("/openapi.json")).json()
    assert spec["openapi"].startswith("3.1")
    paths = spec["paths"]
    assert "/v1/projects/{project_id}/jobs" in paths and "/v1/advisor" in paths
    bundle = paths["/v1/projects/{project_id}/key-bundles"]["post"]
    assert "application/octet-stream" in bundle["requestBody"]["content"]
    job_schema = spec["components"]["schemas"]["JobCreate"]
    assert job_schema.get("examples")
    docs = await h.client.get("/docs")
    assert docs.status_code == 200 and "swagger" in docs.text.lower()


async def test_no_plaintext_result_endpoint(h: Harness) -> None:
    # TM:I-8 - a decryption oracle needs a channel that carries decrypted values to the service.
    # No route may be about decryption, and no request body may accept result values.
    spec = (await h.client.get("/openapi.json")).json()
    forbidden = ("decrypt", "plaintext", "cleartext")
    for path in spec["paths"]:
        assert not any(word in path.lower() for word in forbidden), path
    for name, schema in spec["components"]["schemas"].items():
        properties = {p.lower() for p in schema.get("properties", {})}
        assert not properties & {"values", "decrypted", "plaintext", "result_values"}, name
