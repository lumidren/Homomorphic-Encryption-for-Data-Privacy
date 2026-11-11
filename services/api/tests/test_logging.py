"""No secret in logs, ever: drive a full flow, capture every log line, grep for key material."""

from __future__ import annotations

import logging
import re

from ciphercompute_api.logging import REDACTED, get_logger, scrub_processor, scrub_value
from ciphercompute_core import EncryptedVector, KeyRing

from .conftest import PASSWORD, Harness, auth, make_world, register, upload_ciphertext

KEY_MATERIAL_PATTERNS = [
    re.compile(r"cc_[A-Za-z0-9]{16,}"),
    re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"CCSK"),
    re.compile(r"\$argon2id\$"),
]


async def test_no_key_material_in_captured_logs(h: Harness, ring: KeyRing, bundle_bytes: bytes) -> None:
    w = await make_world(h, bundle_bytes)
    user = await register(h.client, "logcheck@example.com")
    await h.client.post("/v1/auth/login", json={"email": "logcheck@example.com", "password": PASSWORD})
    refreshed = (await h.client.post("/v1/auth/refresh", json={"refresh_token": user["refresh_token"]})).json()
    await h.client.post("/v1/auth/refresh", json={"refresh_token": user["refresh_token"]})  # reuse -> warning log
    key = (
        await h.client.post("/v1/api-keys", json={"name": "k", "scopes": ["jobs:read"]}, headers=auth(w.token))
    ).json()["secret"]
    await h.client.get("/v1/jobs", headers=auth(key))
    ct = await upload_ciphertext(h, w.token, w.dataset_id, EncryptedVector.encrypt(ring.public_bundle(), [3.0]))
    await h.client.post(
        f"/v1/projects/{w.project_id}/jobs", json={"operation": "sum", "inputs": [ct["id"]]}, headers=auth(w.token)
    )
    # deliberately log secrets the way a careless developer might
    log = get_logger("careless")
    log.info("debugging", token=w.token, api_key=key, refresh=refreshed["refresh_token"], note=f"Bearer {w.token}")
    logging.getLogger("stdlib").warning("raw %s", w.token)

    captured = h.log_buffer.getvalue()
    assert captured.count("\n") > 20, "logging capture is not working"
    for secret in (w.token, key, user["refresh_token"], refreshed["refresh_token"], PASSWORD):
        assert secret not in captured
    for pattern in KEY_MATERIAL_PATTERNS:
        assert not pattern.search(captured), pattern.pattern
    assert REDACTED in captured


def test_scrub_value_patterns() -> None:
    assert scrub_value("key cc_" + "a" * 30) == f"key {REDACTED}"
    assert scrub_value("postgresql+asyncpg://user:hunter2@db/x") == f"{REDACTED}db/x"
    assert scrub_value("redis://:pw@cache:6379") == f"{REDACTED}cache:6379"
    assert scrub_value("AKIAABCDEFGHIJKLMNOP") == REDACTED
    assert scrub_value(b"\x00\x01") == "<2 bytes>"
    assert scrub_value({"password": "x", "nested": {"api_key": "y", "ok": "fine"}}) == {
        "password": REDACTED,
        "nested": {"api_key": REDACTED, "ok": "fine"},
    }
    assert scrub_value(["cc_" + "b" * 20, 3]) == [REDACTED, 3]
    assert scrub_value(7) == 7


def test_processor_redacts_by_key_but_keeps_event() -> None:
    out = scrub_processor(None, "info", {"event": "x", "Authorization": "Bearer abc", "count": 3, "secret_thing": 1})
    assert out == {"event": "x", "Authorization": REDACTED, "count": 3, "secret_thing": REDACTED}
