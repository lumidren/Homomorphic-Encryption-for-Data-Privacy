from __future__ import annotations

import hmac
import uuid
from datetime import timedelta

import pytest
from sqlalchemy import select

from ciphercompute_api.auth import api_keys
from ciphercompute_api.auth.api_keys import generate_api_key, hash_api_key, looks_like_api_key, verify_api_key
from ciphercompute_api.db.base import utcnow
from ciphercompute_api.db.models import ApiKey

from .conftest import Harness, auth, register


def test_key_format_and_entropy() -> None:
    secret, prefix, digest = generate_api_key()
    assert secret.startswith("cc_") and len(secret) == 3 + 48
    assert prefix == secret[:12]
    assert digest == hash_api_key(secret) and len(digest) == 64
    assert looks_like_api_key(secret) and not looks_like_api_key("eyJhbGciOi")
    assert len({generate_api_key()[0] for _ in range(200)}) == 200


def test_constant_time_compare(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, str]] = []
    real = hmac.compare_digest

    def spy(a: str, b: str) -> bool:
        calls.append((a, b))
        return real(a, b)

    monkeypatch.setattr(api_keys.hmac, "compare_digest", spy)
    secret, _, digest = generate_api_key()
    assert verify_api_key(secret, digest)
    assert not verify_api_key(secret + "x", digest)
    assert len(calls) == 2


async def test_key_never_stored_plain(h: Harness) -> None:
    owner = await register(h.client)
    secret = (
        await h.client.post(
            "/v1/api-keys", json={"name": "k", "scopes": ["jobs:read"]}, headers=auth(owner["access_token"])
        )
    ).json()["secret"]
    async with h.state.session_factory() as session:
        row = (await session.execute(select(ApiKey))).scalar_one()
    stored = " ".join(str(getattr(row, c.key)) for c in ApiKey.__table__.columns)
    assert secret not in stored
    assert row.key_hash == hash_api_key(secret)


async def test_expired_key_rejected(h: Harness) -> None:
    owner = await register(h.client)
    created = (
        await h.client.post(
            "/v1/api-keys",
            json={"name": "k", "scopes": ["jobs:read"], "expires_in_days": 1},
            headers=auth(owner["access_token"]),
        )
    ).json()
    async with h.state.session_factory() as session:
        row = await session.get(ApiKey, uuid.UUID(created["api_key"]["id"]))
        assert row is not None
        row.expires_at = utcnow() - timedelta(seconds=1)
        await session.commit()
    resp = await h.client.get("/v1/jobs", headers=auth(created["secret"]))
    assert resp.status_code == 401 and resp.json()["error"]["message"] == "API key expired"
