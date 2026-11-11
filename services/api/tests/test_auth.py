from __future__ import annotations

from pathlib import Path

import jwt
import pytest

from ciphercompute_api.auth.passwords import PasswordService
from ciphercompute_api.config import Settings

from .conftest import JWT_SECRET, PASSWORD, Harness, auth, build_harness, register


async def test_register_login_me(h: Harness) -> None:
    user = await register(h.client, "ada@example.com")
    assert user["role"] == "owner" and user["token_type"] == "bearer"
    me = await h.client.get("/v1/auth/me", headers=auth(user["access_token"]))
    assert me.status_code == 200
    assert me.json()["email"] == "ada@example.com" and "members:manage" in me.json()["scopes"]

    resp = await h.client.post("/v1/auth/login", json={"email": "ADA@example.com", "password": PASSWORD})
    assert resp.status_code == 200 and resp.json()["organization_id"] == user["organization_id"]


async def test_duplicate_registration(h: Harness) -> None:
    await register(h.client, "dup@example.com")
    resp = await h.client.post(
        "/v1/auth/register", json={"email": "dup@example.com", "password": PASSWORD, "organization_name": "x2"}
    )
    assert resp.status_code == 409 and resp.json()["error"]["code"] == "conflict"


async def test_weak_password_rejected(h: Harness) -> None:
    resp = await h.client.post(
        "/v1/auth/register", json={"email": "w@example.com", "password": "short", "organization_name": "org"}
    )
    assert resp.status_code == 422 and resp.json()["error"]["code"] == "validation_error"


@pytest.mark.parametrize("email", ["ada@example.com", "nobody@example.com"])
async def test_bad_credentials_same_response(h: Harness, email: str) -> None:
    await register(h.client, "ada@example.com")
    resp = await h.client.post("/v1/auth/login", json={"email": email, "password": "wrong password!!"})
    assert resp.status_code == 401
    assert resp.json()["error"]["message"] == "invalid email or password"


async def test_login_to_unknown_org_refused(h: Harness) -> None:
    await register(h.client, "ada@example.com")
    resp = await h.client.post(
        "/v1/auth/login",
        json={
            "email": "ada@example.com",
            "password": PASSWORD,
            "organization_id": "01934f6e-0000-7000-8000-000000000000",
        },
    )
    assert resp.status_code == 401


async def test_login_rate_limited(tmp_path: Path, aws: None) -> None:
    async for h in build_harness(tmp_path, login_rate_limit_per_minute=3):
        for _ in range(3):
            assert (
                await h.client.post("/v1/auth/login", json={"email": "x@example.com", "password": "nope-nope-nope"})
            ).status_code == 401
        resp = await h.client.post("/v1/auth/login", json={"email": "x@example.com", "password": "nope-nope-nope"})
        assert resp.status_code == 429
        assert int(resp.headers["Retry-After"]) >= 0
        assert resp.json()["error"]["code"] == "rate_limited"


async def test_missing_and_malformed_tokens(h: Harness) -> None:
    assert (await h.client.get("/v1/auth/me")).status_code == 401
    assert (await h.client.get("/v1/auth/me", headers={"Authorization": "Basic abc"})).status_code == 401
    assert (await h.client.get("/v1/auth/me", headers=auth("not.a.jwt"))).status_code == 401
    forged = jwt.encode({"sub": "x"}, "another-secret-" + "y" * 40, algorithm="HS256", headers={"kid": "v1"})
    assert (await h.client.get("/v1/auth/me", headers=auth(forged))).status_code == 401
    unknown_kid = jwt.encode({"sub": "x"}, JWT_SECRET, algorithm="HS256", headers={"kid": "zz"})
    assert (await h.client.get("/v1/auth/me", headers=auth(unknown_kid))).status_code == 401


async def test_expired_token(h: Harness) -> None:
    user = await register(h.client)
    claims = jwt.decode(user["access_token"], JWT_SECRET, algorithms=["HS256"], options={"verify_exp": False})
    claims["exp"] = claims["iat"] - 10
    expired = jwt.encode(claims, JWT_SECRET, algorithm="HS256", headers={"kid": "v1"})
    resp = await h.client.get("/v1/auth/me", headers=auth(expired))
    assert resp.status_code == 401 and resp.json()["error"]["message"] == "token expired"


async def test_refresh_rotates(h: Harness) -> None:
    user = await register(h.client)
    resp = await h.client.post("/v1/auth/refresh", json={"refresh_token": user["refresh_token"]})
    assert resp.status_code == 200
    rotated = resp.json()
    assert rotated["refresh_token"] != user["refresh_token"]
    assert (await h.client.get("/v1/auth/me", headers=auth(rotated["access_token"]))).status_code == 200


async def test_refresh_reuse_revokes_family(h: Harness) -> None:
    user = await register(h.client)
    first = await h.client.post("/v1/auth/refresh", json={"refresh_token": user["refresh_token"]})
    new_refresh = first.json()["refresh_token"]
    # replaying the already-rotated token is treated as theft ...
    replay = await h.client.post("/v1/auth/refresh", json={"refresh_token": user["refresh_token"]})
    assert replay.status_code == 401 and replay.json()["error"]["code"] == "refresh_token_reuse"
    # ... which revokes the legitimate successor too
    after = await h.client.post("/v1/auth/refresh", json={"refresh_token": new_refresh})
    assert after.status_code == 401
    audit = (await h.client.get("/v1/audit?action=token.reuse_detected", headers=auth(user["access_token"]))).json()
    assert len(audit["items"]) == 2  # the replay, then the revoked successor


async def test_refresh_unknown_token(h: Harness) -> None:
    resp = await h.client.post("/v1/auth/refresh", json={"refresh_token": "x" * 40})
    assert resp.status_code == 401


async def test_logout_denylists_access_and_revokes_refresh(h: Harness) -> None:
    user = await register(h.client)
    resp = await h.client.post(
        "/v1/auth/logout", json={"refresh_token": user["refresh_token"]}, headers=auth(user["access_token"])
    )
    assert resp.status_code == 204
    me = await h.client.get("/v1/auth/me", headers=auth(user["access_token"]))
    assert me.status_code == 401 and me.json()["error"]["message"] == "token revoked"
    assert (await h.client.post("/v1/auth/refresh", json={"refresh_token": user["refresh_token"]})).status_code == 401


async def test_self_registration_can_be_disabled(tmp_path: Path, aws: None) -> None:
    async for h in build_harness(tmp_path, allow_self_registration=False):
        resp = await h.client.post(
            "/v1/auth/register", json={"email": "a@example.com", "password": PASSWORD, "organization_name": "org"}
        )
        assert resp.status_code == 403


def test_argon2id_parameters() -> None:
    svc = PasswordService(Settings(jwt_secret="z" * 40))
    assert svc.parameters == {"type": "argon2id", "time_cost": 3, "memory_kib": 65536, "parallelism": 4}
    digest = svc.hash("correct horse battery staple")
    assert digest.startswith("$argon2id$v=19$m=65536,t=3,p=4$")
    assert svc.verify("correct horse battery staple", digest)
    assert not svc.verify("wrong", digest)
    assert not svc.verify("anything", "not-a-hash")
    assert not svc.needs_rehash(digest)


def test_short_jwt_secret_rejected() -> None:
    with pytest.raises(ValueError, match="at least 32 bytes"):
        Settings(jwt_secret="short")
