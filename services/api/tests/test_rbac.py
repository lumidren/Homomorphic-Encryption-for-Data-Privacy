"""Role x route matrix, member management and API-key scopes."""

from __future__ import annotations

import pytest

from ciphercompute_api.auth.api_keys import check_scope_ceiling, role_for_scopes, scopes_for_role
from ciphercompute_api.auth.rbac import assert_can_assign_role
from ciphercompute_api.db.models import Role
from ciphercompute_api.errors import ForbiddenError, UnprocessableError

from .conftest import PASSWORD, Harness, auth, create_project, register


async def _member(h: Harness, owner_token: str, role: str) -> str:
    """Register a user elsewhere, add them to the owner's org with ``role``, log in there."""
    other = await register(h.client, org="Elsewhere")
    org_id = (await h.client.get("/v1/auth/me", headers=auth(owner_token))).json()["organization_id"]
    resp = await h.client.post(
        "/v1/organization/members", json={"email": other["email"], "role": role}, headers=auth(owner_token)
    )
    assert resp.status_code == 201, resp.text
    login = await h.client.post(
        "/v1/auth/login", json={"email": other["email"], "password": PASSWORD, "organization_id": org_id}
    )
    assert login.status_code == 200 and login.json()["role"] == role
    return login.json()["access_token"]  # type: ignore[no-any-return]


@pytest.mark.parametrize(
    ("role", "create_project_status", "delete_project_status", "add_member_status", "list_keys_status"),
    [
        ("viewer", 403, 403, 403, 403),
        ("analyst", 201, 403, 403, 403),
        ("admin", 201, 204, 201, 200),
    ],
)
async def test_role_matrix(
    h: Harness,
    role: str,
    create_project_status: int,
    delete_project_status: int,
    add_member_status: int,
    list_keys_status: int,
) -> None:
    owner = await register(h.client)
    token = await _member(h, owner["access_token"], role)
    target = await create_project(h.client, owner["access_token"], "target")

    assert (await h.client.get("/v1/projects", headers=auth(token))).status_code == 200
    assert (
        await h.client.post("/v1/projects", json={"name": "mine"}, headers=auth(token))
    ).status_code == create_project_status
    assert (
        await h.client.delete(f"/v1/projects/{target['id']}", headers=auth(token))
    ).status_code == delete_project_status
    newcomer = await register(h.client, org="Third")
    resp = await h.client.post(
        "/v1/organization/members", json={"email": newcomer["email"], "role": "viewer"}, headers=auth(token)
    )
    assert resp.status_code == add_member_status
    assert (await h.client.get("/v1/api-keys", headers=auth(token))).status_code == list_keys_status


async def test_only_owner_changes_roles_and_last_owner_is_kept(h: Harness) -> None:
    owner = await register(h.client)
    admin = await _member(h, owner["access_token"], "admin")
    members = (await h.client.get("/v1/organization/members", headers=auth(owner["access_token"]))).json()
    owner_id = next(m["user_id"] for m in members if m["role"] == "owner")
    admin_id = next(m["user_id"] for m in members if m["role"] == "admin")

    resp = await h.client.patch(f"/v1/organization/members/{owner_id}", json={"role": "viewer"}, headers=auth(admin))
    assert resp.status_code == 403
    resp = await h.client.patch(
        f"/v1/organization/members/{owner_id}", json={"role": "admin"}, headers=auth(owner["access_token"])
    )
    assert resp.status_code == 409 and "at least one owner" in resp.json()["error"]["message"]
    resp = await h.client.delete(f"/v1/organization/members/{owner_id}", headers=auth(owner["access_token"]))
    assert resp.status_code == 409
    # admins cannot remove admins; owners can
    resp = await h.client.delete(f"/v1/organization/members/{admin_id}", headers=auth(admin))
    assert resp.status_code == 403
    resp = await h.client.patch(
        f"/v1/organization/members/{admin_id}", json={"role": "viewer"}, headers=auth(owner["access_token"])
    )
    assert resp.status_code == 200 and resp.json()["role"] == "viewer"


async def test_demotion_applies_to_existing_token(h: Harness) -> None:
    owner = await register(h.client)
    analyst = await _member(h, owner["access_token"], "analyst")
    assert (await h.client.post("/v1/projects", json={"name": "a"}, headers=auth(analyst))).status_code == 201
    members = (await h.client.get("/v1/organization/members", headers=auth(owner["access_token"]))).json()
    analyst_id = next(m["user_id"] for m in members if m["role"] == "analyst")
    await h.client.patch(
        f"/v1/organization/members/{analyst_id}", json={"role": "viewer"}, headers=auth(owner["access_token"])
    )
    assert (await h.client.post("/v1/projects", json={"name": "b"}, headers=auth(analyst))).status_code == 403


async def test_removed_member_token_rejected(h: Harness) -> None:
    owner = await register(h.client)
    viewer = await _member(h, owner["access_token"], "viewer")
    members = (await h.client.get("/v1/organization/members", headers=auth(owner["access_token"]))).json()
    viewer_id = next(m["user_id"] for m in members if m["role"] == "viewer")
    assert (
        await h.client.delete(f"/v1/organization/members/{viewer_id}", headers=auth(owner["access_token"]))
    ).status_code == 204
    assert (await h.client.get("/v1/projects", headers=auth(viewer))).status_code == 401


async def test_add_member_errors(h: Harness) -> None:
    owner = await register(h.client)
    resp = await h.client.post(
        "/v1/organization/members",
        json={"email": "ghost@example.com", "role": "viewer"},
        headers=auth(owner["access_token"]),
    )
    assert resp.status_code == 404
    other = await register(h.client, org="Other Org")
    payload = {"email": other["email"], "role": "viewer"}
    assert (
        await h.client.post("/v1/organization/members", json=payload, headers=auth(owner["access_token"]))
    ).status_code == 201
    assert (
        await h.client.post("/v1/organization/members", json=payload, headers=auth(owner["access_token"]))
    ).status_code == 409
    org = (await h.client.get("/v1/organization", headers=auth(owner["access_token"]))).json()
    assert org["name"] == "Acme Health"


async def test_api_key_lifecycle_and_scopes(h: Harness) -> None:
    owner = await register(h.client)
    resp = await h.client.post(
        "/v1/api-keys", json={"name": "ci", "scopes": ["projects:read"]}, headers=auth(owner["access_token"])
    )
    assert resp.status_code == 201
    created = resp.json()
    secret = created["secret"]
    assert (
        secret.startswith("cc_")
        and created["api_key"]["prefix"] == secret[:12]
        and created["api_key"]["role"] == "viewer"
    )

    assert (await h.client.get("/v1/projects", headers=auth(secret))).status_code == 200
    resp = await h.client.post("/v1/projects", json={"name": "x"}, headers=auth(secret))
    assert resp.status_code == 403 and resp.json()["error"]["details"]["required_scope"] == "projects:write"
    me = (await h.client.get("/v1/auth/me", headers=auth(secret))).json()
    assert me["principal_type"] == "api_key" and me["scopes"] == ["projects:read"]
    # API keys cannot log out a user session
    assert (await h.client.post("/v1/auth/logout", json={}, headers=auth(secret))).status_code == 403

    listed = (await h.client.get("/v1/api-keys", headers=auth(owner["access_token"]))).json()
    assert [k["id"] for k in listed] == [created["api_key"]["id"]] and listed[0]["last_used_at"] is not None
    resp = await h.client.delete(f"/v1/api-keys/{created['api_key']['id']}", headers=auth(owner["access_token"]))
    assert resp.status_code == 200 and resp.json()["revoked_at"] is not None
    resp = await h.client.get("/v1/projects", headers=auth(secret))
    assert resp.status_code == 401 and resp.json()["error"]["message"] == "API key revoked"
    assert (await h.client.get("/v1/projects", headers=auth("cc_" + "0" * 48))).status_code == 401


async def test_api_key_unknown_scope(h: Harness) -> None:
    owner = await register(h.client)
    resp = await h.client.post(
        "/v1/api-keys", json={"name": "x", "scopes": ["root"]}, headers=auth(owner["access_token"])
    )
    assert resp.status_code == 422


def test_scope_ceiling() -> None:
    with pytest.raises(ForbiddenError) as excinfo:
        check_scope_ceiling(Role.ANALYST, {"jobs:write", "api_keys:manage"})
    assert excinfo.value.details["excess"] == ["api_keys:manage"]
    with pytest.raises(UnprocessableError):
        check_scope_ceiling(Role.ADMIN, {"everything"})
    assert check_scope_ceiling(Role.VIEWER, {"jobs:read"}) == {"jobs:read"}
    assert role_for_scopes(frozenset({"jobs:read"})) == Role.VIEWER
    assert role_for_scopes(frozenset({"jobs:write"})) == Role.ANALYST
    assert role_for_scopes(frozenset({"members:manage"})) == Role.ADMIN
    assert role_for_scopes(frozenset({"unknown"})) == Role.ADMIN
    assert scopes_for_role(Role.OWNER) == scopes_for_role(Role.ADMIN)


def test_role_assignment_rules() -> None:
    assert_can_assign_role(Role.OWNER, Role.OWNER)
    assert_can_assign_role(Role.ADMIN, Role.ANALYST)
    for actor, target in [(Role.ADMIN, Role.ADMIN), (Role.ADMIN, Role.OWNER), (Role.ANALYST, Role.VIEWER)]:
        with pytest.raises(ForbiddenError):
            assert_can_assign_role(actor, target)
