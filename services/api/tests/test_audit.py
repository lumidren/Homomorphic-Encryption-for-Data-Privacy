"""Audit chain integrity, database-level immutability and route coverage."""

from __future__ import annotations

import copy
import itertools
import uuid

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError

from ciphercompute_api.audit.chain import GENESIS, compute_hash, event_payload, verify_chain
from ciphercompute_api.db.models import AuditEvent
from ciphercompute_core import EncryptedVector, KeyRing

from .conftest import Harness, auth, make_world, upload_ciphertext


async def _events(h: Harness) -> list[AuditEvent]:
    async with h.state.session_factory() as session:
        return list((await session.execute(select(AuditEvent).order_by(AuditEvent.seq))).scalars())


async def test_chain_is_valid_after_activity(h: Harness, bundle_bytes: bytes) -> None:
    w = await make_world(h, bundle_bytes)
    resp = await h.client.get("/v1/audit/verify", headers=auth(w.token))
    assert resp.status_code == 200
    report = resp.json()
    assert report["valid"] and report["checked"] >= 4 and report["first_broken_seq"] is None
    events = await _events(h)
    assert events[0].prev_hash == GENESIS
    assert all(e.prev_hash == p.hash for p, e in itertools.pairwise(events))
    assert report["head_hash"] == events[-1].hash


async def test_chain_detects_tamper(h: Harness, bundle_bytes: bytes) -> None:
    await make_world(h, bundle_bytes)
    events = await _events(h)
    assert verify_chain(events).valid

    edited = [copy.copy(e) for e in events]
    edited[1].details = {"forged": True}
    result = verify_chain(edited)
    assert not result.valid and result.first_broken_seq == events[1].seq and "content" in (result.reason or "")

    deleted = events[:1] + events[2:]
    result = verify_chain(deleted)
    assert not result.valid and result.first_broken_seq == events[2].seq and "prev_hash" in (result.reason or "")

    # recomputing the edited row's own hash is not enough: the successor still points at the original
    edited[1].hash = compute_hash(edited[1].prev_hash, event_payload(edited[1]))
    assert not verify_chain(edited).valid


async def test_update_and_delete_rejected_by_trigger(h: Harness, bundle_bytes: bytes) -> None:
    await make_world(h, bundle_bytes)
    async with h.state.engine.connect() as conn:
        with pytest.raises(DBAPIError, match="append-only"):
            await conn.execute(text("UPDATE audit_events SET action = 'x'"))
        await conn.rollback()
        with pytest.raises(DBAPIError, match="append-only"):
            await conn.execute(text("DELETE FROM audit_events"))
        await conn.rollback()


async def test_every_data_route_audited(h: Harness, ring: KeyRing, bundle_bytes: bytes) -> None:
    w = await make_world(h, bundle_bytes)
    ct = await upload_ciphertext(h, w.token, w.dataset_id, EncryptedVector.encrypt(ring.public_bundle(), [1.0]))
    job = (
        await h.client.post(
            f"/v1/projects/{w.project_id}/jobs", json={"operation": "sum", "inputs": [ct["id"]]}, headers=auth(w.token)
        )
    ).json()
    await h.client.get(f"/v1/ciphertexts/{ct['id']}/download", headers=auth(w.token))
    await h.client.post(f"/v1/jobs/{job['id']}/cancel", headers=auth(w.token))
    key = (
        await h.client.post("/v1/api-keys", json={"name": "k", "scopes": ["jobs:read"]}, headers=auth(w.token))
    ).json()
    await h.client.delete(f"/v1/api-keys/{key['api_key']['id']}", headers=auth(w.token))
    await h.client.patch(f"/v1/projects/{w.project_id}", json={"description": "d"}, headers=auth(w.token))

    actions = {e.action for e in await _events(h)}
    expected = {
        "user.registered",
        "project.created",
        "project.updated",
        "key_bundle.created",
        "dataset.created",
        "ciphertext.created",
        "ciphertext.confirmed",
        "ciphertext.accessed",
        "job.submitted",
        "job.cancelled",
        "api_key.created",
        "api_key.revoked",
    }
    assert expected <= actions, expected - actions
    submitted = next(e for e in await _events(h) if e.action == "job.submitted")
    assert submitted.actor_type.value == "user" and submitted.resource_id == uuid.UUID(job["id"])
    assert submitted.request_id and submitted.ip == "127.0.0.1"


async def test_audit_listing_filters_and_pages(h: Harness, bundle_bytes: bytes) -> None:
    w = await make_world(h, bundle_bytes)
    page = (await h.client.get("/v1/audit?limit=2", headers=auth(w.token))).json()
    assert len(page["items"]) == 2 and page["next_cursor"]
    nxt = (await h.client.get(f"/v1/audit?limit=2&before_seq={page['next_cursor']}", headers=auth(w.token))).json()
    assert nxt["items"][0]["seq"] < page["items"][-1]["seq"]
    by_resource = (await h.client.get(f"/v1/audit?resource_id={w.project_id}", headers=auth(w.token))).json()
    assert [e["action"] for e in by_resource["items"]] == ["project.created"]
    assert (await h.client.get("/v1/audit?resource_id=nope", headers=auth(w.token))).status_code == 422
