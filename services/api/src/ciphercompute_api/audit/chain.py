"""Hash chain over audit events: ``hash = SHA-256(prev_hash || canonical(event))``.

Each organization has its own chain starting from :data:`GENESIS`. Verification re-walks the
chain in sequence order and reports the first broken link.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from ..db.models import AuditEvent

GENESIS = "0" * 64


def canonical(payload: Mapping[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str).encode("ascii")


def compute_hash(prev_hash: str, payload: Mapping[str, Any]) -> str:
    # [TM:T-1] Every event commits to its predecessor; editing or deleting any row breaks the
    # chain from that point on, which ``verify_chain`` detects.
    return hashlib.sha256(prev_hash.encode("ascii") + b"\n" + canonical(payload)).hexdigest()


def event_payload(event: AuditEvent) -> dict[str, Any]:
    """The fields covered by the hash (everything except ``seq``, ``prev_hash`` and ``hash``)."""
    return {
        "id": str(event.id),
        "organization_id": str(event.organization_id),
        "occurred_at": event.occurred_at.isoformat(),
        "actor_type": event.actor_type.value,
        "actor_id": None if event.actor_id is None else str(event.actor_id),
        "action": event.action,
        "resource_type": event.resource_type,
        "resource_id": None if event.resource_id is None else str(event.resource_id),
        "ip": event.ip,
        "user_agent": event.user_agent,
        "request_id": event.request_id,
        "trace_id": event.trace_id,
        "details": event.details,
    }


@dataclass(frozen=True, slots=True)
class ChainVerification:
    valid: bool
    checked: int
    head_hash: str | None
    first_broken_seq: int | None
    reason: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "checked": self.checked,
            "head_hash": self.head_hash,
            "first_broken_seq": self.first_broken_seq,
            "reason": self.reason,
        }


def verify_chain(events: Iterable[AuditEvent]) -> ChainVerification:
    """Verify events of one organization, ordered by ``seq`` ascending."""
    expected_prev = GENESIS
    checked = 0
    head: str | None = None
    for event in events:
        if event.prev_hash != expected_prev:
            return ChainVerification(False, checked, head, event.seq, "prev_hash does not match the previous event")
        if compute_hash(event.prev_hash, event_payload(event)) != event.hash:
            return ChainVerification(False, checked, head, event.seq, "event content does not match its hash")
        expected_prev = event.hash
        head = event.hash
        checked += 1
    return ChainVerification(True, checked, head, None, None)
