"""Idempotent job submission.

A client sends ``Idempotency-Key: <opaque>``; the key is unique per organization (database
constraint). The first request creates the job; a retry with the same key and the same body
returns that job; the same key with a *different* body is a client bug and gets 409.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from .errors import ConflictError, UnprocessableError

_KEY_RE = re.compile(r"^[A-Za-z0-9._:-]{8,128}$")


def validate_key(value: str | None) -> str | None:
    if value is None:
        return None
    if not _KEY_RE.match(value):
        raise UnprocessableError("Idempotency-Key must be 8-128 characters of [A-Za-z0-9._:-]")
    return value


def request_hash(body: dict[str, Any]) -> str:
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def assert_same_request(stored_hash: str | None, new_hash: str) -> None:
    # [TM:P-1] A replay with the same key returns the original job; a different body is refused.
    if stored_hash != new_hash:
        raise ConflictError("Idempotency-Key was already used with a different request body")
