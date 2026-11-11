"""Job manifest: a commitment to exactly what the client asked the server to compute.

The API stores ``manifest_hash`` with every job and returns it with the result. The client SDK
recomputes it from what *it* uploaded (input fingerprints), the operation and the arguments; a
mismatch means the server ran something other than what was requested (THREAT_MODEL T-2).
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from typing import Any


def manifest_hash(
    operation: str,
    args: Mapping[str, Any],
    input_fingerprints: Sequence[str],
    bundle_fingerprint: str | None,
) -> str:
    body = {
        "operation": operation,
        "args": dict(args),
        "inputs": list(input_fingerprints),
        "bundle": bundle_fingerprint,
    }
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def object_fingerprint(data: bytes) -> str:
    """Fingerprint of a stored object (the full serialized envelope), as recorded by the API."""
    return "sha256:" + hashlib.sha256(data).hexdigest()
