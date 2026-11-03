"""UUIDv7 generation (RFC 9562 §5.7) for every tenant-scoped identifier.

Layout (most significant bit first):
``unix_ts_ms[48] | ver[4]=7 | rand_a[12] | var[2]=0b10 | rand_b[62]``.

``rand_a`` is used as a per-millisecond counter seeded with 11 random bits so that ids
generated within the same millisecond on one process stay strictly increasing — important
for index locality in PostgreSQL.
"""

from __future__ import annotations

import secrets
import threading
import time
import uuid

_lock = threading.Lock()
_last_ms = -1
_seq = 0

_SEQ_MAX = 0xFFF


def uuid7() -> uuid.UUID:
    """Return a new time-ordered UUIDv7."""
    global _last_ms, _seq
    with _lock:
        ms = time.time_ns() // 1_000_000
        if ms > _last_ms:
            _last_ms = ms
            _seq = secrets.randbits(11)
        else:
            _seq += 1
            if _seq > _SEQ_MAX:
                _last_ms += 1
                _seq = secrets.randbits(11)
            ms = _last_ms
        rand_b = secrets.randbits(62)
        value = (ms << 80) | (7 << 76) | (_seq << 64) | (0b10 << 62) | rand_b
    return uuid.UUID(int=value)


def is_uuid7(value: uuid.UUID | str) -> bool:
    """True when ``value`` is a UUID with version 7 and the RFC 4122/9562 variant."""
    try:
        u = value if isinstance(value, uuid.UUID) else uuid.UUID(str(value))
    except (ValueError, AttributeError, TypeError):
        return False
    return u.version == 7 and u.variant == uuid.RFC_4122


def uuid7_timestamp_ms(value: uuid.UUID) -> int:
    """Extract the millisecond Unix timestamp embedded in a UUIDv7."""
    if not is_uuid7(value):
        raise ValueError(f"{value} is not a UUIDv7")
    return value.int >> 80
