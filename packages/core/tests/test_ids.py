from __future__ import annotations

import threading
import uuid

import pytest

from ciphercompute_core import ids
from ciphercompute_core.ids import is_uuid7, uuid7, uuid7_timestamp_ms


def test_uuid7_version_and_variant() -> None:
    u = uuid7()
    assert u.version == 7
    assert u.variant == uuid.RFC_4122
    assert is_uuid7(u)
    assert is_uuid7(str(u))


def test_uuid7_is_monotonic_within_a_process() -> None:
    values = [uuid7() for _ in range(5000)]
    assert values == sorted(values)
    assert len(set(values)) == len(values)


def test_uuid7_timestamp_is_recent() -> None:
    import time

    before = time.time_ns() // 1_000_000
    u = uuid7()
    after = time.time_ns() // 1_000_000
    # the counter may bump the embedded millisecond by a few ms under bursts
    assert before <= uuid7_timestamp_ms(u) <= after + 50


def test_sequence_overflow_advances_millisecond(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ids, "_last_ms", 10_000)
    monkeypatch.setattr(ids, "_seq", ids._SEQ_MAX)
    monkeypatch.setattr(ids.time, "time_ns", lambda: 10_000 * 1_000_000)
    u = uuid7()
    assert uuid7_timestamp_ms(u) == 10_001


def test_thread_safety_unique() -> None:
    out: list[uuid.UUID] = []
    lock = threading.Lock()

    def work() -> None:
        local = [uuid7() for _ in range(500)]
        with lock:
            out.extend(local)

    threads = [threading.Thread(target=work) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(set(out)) == len(out)


def test_rejects_non_v7() -> None:
    assert not is_uuid7(uuid.uuid4())
    assert not is_uuid7("not-a-uuid")
    assert not is_uuid7(None)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        uuid7_timestamp_ms(uuid.uuid4())
