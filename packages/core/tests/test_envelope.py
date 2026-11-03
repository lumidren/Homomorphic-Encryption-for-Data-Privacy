from __future__ import annotations

import pytest

from ciphercompute_core.envelope import MAGIC_BUNDLE, MAGIC_CIPHERTEXT, VERSION, canonical_json, pack, unpack
from ciphercompute_core.errors import SerializationError


def test_round_trip() -> None:
    header = {"b": 1, "a": [1, 2], "nested": {"z": True}}
    payload = b"\x00\x01\x02" * 100
    data = pack(MAGIC_CIPHERTEXT, header, payload)
    assert data[:4] == MAGIC_CIPHERTEXT
    assert data[4] == VERSION
    got_header, got_payload = unpack(MAGIC_CIPHERTEXT, data)
    assert got_header == header
    assert got_payload == payload


def test_canonical_json_is_deterministic() -> None:
    assert canonical_json({"b": 1, "a": 2}) == b'{"a":2,"b":1}'


def test_wrong_magic() -> None:
    data = pack(MAGIC_BUNDLE, {}, b"x")
    with pytest.raises(SerializationError, match="wrong envelope type"):
        unpack(MAGIC_CIPHERTEXT, data)


def test_bad_version() -> None:
    data = bytearray(pack(MAGIC_BUNDLE, {}, b"x"))
    data[4] = 99
    with pytest.raises(SerializationError, match="unsupported envelope version"):
        unpack(MAGIC_BUNDLE, bytes(data))


def test_truncated_and_bad_lengths() -> None:
    with pytest.raises(SerializationError, match="truncated"):
        unpack(MAGIC_BUNDLE, b"CCPK")
    data = bytearray(pack(MAGIC_BUNDLE, {"k": "v"}, b"x"))
    data[5:9] = (10**6).to_bytes(4, "big")
    with pytest.raises(SerializationError, match="header length"):
        unpack(MAGIC_BUNDLE, bytes(data))


def test_header_must_be_object_and_valid_json() -> None:
    raw = MAGIC_BUNDLE + bytes([VERSION]) + (2).to_bytes(4, "big") + b"[]" + b"payload"
    with pytest.raises(SerializationError, match="JSON object"):
        unpack(MAGIC_BUNDLE, raw)
    raw = MAGIC_BUNDLE + bytes([VERSION]) + (3).to_bytes(4, "big") + b"{x}" + b"payload"
    with pytest.raises(SerializationError, match="not valid JSON"):
        unpack(MAGIC_BUNDLE, raw)


def test_non_bytes_rejected() -> None:
    with pytest.raises(SerializationError, match="must be bytes"):
        unpack(MAGIC_BUNDLE, "string")  # type: ignore[arg-type]


def test_header_size_limit_and_magic_length() -> None:
    with pytest.raises(SerializationError, match="header is"):
        pack(MAGIC_BUNDLE, {"big": "x" * 70_000}, b"")
    with pytest.raises(SerializationError, match="exactly 4 bytes"):
        pack(b"TOOLONG", {}, b"")


def test_memoryview_accepted() -> None:
    data = pack(MAGIC_BUNDLE, {"a": 1}, b"payload")
    header, payload = unpack(MAGIC_BUNDLE, memoryview(data))
    assert header == {"a": 1} and payload == b"payload"
