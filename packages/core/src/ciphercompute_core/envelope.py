"""Versioned binary envelope for serialized key bundles and ciphertexts.

Layout::

    magic[4] | version[1] | header_len[4, big-endian] | header_json[header_len] | payload

The header is canonical JSON (sorted keys, no whitespace) so that it can be hashed
deterministically. The payload is the raw TenSEAL serialization.
"""

from __future__ import annotations

import json
from typing import Any, Final

from .errors import SerializationError

MAGIC_BUNDLE: Final = b"CCPK"
MAGIC_CIPHERTEXT: Final = b"CCCT"
VERSION: Final = 1

_MAX_HEADER_BYTES: Final = 64 * 1024
_PREFIX_LEN: Final = 4 + 1 + 4


def canonical_json(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def pack(magic: bytes, header: dict[str, Any], payload: bytes) -> bytes:
    if len(magic) != 4:
        raise SerializationError("magic must be exactly 4 bytes")
    header_bytes = canonical_json(header)
    if len(header_bytes) > _MAX_HEADER_BYTES:
        raise SerializationError(f"envelope header is {len(header_bytes)} bytes; the limit is {_MAX_HEADER_BYTES}")
    return magic + bytes([VERSION]) + len(header_bytes).to_bytes(4, "big") + header_bytes + payload


def unpack(magic: bytes, data: bytes | bytearray | memoryview) -> tuple[dict[str, Any], bytes]:
    """Split ``data`` into ``(header, payload)``, validating magic, version and lengths."""
    if not isinstance(data, bytes | bytearray | memoryview):
        raise SerializationError("envelope must be bytes")
    data = bytes(data)
    if len(data) < _PREFIX_LEN:
        raise SerializationError("envelope is truncated")
    if data[:4] != magic:
        raise SerializationError(
            f"wrong envelope type: expected {magic!r}, got {data[:4]!r}",
            expected=magic.decode(),
            got=data[:4].decode(errors="replace"),
        )
    version = data[4]
    if version != VERSION:
        raise SerializationError(
            f"unsupported envelope version {version}; this build reads version {VERSION}", version=version
        )
    header_len = int.from_bytes(data[5:9], "big")
    if header_len > _MAX_HEADER_BYTES or _PREFIX_LEN + header_len > len(data):
        raise SerializationError("envelope header length is invalid", header_len=header_len)
    header_bytes = data[_PREFIX_LEN : _PREFIX_LEN + header_len]
    try:
        header = json.loads(header_bytes)
    except ValueError as exc:
        raise SerializationError(f"envelope header is not valid JSON: {exc}") from exc
    if not isinstance(header, dict):
        raise SerializationError("envelope header must be a JSON object")
    return header, data[_PREFIX_LEN + header_len :]
