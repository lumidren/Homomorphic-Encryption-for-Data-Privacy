from __future__ import annotations

import numpy as np
import pytest

from ciphercompute_core import EncryptedVector, KeyRing, PublicKeyBundle, standard_params
from ciphercompute_core.envelope import MAGIC_CIPHERTEXT, pack, unpack
from ciphercompute_core.errors import InvalidArgumentError, KeyMismatchError, SerializationError


def _tampered(ev: EncryptedVector, **changes) -> bytes:
    header, payload = unpack(MAGIC_CIPHERTEXT, ev.to_bytes())
    header.update(changes)
    return pack(MAGIC_CIPHERTEXT, header, payload)


def test_round_trip_with_bundle_and_ring(small_ring: KeyRing, small_bundle: PublicKeyBundle) -> None:
    values = [0.0, 1.0, -1.0, 123.456, 1e-6]
    for keys in (small_bundle, small_ring):
        ev = EncryptedVector.encrypt(keys, values)
        assert ev.length == 5
        assert ev.ring_id == small_ring.ring_id
        assert ev.params == small_ring.params
        assert ev.levels_consumed == 0
        assert ev.levels_remaining == small_ring.params.depth
        assert ev.scale == small_ring.params.scale
        assert small_ring.decrypt(ev) == pytest.approx(values, abs=1e-6)


def test_accepts_numpy_and_nested_shapes(small_ring: KeyRing, small_bundle: PublicKeyBundle) -> None:
    ev = EncryptedVector.encrypt(small_bundle, np.array([[1, 2], [3, 4]], dtype=np.int64))
    assert ev.length == 4
    assert small_ring.decrypt(ev) == pytest.approx([1, 2, 3, 4], abs=1e-6)


def test_padding(small_ring: KeyRing, small_bundle: PublicKeyBundle) -> None:
    ev = EncryptedVector.encrypt(small_bundle, [1.0, 2.0], pad_to=8)
    assert ev.length == 8
    assert small_ring.decrypt(ev) == pytest.approx([1, 2, 0, 0, 0, 0, 0, 0], abs=1e-6)
    with pytest.raises(InvalidArgumentError, match="smaller than the vector length"):
        EncryptedVector.encrypt(small_bundle, [1.0, 2.0, 3.0], pad_to=2)


@pytest.mark.parametrize(
    ("values", "fragment"),
    [
        ([], "empty"),
        ([1.0, float("nan")], "finite"),
        ([float("inf")], "finite"),
        ([2.0**20], "below 2\\^20"),
        ([-(2.0**21)], "below 2\\^20"),
    ],
)
def test_rejects_bad_values(small_bundle: PublicKeyBundle, values, fragment: str) -> None:
    with pytest.raises(InvalidArgumentError, match=fragment):
        EncryptedVector.encrypt(small_bundle, values)


def test_rejects_too_many_slots(small_bundle: PublicKeyBundle) -> None:
    with pytest.raises(InvalidArgumentError, match="exceeds the 4096 slots"):
        EncryptedVector.encrypt(small_bundle, np.ones(4097))
    with pytest.raises(InvalidArgumentError, match="exceeds the 4096 slots"):
        EncryptedVector.encrypt(small_bundle, [1.0], pad_to=5000)


def test_levels_are_read_from_the_ciphertext(small_bundle: PublicKeyBundle) -> None:
    ev = EncryptedVector.encrypt(small_bundle, [1.0, 2.0])
    once = ev.spawn(ev.raw() * 2.0, 2)
    assert once.levels_consumed == 1 and once.levels_remaining == ev.params.depth - 1
    report = once.depth_report()
    assert report.levels_consumed == 1 and report.levels_total == ev.params.depth
    assert report.to_dict()["levels_remaining"] == ev.params.depth - 1


def test_serialization_round_trip(small_ring: KeyRing, small_bundle: PublicKeyBundle) -> None:
    ev = EncryptedVector.encrypt(small_bundle, [3.0, 4.0, 5.0])
    ev = ev.spawn(ev.raw() * 0.5, 3)
    data = ev.to_bytes()
    for keys in (small_bundle, small_ring):
        back = EncryptedVector.load(keys, data)
        assert back.length == 3 and back.levels_consumed == 1 and back.ring_id == ev.ring_id
        assert small_ring.decrypt(back) == pytest.approx([1.5, 2.0, 2.5], abs=1e-5)
    assert ev.fingerprint().startswith("sha256:")
    assert ev.fingerprint() == ev.fingerprint()
    assert ev.fingerprint() != EncryptedVector.encrypt(small_bundle, [3.0, 4.0, 5.0]).fingerprint()
    assert "EncryptedVector(length=3, levels_consumed=1/" in repr(ev)
    assert ev.copy().levels_consumed == 1


def test_load_rejects_other_ring(small_bundle: PublicKeyBundle) -> None:
    ev = EncryptedVector.encrypt(small_bundle, [1.0])
    with pytest.raises(KeyMismatchError, match="different key ring"):
        EncryptedVector.load(small_bundle, _tampered(ev, ring_id="0" * 32))


def test_load_rejects_other_params(small_bundle: PublicKeyBundle) -> None:
    ev = EncryptedVector.encrypt(small_bundle, [1.0])
    other = standard_params(8192, 128, "deep").to_dict()
    with pytest.raises(KeyMismatchError, match="parameters do not match"):
        EncryptedVector.load(small_bundle, _tampered(ev, params=other))


@pytest.mark.parametrize(
    ("changes", "fragment"),
    [
        ({"kind": "bundle"}, "expected a ckks_vector"),
        ({"length": 0}, "invalid length"),
        ({"length": "3"}, "invalid length"),
        ({"length": 2}, "does not match the ciphertext"),
        ({"levels_consumed": 1}, "claims 1 levels consumed"),
        ({"levels_consumed": None}, "claims None levels consumed"),
    ],
)
def test_load_rejects_tampered_headers(small_bundle: PublicKeyBundle, changes: dict, fragment: str) -> None:
    ev = EncryptedVector.encrypt(small_bundle, [1.0, 2.0, 3.0])
    with pytest.raises(SerializationError, match=fragment):
        EncryptedVector.load(small_bundle, _tampered(ev, **changes))


def test_load_rejects_garbage_payload(small_bundle: PublicKeyBundle) -> None:
    ev = EncryptedVector.encrypt(small_bundle, [1.0])
    header, _ = unpack(MAGIC_CIPHERTEXT, ev.to_bytes())
    with pytest.raises(SerializationError, match="could not deserialize"):
        EncryptedVector.load(small_bundle, pack(MAGIC_CIPHERTEXT, header, b"garbage"))
