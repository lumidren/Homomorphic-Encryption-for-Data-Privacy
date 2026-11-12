"""KeyRing / PublicKeyBundle: the secret key never crosses the bundle boundary."""

from __future__ import annotations

import pytest

from ciphercompute_core import EncryptedVector, KeyRing, PublicKeyBundle, standard_params
from ciphercompute_core.envelope import MAGIC_BUNDLE, pack
from ciphercompute_core.errors import (
    InsecureParametersError,
    KeyMismatchError,
    SecretKeyLeakError,
    SerializationError,
)
from ciphercompute_core.keys import BUNDLE_KIND, MAGIC_SECRET, SECRET_KIND, fingerprint_bytes
from ciphercompute_core.params import CKKSParams


def _public_raw(ring: KeyRing, **overrides: bool) -> bytes:
    flags = {"save_public_key": True, "save_secret_key": False, "save_galois_keys": True, "save_relin_keys": True}
    flags.update(overrides)
    return ring.context().serialize(**flags)


def _header(
    ring: KeyRing, params: CKKSParams | None = None, kind: str = BUNDLE_KIND, ring_id: str | None = None
) -> dict:
    return {"kind": kind, "ring_id": ring_id or ring.ring_id, "params": (params or ring.params).to_dict()}


def test_bundle_is_public_and_complete(small_ring: KeyRing, small_bundle: PublicKeyBundle) -> None:
    assert small_bundle.ring_id == small_ring.ring_id
    assert small_bundle.params == small_ring.params
    ctx = small_bundle.context()
    assert not ctx.is_private()
    assert not ctx.has_secret_key()
    assert ctx.has_public_key() and ctx.has_relin_keys() and ctx.has_galois_keys()
    assert small_bundle.fingerprint.startswith("sha256:") and len(small_bundle.fingerprint) == 7 + 64
    assert small_bundle.size_bytes > 1_000_000
    assert "PublicKeyBundle" in repr(small_bundle)
    assert "KeyRing" in repr(small_ring)


def test_bundle_round_trip_and_equality(small_bundle: PublicKeyBundle) -> None:
    again = PublicKeyBundle.load(small_bundle.to_bytes())
    assert again == small_bundle
    assert hash(again) == hash(small_bundle)
    assert again.fingerprint == small_bundle.fingerprint
    assert small_bundle != object()


def test_private_context_is_rejected(small_ring: KeyRing) -> None:
    raw = _public_raw(small_ring, save_secret_key=True)
    with pytest.raises(SecretKeyLeakError) as excinfo:
        PublicKeyBundle.load(pack(MAGIC_BUNDLE, _header(small_ring), raw))
    assert excinfo.value.code == "secret_key_leak"
    assert excinfo.value.details["ring_id"] == small_ring.ring_id


def test_header_params_must_match_context(small_ring: KeyRing) -> None:
    raw = _public_raw(small_ring)
    other = standard_params(8192, 128, "deep")
    with pytest.raises(SerializationError, match="do not match"):
        PublicKeyBundle.load(pack(MAGIC_BUNDLE, _header(small_ring, other), raw))


def test_header_scale_must_match_context(small_ring: KeyRing) -> None:
    raw = _public_raw(small_ring)
    same_chain_other_scale = CKKSParams(8192, (60, 40, 40, 60), 30)
    with pytest.raises(SerializationError, match="scale"):
        PublicKeyBundle.load(pack(MAGIC_BUNDLE, _header(small_ring, same_chain_other_scale), raw))


def test_header_params_are_security_validated(small_ring: KeyRing) -> None:
    raw = _public_raw(small_ring)
    header = _header(small_ring)
    header["params"]["coeff_mod_bit_sizes"] = [60, 60, 60, 60]
    with pytest.raises(InsecureParametersError):
        PublicKeyBundle.load(pack(MAGIC_BUNDLE, header, raw))


def test_missing_evaluation_keys_rejected(small_ring: KeyRing) -> None:
    raw = _public_raw(small_ring, save_galois_keys=False)
    with pytest.raises(SerializationError, match="Galois") as excinfo:
        PublicKeyBundle.load(pack(MAGIC_BUNDLE, _header(small_ring), raw))
    assert excinfo.value.details["has_galois_keys"] is False


@pytest.mark.parametrize(
    ("mutate", "fragment"),
    [
        (lambda h: h.update(kind="ciphertext"), "expected a public_key_bundle"),
        (lambda h: h.update(ring_id="short"), "ring_id"),
        (lambda h: h.update(ring_id="zz" * 16), "ring_id"),
        (lambda h: h.update(ring_id=12345), "ring_id"),
        (lambda h: h.pop("params"), "malformed"),
    ],
)
def test_malformed_headers(small_ring: KeyRing, mutate, fragment: str) -> None:
    header = _header(small_ring)
    mutate(header)
    with pytest.raises((SerializationError, InsecureParametersError), match=fragment):
        PublicKeyBundle.load(pack(MAGIC_BUNDLE, header, _public_raw(small_ring)))


def test_garbage_payload(small_ring: KeyRing) -> None:
    with pytest.raises(SerializationError, match="could not deserialize"):
        PublicKeyBundle.load(pack(MAGIC_BUNDLE, _header(small_ring), b"not a context"))


def test_secret_bytes_round_trip(small_ring: KeyRing, small_bundle: PublicKeyBundle) -> None:
    reloaded = KeyRing.from_secret_bytes(small_ring.to_secret_bytes())
    assert reloaded.ring_id == small_ring.ring_id
    assert reloaded.params == small_ring.params
    ev = EncryptedVector.encrypt(small_bundle, [1.5, -2.25, 3.0])
    assert reloaded.decrypt(ev) == pytest.approx([1.5, -2.25, 3.0], abs=1e-6)
    # a bundle derived from the reloaded ring must pass the same gate and keep the identity
    again = reloaded.public_bundle()
    assert again.ring_id == small_bundle.ring_id
    assert again.params == small_bundle.params


def test_secret_envelope_rejects_public_context(small_ring: KeyRing) -> None:
    header = _header(small_ring, kind=SECRET_KIND)
    with pytest.raises(SerializationError, match="does not contain a secret key"):
        KeyRing.from_secret_bytes(pack(MAGIC_SECRET, header, _public_raw(small_ring)))


def test_secret_envelope_wrong_kind_and_garbage(small_ring: KeyRing) -> None:
    with pytest.raises(SerializationError, match="expected a secret_key_ring"):
        KeyRing.from_secret_bytes(pack(MAGIC_SECRET, _header(small_ring), b""))
    with pytest.raises(SerializationError, match="could not deserialize"):
        KeyRing.from_secret_bytes(pack(MAGIC_SECRET, _header(small_ring, kind=SECRET_KIND), b"junk"))


def test_decrypt_with_wrong_ring(small_ring: KeyRing) -> None:
    other = KeyRing.generate(small_ring.params)
    ev = EncryptedVector.encrypt(other.public_bundle(), [1.0])
    with pytest.raises(KeyMismatchError) as excinfo:
        small_ring.decrypt(ev)
    assert excinfo.value.details["expected_ring_id"] == small_ring.ring_id
    assert excinfo.value.details["got_ring_id"] == other.ring_id


def test_keyring_requires_private_context(small_bundle: PublicKeyBundle) -> None:
    with pytest.raises(SerializationError, match="private context"):
        KeyRing(small_bundle.context(), small_bundle.params, small_bundle.ring_id)


def test_fingerprint_bytes_is_sha256() -> None:
    assert fingerprint_bytes(b"") == "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def test_secret_envelope_missing_evaluation_keys(small_ring: KeyRing) -> None:
    raw = small_ring.context().serialize(
        save_public_key=True, save_secret_key=True, save_galois_keys=False, save_relin_keys=True
    )
    header = _header(small_ring, kind=SECRET_KIND)
    with pytest.raises(SerializationError, match="missing evaluation keys"):
        KeyRing.from_secret_bytes(pack(MAGIC_SECRET, header, raw))
