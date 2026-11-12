from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from ciphercompute_client import KeyStore
from ciphercompute_client.errors import KeyStoreError
from ciphercompute_client.keystore import HEADER_LEN, PUBLIC_FILE, SECRET_FILE, seal, unseal
from ciphercompute_core import EncryptedVector, PublicKeyBundle

PASS = "a long enough passphrase"
FAST_KDF = {"time_cost": 1, "memory_kib": 8, "parallelism": 1}


@pytest.fixture(autouse=True)
def fast_kdf(monkeypatch: pytest.MonkeyPatch) -> None:
    """Argon2id at 64 MiB per call is the production setting; tests use a cheap one."""
    import ciphercompute_client.keystore as ks

    monkeypatch.setattr(ks, "KDF_TIME_COST", 1)
    monkeypatch.setattr(ks, "KDF_MEMORY_KIB", 8)
    monkeypatch.setattr(ks, "KDF_PARALLELISM", 1)


def test_create_and_open_round_trip(tmp_path: Path) -> None:
    store = KeyStore.create(tmp_path / "ring", passphrase=PASS)
    assert (tmp_path / "ring" / SECRET_FILE).is_file() and (tmp_path / "ring" / PUBLIC_FILE).is_file()
    meta = KeyStore.metadata(tmp_path / "ring")
    assert meta["ring_id"] == store.ring_id and meta["encrypted"] is True and meta["cipher"] == "AES-256-GCM"
    assert meta["kdf"]["algorithm"] == "argon2id"
    reopened = KeyStore.open(tmp_path / "ring", passphrase=PASS)
    assert reopened.ring_id == store.ring_id and reopened.params == store.params
    ev = EncryptedVector.encrypt(store.public_bundle(), [1.5, -2.5])
    assert reopened.ring.decrypt(ev) == pytest.approx([1.5, -2.5], abs=1e-6)
    # the public file is a valid public bundle and does not need the passphrase
    bundle = PublicKeyBundle.load(KeyStore.public_bundle_bytes(tmp_path / "ring"))
    assert bundle.ring_id == store.ring_id


def test_secret_file_is_encrypted_at_rest(tmp_path: Path) -> None:
    store = KeyStore.create(tmp_path / "ring", passphrase=PASS)
    blob = (tmp_path / "ring" / SECRET_FILE).read_bytes()
    assert blob[:4] == b"CCKS" and b"CCSK" not in blob  # the inner secret envelope magic is not visible
    assert store.ring_id.encode() not in blob


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission bits")
def test_permissions(tmp_path: Path) -> None:
    KeyStore.create(tmp_path / "ring", passphrase=PASS)
    secret = tmp_path / "ring" / SECRET_FILE
    assert oct(secret.stat().st_mode & 0o777) == "0o600"
    assert oct((tmp_path / "ring").stat().st_mode & 0o777) == "0o700"
    secret.chmod(0o644)
    with pytest.raises(KeyStoreError, match="accessible by other users"):
        KeyStore.open(tmp_path / "ring", passphrase=PASS)


def test_wrong_passphrase_and_tampering(tmp_path: Path) -> None:
    KeyStore.create(tmp_path / "ring", passphrase=PASS)
    with pytest.raises(KeyStoreError, match="wrong passphrase"):
        KeyStore.open(tmp_path / "ring", passphrase="not the passphrase")
    with pytest.raises(KeyStoreError, match="passphrase is required"):
        KeyStore.open(tmp_path / "ring", passphrase=None)
    secret = tmp_path / "ring" / SECRET_FILE
    blob = bytearray(secret.read_bytes())
    blob[HEADER_LEN + 10] ^= 1
    secret.unlink()
    secret.write_bytes(bytes(blob))
    secret.chmod(0o600)  # keep the permission check satisfied so the integrity check is what fires
    with pytest.raises(KeyStoreError, match="modified"):
        KeyStore.open(tmp_path / "ring", passphrase=PASS)


def test_header_is_authenticated() -> None:
    blob = bytearray(seal(b"secret material", "pw-pw-pw-pw-pw", kdf=FAST_KDF))
    blob[6] ^= 1  # flip a salt bit: key derivation changes AND the AAD no longer matches
    with pytest.raises(KeyStoreError):
        unseal(bytes(blob), "pw-pw-pw-pw-pw", kdf=FAST_KDF)
    with pytest.raises(KeyStoreError, match="not a CipherCompute"):
        unseal(b"XXXX" + bytes(100), "x", kdf=FAST_KDF)
    bad_version = b"CCKS" + bytes([9]) + bytes(100)
    with pytest.raises(KeyStoreError, match="version"):
        unseal(bad_version, "x", kdf=FAST_KDF)


def test_unencrypted_requires_opt_in(tmp_path: Path) -> None:
    with pytest.raises(KeyStoreError, match="passphrase is required"):
        KeyStore.create(tmp_path / "a", passphrase=None)
    with pytest.raises(KeyStoreError, match="at least 12"):
        KeyStore.create(tmp_path / "b", passphrase="short")
    store = KeyStore.create(tmp_path / "c", passphrase=None, allow_unencrypted=True, profile="deep")
    assert KeyStore.metadata(tmp_path / "c")["encrypted"] is False
    assert KeyStore.open(tmp_path / "c", passphrase=None).ring_id == store.ring_id
    assert store.params.depth == 4


def test_refuses_to_overwrite_and_reports_missing(tmp_path: Path) -> None:
    KeyStore.create(tmp_path / "ring", passphrase=PASS)
    with pytest.raises(KeyStoreError, match="refusing to overwrite"):
        KeyStore.create(tmp_path / "ring", passphrase=PASS)
    with pytest.raises(KeyStoreError, match="no key ring"):
        KeyStore.open(tmp_path / "nothing", passphrase=PASS)
    (tmp_path / "bad").mkdir()
    (tmp_path / "bad" / "keystore.json").write_text("[1, 2]", encoding="utf-8")
    with pytest.raises(KeyStoreError, match="malformed"):
        KeyStore.metadata(tmp_path / "bad")
    with pytest.raises(KeyStoreError, match="cannot read"):
        KeyStore.metadata(tmp_path / "missing")


def test_ring_id_mismatch_detected(tmp_path: Path) -> None:
    KeyStore.create(tmp_path / "ring", passphrase=PASS)
    meta_path = tmp_path / "ring" / "keystore.json"
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    meta["ring_id"] = "0" * 32
    meta_path.write_text(json.dumps(meta), encoding="utf-8")
    with pytest.raises(KeyStoreError, match="does not match"):
        KeyStore.open(tmp_path / "ring", passphrase=PASS)


def test_custom_params(tmp_path: Path) -> None:
    from ciphercompute_core import standard_params

    params = standard_params(8192, 192)
    store = KeyStore.create(tmp_path / "ring", params=params, passphrase=PASS)
    assert store.params == params and KeyStore.open(tmp_path / "ring", passphrase=PASS).params == params
