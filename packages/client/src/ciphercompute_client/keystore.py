"""Local key storage. The secret key lives here and nowhere else.

On-disk format (``secret.ccks``)::

    magic "CCKS" | version 1 | salt[16] | nonce[12] | AES-256-GCM(ciphertext of KeyRing.to_secret_bytes())

The AES key is derived from a passphrase with Argon2id (64 MiB, t=3, p=4). The header bytes are
bound into the GCM tag as associated data, so a modified header fails decryption just like a
modified body. Files are created with mode 0600 inside a 0700 directory. A passphrase-less mode
exists for CI and demos and is refused unless explicitly requested.
"""

from __future__ import annotations

import json
import os
import secrets
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ciphercompute_core import CKKSParams, KeyRing, PublicKeyBundle, SecurityLevel, standard_params
from ciphercompute_core.params import Profile

from .errors import KeyStoreError

MAGIC: Final = b"CCKS"
VERSION: Final = 1
SALT_LEN: Final = 16
NONCE_LEN: Final = 12
HEADER_LEN: Final = 4 + 1 + SALT_LEN + NONCE_LEN
SECRET_FILE: Final = "secret.ccks"  # noqa: S105 - a file name
PUBLIC_FILE: Final = "public.ccpk"
META_FILE: Final = "keystore.json"

# Argon2id parameters (RFC 9106 "second recommended"); recorded in keystore.json so they can evolve.
KDF_TIME_COST: Final = 3
KDF_MEMORY_KIB: Final = 65536
KDF_PARALLELISM: Final = 4


def _derive(passphrase: str, salt: bytes, time_cost: int, memory_kib: int, parallelism: int) -> bytes:
    return hash_secret_raw(
        passphrase.encode("utf-8"),
        salt,
        time_cost=time_cost,
        memory_cost=memory_kib,
        parallelism=parallelism,
        hash_len=32,
        type=Type.ID,
    )


def seal(secret: bytes, passphrase: str | None, *, kdf: dict[str, int] | None = None) -> bytes:
    """Encrypt ``secret`` for storage; ``passphrase=None`` stores it with an all-zero key (explicit opt-in only)."""
    kdf = kdf or {"time_cost": KDF_TIME_COST, "memory_kib": KDF_MEMORY_KIB, "parallelism": KDF_PARALLELISM}
    salt = secrets.token_bytes(SALT_LEN)
    nonce = secrets.token_bytes(NONCE_LEN)
    header = MAGIC + bytes([VERSION]) + salt + nonce
    key = (
        bytes(32)
        if passphrase is None
        else _derive(passphrase, salt, kdf["time_cost"], kdf["memory_kib"], kdf["parallelism"])
    )
    return header + AESGCM(key).encrypt(nonce, secret, header)


def unseal(blob: bytes, passphrase: str | None, *, kdf: dict[str, int] | None = None) -> bytes:
    kdf = kdf or {"time_cost": KDF_TIME_COST, "memory_kib": KDF_MEMORY_KIB, "parallelism": KDF_PARALLELISM}
    if len(blob) <= HEADER_LEN or blob[:4] != MAGIC:
        raise KeyStoreError("not a CipherCompute secret key file")
    if blob[4] != VERSION:
        raise KeyStoreError(f"unsupported key file version {blob[4]}")
    header = blob[:HEADER_LEN]
    salt = blob[5 : 5 + SALT_LEN]
    nonce = blob[5 + SALT_LEN : HEADER_LEN]
    key = (
        bytes(32)
        if passphrase is None
        else _derive(passphrase, salt, kdf["time_cost"], kdf["memory_kib"], kdf["parallelism"])
    )
    try:
        return AESGCM(key).decrypt(nonce, blob[HEADER_LEN:], header)
    except InvalidTag:
        raise KeyStoreError("wrong passphrase, or the key file was modified") from None


def _write_private(path: Path, data: bytes) -> None:
    """Create ``path`` with 0600 permissions from the first byte (no window where it is readable)."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)


def _check_permissions(path: Path) -> None:
    if os.name != "posix":
        return  # NTFS ACLs: the file is created in the user's profile; POSIX mode bits do not apply
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & 0o077:
        raise KeyStoreError(f"{path} is accessible by other users (mode {oct(mode)}); run: chmod 600 {path}")


@dataclass(frozen=True)
class KeyStore:
    """A directory holding one key ring: encrypted secret key, public bundle, metadata."""

    path: Path
    ring: KeyRing

    @property
    def params(self) -> CKKSParams:
        return self.ring.params

    @property
    def ring_id(self) -> str:
        return self.ring.ring_id

    def public_bundle(self) -> PublicKeyBundle:
        return self.ring.public_bundle()

    @classmethod
    def create(
        cls,
        path: str | os.PathLike[str],
        *,
        poly_modulus_degree: int = 8192,
        security_level: int | SecurityLevel = SecurityLevel.BITS_128,
        profile: Profile = "balanced",
        params: CKKSParams | None = None,
        passphrase: str | None,
        allow_unencrypted: bool = False,
    ) -> KeyStore:
        """Generate a fresh key ring and store it under ``path`` (which must not exist yet)."""
        if passphrase is None and not allow_unencrypted:
            raise KeyStoreError("a passphrase is required (pass allow_unencrypted=True only for throwaway keys)")
        if passphrase is not None and len(passphrase) < 12:
            raise KeyStoreError("passphrase must be at least 12 characters")
        directory = Path(path).expanduser()
        if directory.exists() and any(directory.iterdir()):
            raise KeyStoreError(f"{directory} already contains files; refusing to overwrite a key ring")
        params = params or standard_params(poly_modulus_degree, security_level, profile)
        ring = KeyRing.generate(params)
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        # [TM:K-1] Secret key encrypted at rest (AES-256-GCM, Argon2id-derived key), created 0600.
        _write_private(directory / SECRET_FILE, seal(ring.to_secret_bytes(), passphrase))
        (directory / PUBLIC_FILE).write_bytes(ring.public_bundle().to_bytes())
        meta = {
            "ring_id": ring.ring_id,
            "params": params.to_dict(),
            "encrypted": passphrase is not None,
            "kdf": {
                "algorithm": "argon2id",
                "time_cost": KDF_TIME_COST,
                "memory_kib": KDF_MEMORY_KIB,
                "parallelism": KDF_PARALLELISM,
            },
            "cipher": "AES-256-GCM",
            "format_version": VERSION,
        }
        (directory / META_FILE).write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")
        return cls(directory, ring)

    @classmethod
    def open(cls, path: str | os.PathLike[str], *, passphrase: str | None) -> KeyStore:
        directory = Path(path).expanduser()
        secret_path = directory / SECRET_FILE
        if not secret_path.is_file():
            raise KeyStoreError(f"no key ring at {directory}")
        _check_permissions(secret_path)
        meta = cls.metadata(directory)
        if meta.get("encrypted", True) and passphrase is None:
            raise KeyStoreError("this key ring is passphrase-protected; a passphrase is required")
        raw_kdf = meta.get("kdf")
        kdf = (
            {k: int(v) for k, v in raw_kdf.items() if k in {"time_cost", "memory_kib", "parallelism"}} or None
            if isinstance(raw_kdf, dict)
            else None
        )
        secret = unseal(secret_path.read_bytes(), passphrase if meta.get("encrypted", True) else None, kdf=kdf)
        ring = KeyRing.from_secret_bytes(secret)
        if ring.ring_id != meta.get("ring_id"):
            raise KeyStoreError("key ring id does not match keystore.json")
        return cls(directory, ring)

    @staticmethod
    def metadata(path: str | os.PathLike[str]) -> dict[str, object]:
        try:
            data = json.loads((Path(path).expanduser() / META_FILE).read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise KeyStoreError(f"cannot read keystore metadata: {exc}") from exc
        if not isinstance(data, dict):
            raise KeyStoreError("keystore metadata is malformed")
        return data

    @staticmethod
    def public_bundle_bytes(path: str | os.PathLike[str]) -> bytes:
        """The public bundle without unlocking the secret key (safe to share)."""
        return (Path(path).expanduser() / PUBLIC_FILE).read_bytes()
