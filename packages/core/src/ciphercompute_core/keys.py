"""Key material.

``KeyRing`` is the only type in the platform that holds a secret key, and it exists only on
the client. ``PublicKeyBundle`` is what the server works with. The secret key is kept out of
the server *structurally*, not procedurally: ``PublicKeyBundle.load`` — the one entry point
through which key material reaches the API and the worker — refuses any serialized context
that contains a secret key.
"""

from __future__ import annotations

import hashlib
import secrets
from typing import TYPE_CHECKING, Any, Final

import numpy as np
import tenseal as ts

from .envelope import MAGIC_BUNDLE, pack, unpack
from .errors import KeyMismatchError, SecretKeyLeakError, SerializationError
from .params import CKKSParams

if TYPE_CHECKING:
    from .ciphertext import EncryptedVector

MAGIC_SECRET: Final = b"CCSK"
BUNDLE_KIND: Final = "public_key_bundle"
SECRET_KIND: Final = "secret_key_ring"
_RING_ID_HEX_LEN: Final = 32


def fingerprint_bytes(data: bytes) -> str:
    """``sha256:<hex>`` of ``data``; used for bundle and ciphertext integrity checks."""
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _new_ring_id() -> str:
    return secrets.token_hex(_RING_ID_HEX_LEN // 2)


def _validate_ring_id(value: Any) -> str:
    if not isinstance(value, str) or len(value) != _RING_ID_HEX_LEN:
        raise SerializationError("ring_id must be a 32-character hex string", ring_id=value)
    try:
        int(value, 16)
    except ValueError:
        raise SerializationError("ring_id must be a 32-character hex string", ring_id=value) from None
    return value.lower()


def _read_context_params(ctx: Any) -> tuple[int, tuple[int, ...]]:
    """Read ``(poly_modulus_degree, coeff_mod_bit_sizes)`` from the live SEAL context.

    TenSEAL does not bind ``EncryptionParameters.coeff_modulus``, but every level of the
    modulus chain reports its total bit count, and successive levels differ by exactly one
    prime: key level = all primes, first level = without the special prime, then one working
    prime fewer per level down to the first prime alone. The differences recover every prime
    size, in chain order.
    """
    seal = ctx.data.seal_context()
    key_data = seal.key_context_data()
    degree = int(key_data.parms().poly_modulus_degree())
    totals = [int(key_data.total_coeff_modulus_bit_count())]
    data = seal.first_context_data()
    while data is not None:
        totals.append(int(data.total_coeff_modulus_bit_count()))
        data = data.next_context_data()
    bits = [totals[-1]] + [totals[i - 1] - totals[i] for i in range(len(totals) - 1, 0, -1)]
    return degree, tuple(bits)


def _check_context_matches(ctx: Any, params: CKKSParams) -> None:
    degree, bits = _read_context_params(ctx)
    if degree != params.poly_modulus_degree or bits != params.coeff_mod_bit_sizes:
        raise SerializationError(
            "the envelope header's parameters do not match the encryption context inside it",
            header=params.to_dict(),
            context={"poly_modulus_degree": degree, "coeff_mod_bit_sizes": list(bits)},
        )
    if float(ctx.global_scale) != params.scale:
        raise SerializationError(
            "the envelope header's scale does not match the encryption context inside it",
            header_scale_bits=params.scale_bits,
            context_scale=float(ctx.global_scale),
        )


class PublicKeyBundle:
    """Public, relinearization and Galois keys for one key ring — never a secret key.

    Instances are only created through :meth:`load`, so every bundle in memory has passed the
    secret-key check, the parameter-security check and the header/context consistency check.
    """

    __slots__ = ("_ctx", "_fingerprint", "_params", "_raw", "_ring_id")

    def __init__(self, ctx: Any, params: CKKSParams, ring_id: str, raw: bytes) -> None:
        self._ctx = ctx
        self._params = params
        self._ring_id = ring_id
        self._raw = raw
        self._fingerprint = fingerprint_bytes(raw)

    @classmethod
    def load(cls, data: bytes) -> PublicKeyBundle:
        """Parse a serialized bundle, refusing anything that carries a secret key."""
        header, raw = unpack(MAGIC_BUNDLE, data)
        if header.get("kind") != BUNDLE_KIND:
            raise SerializationError(f"expected a {BUNDLE_KIND} envelope", kind=header.get("kind"))
        ring_id = _validate_ring_id(header.get("ring_id"))
        params = CKKSParams.from_dict(header.get("params") or {})
        try:
            ctx = ts.context_from(raw)
        except Exception as exc:  # TenSEAL raises plain RuntimeError/ValueError
            raise SerializationError(f"TenSEAL could not deserialize the context: {exc}") from exc
        # [TM:I-1] The only gate through which key material enters the server. A context
        # that can decrypt is rejected before anything is stored or computed.
        if ctx.is_private() or ctx.has_secret_key():
            raise SecretKeyLeakError(
                "the bundle contains a secret key; secret keys must never leave the client",
                ring_id=ring_id,
            )
        if not (ctx.has_public_key() and ctx.has_relin_keys() and ctx.has_galois_keys()):
            raise SerializationError(
                "bundle must carry public, relinearization and Galois keys",
                has_public_key=bool(ctx.has_public_key()),
                has_relin_keys=bool(ctx.has_relin_keys()),
                has_galois_keys=bool(ctx.has_galois_keys()),
            )
        _check_context_matches(ctx, params)
        return cls(ctx, params, ring_id, raw)

    def _header(self) -> dict[str, Any]:
        return {"kind": BUNDLE_KIND, "ring_id": self._ring_id, "params": self._params.to_dict()}

    def to_bytes(self) -> bytes:
        return pack(MAGIC_BUNDLE, self._header(), self._raw)

    @property
    def params(self) -> CKKSParams:
        return self._params

    @property
    def ring_id(self) -> str:
        """Identity of the key ring that produced this bundle (shared with its ciphertexts)."""
        return self._ring_id

    @property
    def fingerprint(self) -> str:
        """SHA-256 of the serialized key material; an integrity check, not an identity."""
        return self._fingerprint

    @property
    def size_bytes(self) -> int:
        return len(self._raw)

    def context(self) -> Any:
        """The underlying public TenSEAL context (for ``ciphertext`` and ``ops``)."""
        return self._ctx

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, PublicKeyBundle):
            return NotImplemented
        return self._ring_id == other._ring_id and self._fingerprint == other._fingerprint

    def __hash__(self) -> int:
        return hash((self._ring_id, self._fingerprint))

    def __repr__(self) -> str:
        return f"PublicKeyBundle(ring_id={self._ring_id!r}, {self._params.describe()}, {self.size_bytes / 1e6:.1f} MB)"


class KeyRing:
    """Owner of a CKKS secret key. Lives on the client only.

    There is deliberately no way to obtain the secret key as bytes except
    :meth:`to_secret_bytes`, which the client SDK wraps in an encrypted keystore.
    """

    __slots__ = ("_ctx", "_params", "_ring_id")

    def __init__(self, ctx: Any, params: CKKSParams, ring_id: str) -> None:
        if not ctx.is_private():
            raise SerializationError("a KeyRing requires a private context")
        self._ctx = ctx
        self._params = params
        self._ring_id = ring_id

    @classmethod
    def generate(cls, params: CKKSParams) -> KeyRing:
        """Generate a fresh secret/public/relinearization/Galois key set for ``params``."""
        ctx = ts.context(
            ts.SCHEME_TYPE.CKKS,
            poly_modulus_degree=params.poly_modulus_degree,
            coeff_mod_bit_sizes=list(params.coeff_mod_bit_sizes),
        )
        ctx.global_scale = params.scale
        ctx.generate_galois_keys()
        if not ctx.has_relin_keys():
            ctx.generate_relin_keys()
        return cls(ctx, params, _new_ring_id())

    @property
    def params(self) -> CKKSParams:
        return self._params

    @property
    def ring_id(self) -> str:
        return self._ring_id

    def context(self) -> Any:
        """The private TenSEAL context (used for local encryption and decryption)."""
        return self._ctx

    def public_bundle(self) -> PublicKeyBundle:
        """Serialize the public half of the ring and re-load it through the server's gate."""
        # [TM:I-1] ``save_secret_key=False`` is hard-coded; there is no parameter to flip it.
        raw = self._ctx.serialize(
            save_public_key=True, save_secret_key=False, save_galois_keys=True, save_relin_keys=True
        )
        header = {"kind": BUNDLE_KIND, "ring_id": self._ring_id, "params": self._params.to_dict()}
        return PublicKeyBundle.load(pack(MAGIC_BUNDLE, header, raw))

    def decrypt(self, vector: EncryptedVector) -> np.ndarray:
        """Decrypt an :class:`EncryptedVector` produced under this ring."""
        if vector.ring_id != self._ring_id:
            raise KeyMismatchError(
                "ciphertext was produced under a different key ring",
                expected_ring_id=self._ring_id,
                got_ring_id=vector.ring_id,
            )
        values = vector.raw().decrypt(self._ctx.secret_key())
        return np.asarray(values[: vector.length], dtype=np.float64)

    def to_secret_bytes(self) -> bytes:
        """Serialize the whole ring, secret key included. Callers must encrypt this at rest."""
        raw = self._ctx.serialize(
            save_public_key=True, save_secret_key=True, save_galois_keys=True, save_relin_keys=True
        )
        header = {"kind": SECRET_KIND, "ring_id": self._ring_id, "params": self._params.to_dict()}
        return pack(MAGIC_SECRET, header, raw)

    @classmethod
    def from_secret_bytes(cls, data: bytes) -> KeyRing:
        header, raw = unpack(MAGIC_SECRET, data)
        if header.get("kind") != SECRET_KIND:
            raise SerializationError(f"expected a {SECRET_KIND} envelope", kind=header.get("kind"))
        ring_id = _validate_ring_id(header.get("ring_id"))
        params = CKKSParams.from_dict(header.get("params") or {})
        try:
            ctx = ts.context_from(raw)
        except Exception as exc:
            raise SerializationError(f"TenSEAL could not deserialize the context: {exc}") from exc
        if not ctx.is_private():
            raise SerializationError("secret ring envelope does not contain a secret key")
        _check_context_matches(ctx, params)
        # Evaluation keys are derived from the secret key and may be regenerated after a reload.
        if not ctx.has_galois_keys():
            ctx.generate_galois_keys()
        if not ctx.has_relin_keys():
            ctx.generate_relin_keys()
        return cls(ctx, params, ring_id)

    def __repr__(self) -> str:
        return f"KeyRing(ring_id={self._ring_id!r}, {self._params.describe()})"
