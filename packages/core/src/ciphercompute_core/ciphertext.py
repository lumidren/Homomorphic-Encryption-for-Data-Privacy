"""``EncryptedVector`` — a CKKS ciphertext holding a real vector, with exact level accounting.

The number of remaining levels is read from the ciphertext itself (``coeff_modulus_size``),
never from a header, so a client cannot mis-declare how much depth a ciphertext has left.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Final

import numpy as np
import tenseal as ts

from .envelope import MAGIC_CIPHERTEXT, pack, unpack
from .errors import InvalidArgumentError, KeyMismatchError, SerializationError
from .keys import fingerprint_bytes
from .params import CKKSParams

if TYPE_CHECKING:
    from .budget import DepthReport
    from .keys import KeyRing, PublicKeyBundle

CIPHERTEXT_KIND: Final = "ckks_vector"


class EncryptedVector:
    """A real-valued vector encrypted under a key ring.

    ``length`` is the number of slots in use (after optional padding); the remaining slots are
    zero. Arithmetic is performed by :mod:`ciphercompute_core.ops`, not by this class.
    """

    __slots__ = ("_length", "_params", "_ring_id", "_vector")

    def __init__(self, vector: Any, params: CKKSParams, ring_id: str, length: int) -> None:
        self._vector = vector
        self._params = params
        self._ring_id = ring_id
        self._length = int(length)

    # ----- construction -------------------------------------------------------------------

    @classmethod
    def encrypt(
        cls,
        keys: PublicKeyBundle | KeyRing,
        values: Any,
        *,
        pad_to: int | None = None,
    ) -> EncryptedVector:
        """Encrypt ``values`` (any 1-D array-like of finite floats).

        Args:
            keys: A :class:`PublicKeyBundle` or :class:`KeyRing`; only the public key is used.
            values: Finite real numbers with ``|x| < params.max_abs_value``.
            pad_to: Fix the visible vector length to this many slots by appending zeros, so the
                ciphertext does not reveal how many values it really holds.
        """
        params = keys.params
        arr = np.asarray(values, dtype=np.float64).ravel()
        if arr.size == 0:
            raise InvalidArgumentError("cannot encrypt an empty vector")
        if not np.all(np.isfinite(arr)):
            raise InvalidArgumentError("values must be finite (no NaN or infinity)")
        peak = float(np.max(np.abs(arr)))
        if peak >= params.max_abs_value:
            raise InvalidArgumentError(
                f"|value| must be below 2^{params.integer_headroom_bits} = {params.max_abs_value:g} "
                "for this parameter set; scale your data or choose a set with more headroom",
                max_abs_value=params.max_abs_value,
                observed=peak,
            )
        length = int(arr.size)
        if pad_to is not None:
            # [TM:I-5] Padding hides the true length behind a client-chosen visible length.
            if int(pad_to) < length:
                raise InvalidArgumentError(f"pad_to={pad_to} is smaller than the vector length {length}", pad_to=pad_to)
            length = int(pad_to)
            arr = np.concatenate([arr, np.zeros(length - arr.size)])
        if length > params.slots:
            raise InvalidArgumentError(
                f"vector length {length} exceeds the {params.slots} slots of "
                f"poly_modulus_degree={params.poly_modulus_degree}",
                length=length,
                slots=params.slots,
            )
        vector = ts.ckks_vector(keys.context(), arr.tolist())
        return cls(vector, params, keys.ring_id, length)

    @classmethod
    def load(cls, keys: PublicKeyBundle | KeyRing, data: bytes) -> EncryptedVector:
        """Parse a serialized ciphertext and bind it to ``keys``' context.

        The header's declared level count is cross-checked against the real ciphertext; a
        mismatch is rejected so nothing downstream can rely on a forged header.
        """
        header, payload = unpack(MAGIC_CIPHERTEXT, data)
        if header.get("kind") != CIPHERTEXT_KIND:
            raise SerializationError(f"expected a {CIPHERTEXT_KIND} envelope", kind=header.get("kind"))
        ring_id = header.get("ring_id")
        if ring_id != keys.ring_id:
            raise KeyMismatchError(
                "ciphertext belongs to a different key ring",
                expected_ring_id=keys.ring_id,
                got_ring_id=ring_id,
            )
        params = CKKSParams.from_dict(header.get("params") or {})
        if params != keys.params:
            raise KeyMismatchError(
                "ciphertext parameters do not match the key bundle",
                bundle_params=keys.params.to_dict(),
                ciphertext_params=params.to_dict(),
            )
        length = header.get("length")
        if not isinstance(length, int) or not 1 <= length <= params.slots:
            raise SerializationError("ciphertext header has an invalid length", length=length)
        try:
            vector = ts.ckks_vector_from(keys.context(), payload)
        except Exception as exc:
            raise SerializationError(f"TenSEAL could not deserialize the ciphertext: {exc}") from exc
        ev = cls(vector, params, ring_id, length)
        if int(vector.size()) != length:
            raise SerializationError(
                "ciphertext header length does not match the ciphertext",
                header_length=length,
                actual=int(vector.size()),
            )
        declared = header.get("levels_consumed")
        if declared != ev.levels_consumed:
            raise SerializationError(
                f"ciphertext header claims {declared} levels consumed but the ciphertext has "
                f"consumed {ev.levels_consumed}",
                declared=declared,
                actual=ev.levels_consumed,
            )
        return ev

    # ----- accessors ----------------------------------------------------------------------

    def raw(self) -> Any:
        """The underlying ``tenseal.CKKSVector`` (for ``ops`` and ``KeyRing.decrypt``)."""
        return self._vector

    @property
    def params(self) -> CKKSParams:
        return self._params

    @property
    def ring_id(self) -> str:
        return self._ring_id

    @property
    def length(self) -> int:
        return self._length

    @property
    def levels_remaining(self) -> int:
        """Multiplications this ciphertext can still absorb, read from the ciphertext itself."""
        return int(self._vector.ciphertext()[0].coeff_modulus_size()) - 1

    @property
    def levels_consumed(self) -> int:
        return self._params.depth - self.levels_remaining

    @property
    def scale(self) -> float:
        # ``CKKSVector.scale()`` is not bound in TenSEAL 0.3.18; the SEAL ciphertext exposes it.
        return float(self._vector.ciphertext()[0].scale)

    def depth_report(self, precision_class: str = "rotations") -> DepthReport:
        from .budget import DepthReport

        return DepthReport.for_params(self._params, self.levels_consumed, precision_class)

    # ----- serialization ------------------------------------------------------------------

    def _header(self) -> dict[str, Any]:
        return {
            "kind": CIPHERTEXT_KIND,
            "ring_id": self._ring_id,
            "params": self._params.to_dict(),
            "length": self._length,
            "levels_consumed": self.levels_consumed,
        }

    def to_bytes(self) -> bytes:
        return pack(MAGIC_CIPHERTEXT, self._header(), self._vector.serialize())

    def fingerprint(self) -> str:
        # [TM:T-2] Content fingerprint recorded at upload and echoed in job manifests so a
        # client can detect a swapped or altered input.
        return fingerprint_bytes(self._vector.serialize())

    # ----- helpers for ops ------------------------------------------------------------------

    def spawn(self, vector: Any, length: int) -> EncryptedVector:
        """Wrap a derived ``CKKSVector`` with the same ring and parameters."""
        return EncryptedVector(vector, self._params, self._ring_id, length)

    def copy(self) -> EncryptedVector:
        return self.spawn(self._vector.copy(), self._length)

    def __repr__(self) -> str:
        return (
            f"EncryptedVector(length={self._length}, levels_consumed={self.levels_consumed}/"
            f"{self._params.depth}, ring_id={self._ring_id!r})"
        )
