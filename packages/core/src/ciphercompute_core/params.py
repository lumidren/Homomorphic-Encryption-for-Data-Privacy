"""CKKS parameter sets and the security validation that guards them.

A ``CKKSParams`` value is immutable and validated when it is constructed, so an insecure
combination can never reach SEAL. The bounds come from the *Homomorphic Encryption Security
Standard* (homomorphicencryption.org, Nov 2018), the same table Microsoft SEAL ships in
``hestdparms.h`` — SEAL itself only enforces the 128-bit row (TenSEAL creates contexts with
``sec_level_type::tc128``), so the 192- and 256-bit rows are enforced here.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import IntEnum
from typing import Any, Final, Literal

from .errors import InsecureParametersError


class SecurityLevel(IntEnum):
    """Classical security level in bits, as defined by the HE Security Standard."""

    BITS_128 = 128
    BITS_192 = 192
    BITS_256 = 256


class PolyModulusDegree(IntEnum):
    """Ring dimension ``N``. Slots available for batching are ``N / 2``."""

    N_8192 = 8192
    N_16384 = 16384
    N_32768 = 32768


#: Maximum ``log2(q)`` (sum of coefficient-modulus prime bit sizes) permitted for a given
#: ``(poly_modulus_degree, security_level)`` — HE Security Standard, classical (TC) column.
MAX_COEFF_MODULUS_BITS: Final[Mapping[tuple[int, int], int]] = {
    (1024, 128): 27,
    (1024, 192): 19,
    (1024, 256): 14,
    (2048, 128): 54,
    (2048, 192): 37,
    (2048, 256): 29,
    (4096, 128): 109,
    (4096, 192): 75,
    (4096, 256): 58,
    (8192, 128): 218,
    (8192, 192): 152,
    (8192, 256): 118,
    (16384, 128): 438,
    (16384, 192): 305,
    (16384, 256): 237,
    (32768, 128): 881,
    (32768, 192): 611,
    (32768, 256): 476,
}

#: SEAL's hard limit on a single coefficient-modulus prime.
MAX_PRIME_BITS: Final = 60
#: Below this SEAL cannot reliably find enough distinct NTT-friendly primes for N ≥ 8192,
#: and the usable precision becomes meaningless.
MIN_PRIME_BITS: Final = 20
#: ``len(coeff_mod_bit_sizes) - 2`` levels are usable: the first prime carries the initial
#: scale and the last is the special key-switching prime.
_RESERVED_PRIMES: Final = 2

Profile = Literal["balanced", "deep"]


def max_coeff_modulus_bits(poly_modulus_degree: int, level: SecurityLevel) -> int:
    """Return the standard's bound, raising for a degree the platform does not support."""
    try:
        return MAX_COEFF_MODULUS_BITS[(int(poly_modulus_degree), int(level))]
    except KeyError:
        raise InsecureParametersError(
            f"poly_modulus_degree={poly_modulus_degree} is not a supported ring dimension; "
            f"use one of {[int(d) for d in PolyModulusDegree]}",
            poly_modulus_degree=int(poly_modulus_degree),
        ) from None


@dataclass(frozen=True, slots=True)
class CKKSParams:
    """An immutable, validated CKKS parameter set.

    Attributes:
        poly_modulus_degree: Ring dimension ``N`` (8192, 16384 or 32768).
        coeff_mod_bit_sizes: Bit sizes of the coefficient-modulus primes, in chain order.
        scale_bits: ``log2`` of the CKKS encoding scale.
        security_level: The level this set must satisfy; validated at construction.
    """

    poly_modulus_degree: int
    coeff_mod_bit_sizes: tuple[int, ...]
    scale_bits: int
    security_level: SecurityLevel = SecurityLevel.BITS_128

    def __post_init__(self) -> None:
        # Normalise so equality and hashing behave regardless of how the caller built it.
        object.__setattr__(self, "coeff_mod_bit_sizes", tuple(int(b) for b in self.coeff_mod_bit_sizes))
        object.__setattr__(self, "poly_modulus_degree", int(self.poly_modulus_degree))
        object.__setattr__(self, "scale_bits", int(self.scale_bits))
        object.__setattr__(self, "security_level", SecurityLevel(self.security_level))
        self._validate()

    # [TM:T-3] Parameters are validated before any SEAL context can be built from them, and the
    # server re-runs this validation on every bundle it loads, so a downgraded set is refused.
    def _validate(self) -> None:
        n = self.poly_modulus_degree
        if n not in {int(d) for d in PolyModulusDegree}:
            raise InsecureParametersError(
                f"poly_modulus_degree={n} is not supported; choose 8192, 16384 or 32768",
                poly_modulus_degree=n,
            )
        bits = self.coeff_mod_bit_sizes
        if len(bits) < _RESERVED_PRIMES + 1:
            raise InsecureParametersError(
                f"coeff_mod_bit_sizes needs at least {_RESERVED_PRIMES + 1} primes "
                f"(first prime, one working level, special prime); got {len(bits)}",
                coeff_mod_bit_sizes=list(bits),
            )
        for b in bits:
            if not MIN_PRIME_BITS <= b <= MAX_PRIME_BITS:
                raise InsecureParametersError(
                    f"every coefficient-modulus prime must be between {MIN_PRIME_BITS} and "
                    f"{MAX_PRIME_BITS} bits (SEAL limit); got {b}",
                    coeff_mod_bit_sizes=list(bits),
                )
        if bits[-1] < max(bits[:-1]):
            # Measured, not folklore: RNS key switching (relinearisation, rotations) adds noise of
            # about 2^(largest prime - special prime) * N * sigma. A special prime smaller than the
            # first prime wipes out the fractional bits — see precision_table.json history.
            raise InsecureParametersError(
                f"the special (last) prime ({bits[-1]} bits) must be at least as large as every other "
                f"prime ({max(bits[:-1])} bits); a smaller special prime inflates key-switching noise "
                "by 2^(difference) and destroys precision",
                coeff_mod_bit_sizes=list(bits),
            )
        bound = max_coeff_modulus_bits(n, self.security_level)
        total = sum(bits)
        if total > bound:
            next_degree = _next_degree(n)
            hint = (
                f"drop a prime from the chain or raise poly_modulus_degree to {next_degree}"
                if next_degree
                else "drop a prime from the chain"
            )
            raise InsecureParametersError(
                f"coefficient modulus totals {total} bits but the HE Security Standard allows at "
                f"most {bound} bits for poly_modulus_degree={n} at {int(self.security_level)}-bit "
                f"security; {hint}",
                total_bits=total,
                max_bits=bound,
                poly_modulus_degree=n,
                security_level=int(self.security_level),
            )
        if not 0 < self.scale_bits <= MAX_PRIME_BITS:
            raise InsecureParametersError(
                f"scale_bits must be between 1 and {MAX_PRIME_BITS}; got {self.scale_bits}",
                scale_bits=self.scale_bits,
            )
        middle = bits[1:-1]
        if any(self.scale_bits > b for b in middle):
            raise InsecureParametersError(
                f"scale_bits={self.scale_bits} exceeds a working prime in {list(middle)}; "
                "rescaling would lose the fractional part, so the scale must not exceed any "
                "working prime",
                scale_bits=self.scale_bits,
                coeff_mod_bit_sizes=list(bits),
            )
        if bits[0] < self.scale_bits:
            raise InsecureParametersError(
                f"the first prime ({bits[0]} bits) must be at least scale_bits={self.scale_bits} "
                "so the integer part of encoded values has headroom",
                scale_bits=self.scale_bits,
                coeff_mod_bit_sizes=list(bits),
            )

    # ----- derived quantities -------------------------------------------------------------

    @property
    def depth(self) -> int:
        """Usable multiplicative depth (number of rescales the chain can absorb)."""
        return len(self.coeff_mod_bit_sizes) - _RESERVED_PRIMES

    @property
    def slots(self) -> int:
        """Number of real-valued slots a single ciphertext can hold."""
        return self.poly_modulus_degree // 2

    @property
    def scale(self) -> float:
        return float(2**self.scale_bits)

    @property
    def total_coeff_modulus_bits(self) -> int:
        return sum(self.coeff_mod_bit_sizes)

    @property
    def max_coeff_modulus_bits(self) -> int:
        return max_coeff_modulus_bits(self.poly_modulus_degree, self.security_level)

    @property
    def integer_headroom_bits(self) -> int:
        """Bits available for the integer part of encoded values at the top level."""
        return self.coeff_mod_bit_sizes[0] - self.scale_bits

    @property
    def max_abs_value(self) -> float:
        """Largest magnitude that can be encoded without wrapping at the top level."""
        return float(2**self.integer_headroom_bits)

    def achieved_security_level(self) -> SecurityLevel:
        """The strongest standard level this coefficient modulus satisfies."""
        total = self.total_coeff_modulus_bits
        best = SecurityLevel.BITS_128
        for level in (SecurityLevel.BITS_192, SecurityLevel.BITS_256):
            if total <= max_coeff_modulus_bits(self.poly_modulus_degree, level):
                best = level
        return best

    def with_security_level(self, level: SecurityLevel) -> CKKSParams:
        """Re-validate the same modulus chain at a different level."""
        return CKKSParams(self.poly_modulus_degree, self.coeff_mod_bit_sizes, self.scale_bits, level)

    # ----- serialisation ------------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        return {
            "poly_modulus_degree": self.poly_modulus_degree,
            "coeff_mod_bit_sizes": list(self.coeff_mod_bit_sizes),
            "scale_bits": self.scale_bits,
            "security_level": int(self.security_level),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> CKKSParams:
        try:
            return cls(
                poly_modulus_degree=int(data["poly_modulus_degree"]),
                coeff_mod_bit_sizes=tuple(int(b) for b in data["coeff_mod_bit_sizes"]),
                scale_bits=int(data["scale_bits"]),
                security_level=SecurityLevel(int(data.get("security_level", 128))),
            )
        except (KeyError, TypeError, ValueError) as exc:
            if isinstance(exc, InsecureParametersError):
                raise
            raise InsecureParametersError(f"malformed CKKS parameters: {exc}") from exc

    def describe(self) -> str:
        return (
            f"N={self.poly_modulus_degree}, primes={list(self.coeff_mod_bit_sizes)} "
            f"({self.total_coeff_modulus_bits}/{self.max_coeff_modulus_bits} bits), "
            f"scale=2^{self.scale_bits}, depth={self.depth}, {int(self.security_level)}-bit"
        )


def _next_degree(n: int) -> int | None:
    degrees = sorted(int(d) for d in PolyModulusDegree)
    larger = [d for d in degrees if d > n]
    return larger[0] if larger else None


# ----- standard parameter sets ---------------------------------------------------------------
#
# "balanced" favours precision (40-bit working primes where the budget allows);
# "deep" trades scale for extra levels. Both are validated at import time.
#
# Design rules, each backed by calibration measurements (scripts/calibrate_precision.py):
#   * special prime == first prime, so key switching costs no fractional bits;
#   * usable precision ~ scale_bits - log2(N) - 2 fresh, minus ~2-5 bits per level consumed;
#   * first prime - scale is the *integer headroom*: values, intermediate products and sums must
#     stay below 2**headroom or they wrap. Every set keeps >= 12 bits; balanced 128-bit keeps 20.
#
# There is deliberately no "deep" profile for (8192, 256-bit): 118 bits of modulus cannot carry
# a third level with any usable precision (the attempt measured *negative* precision bits).

_BALANCED: Final[dict[tuple[int, int], tuple[tuple[int, ...], int]]] = {
    (8192, 128): ((60, 40, 40, 60), 40),
    (8192, 192): ((45, 30, 30, 45), 30),
    (8192, 256): ((36, 23, 23, 36), 23),
    (16384, 128): ((60, 40, 40, 40, 40, 40, 40, 60), 40),
    (16384, 192): ((55, 35, 35, 35, 35, 35, 55), 35),
    (16384, 256): ((43, 29, 29, 29, 29, 29, 43), 29),
    (32768, 128): ((60,) + (40,) * 8 + (60,), 40),
    (32768, 192): ((60,) + (40,) * 8 + (60,), 40),
    (32768, 256): ((50,) + (35,) * 8 + (50,), 35),
}

_DEEP: Final[dict[tuple[int, int], tuple[tuple[int, ...], int]]] = {
    (8192, 128): ((45, 30, 30, 30, 30, 45), 30),
    (8192, 192): ((38, 25, 25, 25, 38), 25),
    (16384, 128): ((50,) + (30,) * 11 + (50,), 30),
    (16384, 192): ((45,) + (30,) * 7 + (45,), 30),
    (16384, 256): ((38,) + (26,) * 6 + (38,), 26),
    (32768, 128): ((60,) + (40,) * 14 + (60,), 40),
    (32768, 192): ((50,) + (35,) * 14 + (50,), 35),
    (32768, 256): ((45,) + (30,) * 12 + (45,), 30),
}


def _build(
    table: Mapping[tuple[int, int], tuple[tuple[int, ...], int]],
) -> dict[tuple[PolyModulusDegree, SecurityLevel], CKKSParams]:
    return {
        (PolyModulusDegree(n), SecurityLevel(level)): CKKSParams(n, bits, scale, SecurityLevel(level))
        for (n, level), (bits, scale) in table.items()
    }


STANDARD_PARAMS: Final[Mapping[tuple[PolyModulusDegree, SecurityLevel], CKKSParams]] = _build(_BALANCED)
DEEP_PARAMS: Final[Mapping[tuple[PolyModulusDegree, SecurityLevel], CKKSParams]] = _build(_DEEP)


def standard_params(
    poly_modulus_degree: int | PolyModulusDegree,
    security_level: int | SecurityLevel = SecurityLevel.BITS_128,
    profile: Profile = "balanced",
) -> CKKSParams:
    """Return a validated standard parameter set.

    Args:
        poly_modulus_degree: 8192, 16384 or 32768.
        security_level: 128, 192 or 256.
        profile: ``"balanced"`` (more precision) or ``"deep"`` (more levels).
    """
    key = (PolyModulusDegree(int(poly_modulus_degree)), SecurityLevel(int(security_level)))
    table = STANDARD_PARAMS if profile == "balanced" else DEEP_PARAMS
    try:
        return table[key]
    except KeyError:
        raise InsecureParametersError(
            f"no '{profile}' profile exists for poly_modulus_degree={int(key[0])} at {int(key[1])}-bit "
            "security: the coefficient-modulus budget cannot carry an extra level with usable precision",
            poly_modulus_degree=int(key[0]),
            security_level=int(key[1]),
            profile=profile,
        ) from None


def all_presets() -> list[tuple[Profile, CKKSParams]]:
    """Every preset, smallest ring first, balanced before deep within a ring."""
    out: list[tuple[Profile, CKKSParams]] = []
    for degree in PolyModulusDegree:
        for level in SecurityLevel:
            out.append(("balanced", STANDARD_PARAMS[(degree, level)]))
            if (degree, level) in DEEP_PARAMS:
                out.append(("deep", DEEP_PARAMS[(degree, level)]))
    return out
