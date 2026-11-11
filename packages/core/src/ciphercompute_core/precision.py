"""Measured precision bounds for every standard parameter set.

CKKS results are approximate. The error after a computation depends on the scale, the ring
dimension and — most strongly — on how many rescales (levels) the computation consumed. Rather
than quote textbook estimates, CipherCompute *measures* the worst normalised error per
parameter set and per level with ``scripts/calibrate_precision.py`` and ships the result in
``data/precision_table.json``. The property-based tests use these bounds as their tolerance and
``tests/test_precision.py`` re-measures a sample on every run so drift fails CI.

Error model
-----------
For a computation with inputs ``x``, plaintext arguments ``a`` and expected output ``y`` let
``M = max(1, max|x|, max|a|, max|y|)``. The *normalised error* is ``max|got - y| / M``. The
table stores, per level, ``precision_bits = floor(-log2(worst normalised error)) - margin``,
and :func:`tolerance` returns ``M * 2**-precision_bits``.

Inputs must also respect the integer headroom of the parameter set, otherwise values wrap
silently; :func:`recommended_input_bound` gives a safe magnitude for a given vector length.
"""

from __future__ import annotations

import json
import math
from importlib import resources
from typing import Any, Final

from .params import CKKSParams, all_presets

#: Safety margin (in bits) subtracted from the measured worst case.
CALIBRATION_MARGIN_BITS: Final = 3

_TABLE: dict[str, Any] | None = None


def table_key(params: CKKSParams) -> str:
    primes = ",".join(map(str, params.coeff_mod_bit_sizes))
    return f"{params.poly_modulus_degree}/{int(params.security_level)}/{primes}/{params.scale_bits}"


def load_table() -> dict[str, Any]:
    global _TABLE
    if _TABLE is None:
        with (
            resources.files("ciphercompute_core.data")
            .joinpath("precision_table.json")
            .open("r", encoding="utf-8") as fh
        ):
            _TABLE = json.load(fh)
    return _TABLE


def heuristic_precision_bits(params: CKKSParams, levels_consumed: int) -> int:
    """Conservative estimate for parameter sets that have not been calibrated.

    Fresh ciphertexts lose roughly ``log2(N) + 2`` bits of the scale to encoding noise; each
    rescale costs about three more bits in practice. The measured table is always tighter.
    """
    bits = params.scale_bits - math.ceil(math.log2(params.poly_modulus_degree)) - 2 - 3 * levels_consumed
    return max(1, bits)


def bits_from_worst_error(worst_normalized_error: float) -> int:
    """Usable bits implied by a measured worst normalised error, minus the safety margin."""
    if worst_normalized_error <= 0:
        return 60
    return max(1, math.floor(-math.log2(worst_normalized_error)) - CALIBRATION_MARGIN_BITS)


def precision_bits(params: CKKSParams, levels_consumed: int) -> tuple[int, bool]:
    """``(bits, measured)`` — ``measured`` is False when the heuristic or extrapolation was used.

    The table ships the raw measured errors; bits are derived here so the margin lives in one
    place and a recalibration is never needed just to change it.
    """
    if levels_consumed < 0 or levels_consumed > params.depth:
        raise ValueError(f"levels_consumed must be within 0..{params.depth}; got {levels_consumed}")
    entry = load_table().get(table_key(params))
    if entry is None:
        return heuristic_precision_bits(params, levels_consumed), False
    worst = entry["worst_normalized_error"]
    key = str(levels_consumed)
    if key in worst:
        return bits_from_worst_error(float(worst[key])), True
    # Deeper than calibrated: extrapolate from the deepest measured level, 3 bits per level.
    deepest = max(int(k) for k in worst)
    return max(1, bits_from_worst_error(float(worst[str(deepest)])) - 3 * (levels_consumed - deepest)), False


def tolerance(params: CKKSParams, levels_consumed: int, magnitude: float) -> float:
    """Absolute error tolerance for a result of magnitude class ``magnitude`` (see module doc)."""
    bits, _ = precision_bits(params, levels_consumed)
    return max(1.0, float(magnitude)) * 2.0 ** (-bits)


def recommended_input_bound(params: CKKSParams, length: int) -> float:
    """Largest ``|x|`` such that products and sums over ``length`` values stay in headroom.

    Derived from ``length * bound**2 <= 2**headroom / 2``.
    """
    if length < 1:
        raise ValueError("length must be positive")
    growth = math.ceil(math.log2(length)) if length > 1 else 0
    return float(2.0 ** ((params.integer_headroom_bits - growth) / 2 - 1))


def calibrated_params() -> list[CKKSParams]:
    """Every preset that has an entry in the shipped table."""
    table = load_table()
    return [p for _, p in all_presets() if table_key(p) in table]
