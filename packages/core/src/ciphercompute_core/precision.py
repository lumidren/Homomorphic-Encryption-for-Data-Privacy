"""Measured precision bounds for every standard parameter set.

CKKS results are approximate. The error after a computation depends on the scale, the ring
dimension and — most strongly — on how many rescales (levels) the computation consumed. Rather
than quote textbook estimates, CipherCompute *measures* the worst normalised error per
parameter set and per level with ``scripts/calibrate_precision.py`` and ships the result in
``data/precision_table.json``. The property-based tests use these bounds as their tolerance.

The noise floor of rotation-heavy operations (``sum``, ``mean``, ``dot_product``) varies by
10-100x between *fresh key rings with identical parameters*. The calibration therefore samples
many key rings (12 per N=8192 set, 4 per N=16384 set), uses zero and constant inputs as well as
random ones, and keeps a 4-bit (16x) margin over the worst case it saw. These are empirical
bounds, not proofs: they are what the tests enforce and what the API reports to clients.

Precision is tracked per *class* of operation, because the two behave very differently:

* ``slotwise`` — additions and multiplications slot by slot (vector add, scalar and
  element-wise multiply, column-layout regression): error grows with the data and the depth;
* ``rotations`` — operations that rotate slots with Galois keys (sum, mean, variance, dot
  product, weighted average, matvec, single-sample regression): each rotation adds key-switching
  noise, giving an absolute floor that dominates for small values.

A precision of 0 bits means the measured error reached the size of the values themselves: the
parameter set offers no usable precision for that class at that depth. It is reported as such
rather than rounded up.

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
from collections.abc import Mapping, Sequence
from importlib import resources
from typing import Any, Final

import numpy as np

from .params import CKKSParams, all_presets

#: Safety margin (in bits) subtracted from the measured worst case.
CALIBRATION_MARGIN_BITS: Final = 4

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


PRECISION_CLASSES: Final = ("slotwise", "rotations")


#: Extra bits the heuristic gives up for the first multiplication (relinearisation + rescale).
HEURISTIC_FIRST_MULTIPLY_BITS: Final = 3
#: Extra bits the heuristic gives up for rotation key-switching noise (measured gap: 8-9 bits).
HEURISTIC_ROTATION_BITS: Final = 10


def heuristic_precision_bits(params: CKKSParams, levels_consumed: int, precision_class: str = "rotations") -> int:
    """Conservative estimate for parameter sets that have not been calibrated (e.g. N=32768).

    Fresh ciphertexts lose roughly ``log2(N) + 2`` bits of the scale to encoding noise, the same
    calibration margin as measured sets is applied, the first multiplication costs a few more bits
    and each rescale about three. Rotating operations lose a further ~10 bits to key switching.
    ``test_heuristic_never_exceeds_measurements`` holds this at or below every calibrated value.
    """
    fresh = params.scale_bits - math.ceil(math.log2(params.poly_modulus_degree)) - 2 - CALIBRATION_MARGIN_BITS
    if precision_class == "rotations":
        bits = fresh - HEURISTIC_ROTATION_BITS - 3 * levels_consumed
    else:
        bits = fresh - (HEURISTIC_FIRST_MULTIPLY_BITS + 3 * levels_consumed if levels_consumed else 0)
    return max(0, bits)


def magnitude_class(inputs: Sequence[Any], args: Mapping[str, Any], expected: Any) -> float:
    """``M`` in the error model: the largest magnitude among inputs, plaintext arguments and output.

    Floored at 1 so the absolute noise floor of CKKS (which does not shrink with the data) is part
    of what the calibration measures and what the tolerance allows.
    """
    mags = [1.0, float(np.max(np.abs(np.asarray(expected, dtype=np.float64))))]
    mags += [float(np.max(np.abs(np.asarray(x, dtype=np.float64)))) for x in inputs]
    for key in ("scalar", "intercept"):
        if key in args:
            mags.append(abs(float(args[key])))
    for key in ("weights", "matrix"):
        if key in args:
            mags.append(float(np.max(np.abs(np.asarray(args[key], dtype=np.float64)))))
    return max(mags)


def bits_from_worst_error(worst_normalized_error: float) -> int:
    """Usable bits implied by a measured worst normalised error, minus the safety margin."""
    if worst_normalized_error <= 0:
        return 60
    return max(0, math.floor(-math.log2(worst_normalized_error)) - CALIBRATION_MARGIN_BITS)


def precision_bits(params: CKKSParams, levels_consumed: int, precision_class: str = "rotations") -> tuple[int, bool]:
    """``(bits, measured)`` for one operation class — ``measured`` is False when the heuristic or
    extrapolation was used. ``rotations`` is the default because it is the conservative class.

    The table ships the raw measured errors; bits are derived here so the margin lives in one
    place and a recalibration is never needed just to change it.
    """
    if precision_class not in PRECISION_CLASSES:
        raise ValueError(f"precision_class must be one of {PRECISION_CLASSES}; got {precision_class!r}")
    if levels_consumed < 0 or levels_consumed > params.depth:
        raise ValueError(f"levels_consumed must be within 0..{params.depth}; got {levels_consumed}")
    entry = load_table().get(table_key(params))
    if entry is None:
        return heuristic_precision_bits(params, levels_consumed, precision_class), False
    worst = entry["worst_normalized_error"].get(precision_class) or {}
    if not worst:
        return heuristic_precision_bits(params, levels_consumed, precision_class), False
    measured_levels = sorted(int(k) for k in worst)
    deepest = measured_levels[-1]
    if levels_consumed > deepest:
        # Deeper than calibrated: extrapolate from everything measured, 3 bits per extra level.
        base = bits_from_worst_error(max(float(v) for v in worst.values()))
        return max(0, base - 3 * (levels_consumed - deepest)), False
    # A computation that consumed L levels may contain any operation measured at a shallower level
    # (a variance contains a sum), so the bound is the worst error at or below L. A level that no
    # calibrated operation lands on exactly is bounded by the next measured level above it as well.
    ceiling = next(level for level in measured_levels if level >= levels_consumed)
    error = max(float(worst[str(level)]) for level in measured_levels if level <= ceiling)
    return bits_from_worst_error(error), str(levels_consumed) in worst


def tolerance(params: CKKSParams, levels_consumed: int, magnitude: float, precision_class: str = "rotations") -> float:
    """Absolute error tolerance for a result of magnitude class ``magnitude`` (see module doc)."""
    bits, _ = precision_bits(params, levels_consumed, precision_class)
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
