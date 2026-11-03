"""Polynomial approximations of the logistic sigmoid for encrypted inference.

CKKS can only evaluate polynomials, so ``sigma(z) = 1 / (1 + e^-z)`` is replaced by a
least-squares polynomial fit over ``[-8, 8]`` — the interval where logistic-regression
logits of standardised features live in practice. The coefficients below were produced by
``numpy.polynomial.polynomial.polyfit`` on a 4001-point grid and match the degree-3 and
degree-5 approximations used by Kim et al. (iDASH 2017 / BMC Med. Genomics 2018). Their
maximum absolute error on the interval is asserted by ``tests/test_sigmoid.py``.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Final

import numpy as np

from .errors import InvalidArgumentError

#: Coefficients in increasing degree order (``c0 + c1 z + c2 z^2 + ...``).
SIGMOID_COEFFICIENTS: Final[Mapping[int, tuple[float, ...]]] = {
    3: (0.5, 0.15009364278, 0.0, -0.0015920415622),
    5: (0.5, 0.19127975032, 0.0, -0.0045936957853, 0.0, 0.000042189683491),
}

#: Interval on which the approximation is valid. Outside it the polynomial diverges.
SIGMOID_DOMAIN: Final[tuple[float, float]] = (-8.0, 8.0)

#: Documented maximum absolute error of each approximation on ``SIGMOID_DOMAIN``.
SIGMOID_MAX_ABS_ERROR: Final[Mapping[int, float]] = {3: 0.115, 5: 0.062}

SUPPORTED_DEGREES: Final[tuple[int, ...]] = tuple(sorted(SIGMOID_COEFFICIENTS))

#: Multiplicative depth TenSEAL's ``CKKSVector.polyval`` consumes for a polynomial of the given
#: degree: ``floor(log2(degree)) + 1`` (powers by repeated squaring, then one plaintext
#: multiplication by the coefficients). Measured, not derived —
#: ``tests/test_depth_regression.py`` re-measures it on every run.
POLYVAL_DEPTH: Final[Mapping[int, int]] = {1: 1, 2: 2, 3: 2, 4: 3, 5: 3, 6: 3, 7: 3}


def sigmoid(z: np.ndarray) -> np.ndarray:
    """Exact logistic function (plaintext reference)."""
    return 1.0 / (1.0 + np.exp(-np.asarray(z, dtype=np.float64)))


def sigmoid_coefficients(degree: int) -> tuple[float, ...]:
    try:
        return SIGMOID_COEFFICIENTS[int(degree)]
    except (KeyError, TypeError, ValueError):
        raise InvalidArgumentError(
            f"sigmoid approximation degree must be one of {list(SUPPORTED_DEGREES)}; got {degree!r}",
            degree=degree,
        ) from None


def sigmoid_poly(z: np.ndarray, degree: int) -> np.ndarray:
    """Plaintext evaluation of the degree-``degree`` approximation (reference for tests)."""
    coeffs = sigmoid_coefficients(degree)
    return np.asarray(np.polynomial.polynomial.polyval(np.asarray(z, dtype=np.float64), coeffs), dtype=np.float64)


def polyval_depth(degree: int) -> int:
    """Levels consumed by ``CKKSVector.polyval`` for a polynomial of this degree."""
    try:
        return POLYVAL_DEPTH[int(degree)]
    except (KeyError, TypeError, ValueError):
        raise InvalidArgumentError(
            f"polynomial degree must be between 1 and {max(POLYVAL_DEPTH)}; got {degree!r}",
            degree=degree,
        ) from None
