from __future__ import annotations

import numpy as np
import pytest

from ciphercompute_core.errors import InvalidArgumentError
from ciphercompute_core.sigmoid import (
    POLYVAL_DEPTH,
    SIGMOID_DOMAIN,
    SIGMOID_MAX_ABS_ERROR,
    SUPPORTED_DEGREES,
    polyval_depth,
    sigmoid,
    sigmoid_coefficients,
    sigmoid_poly,
)


@pytest.mark.parametrize("degree", SUPPORTED_DEGREES)
def test_documented_max_error_holds_on_domain(degree: int) -> None:
    z = np.linspace(*SIGMOID_DOMAIN, 8001)
    err = np.max(np.abs(sigmoid_poly(z, degree) - sigmoid(z)))
    assert err <= SIGMOID_MAX_ABS_ERROR[degree]
    # the bound is tight to within 10%, i.e. not padded to hide a bad fit
    assert err >= 0.9 * SIGMOID_MAX_ABS_ERROR[degree]


@pytest.mark.parametrize("degree", SUPPORTED_DEGREES)
def test_symmetry_and_midpoint(degree: int) -> None:
    z = np.linspace(-8, 8, 101)
    assert sigmoid_poly(np.array([0.0]), degree)[0] == pytest.approx(0.5)
    assert np.allclose(sigmoid_poly(-z, degree), 1.0 - sigmoid_poly(z, degree))
    assert len(sigmoid_coefficients(degree)) == degree + 1


def test_degree_5_is_better_than_degree_3() -> None:
    assert SIGMOID_MAX_ABS_ERROR[5] < SIGMOID_MAX_ABS_ERROR[3]


def test_invalid_degree() -> None:
    with pytest.raises(InvalidArgumentError, match="degree must be one of"):
        sigmoid_coefficients(4)
    with pytest.raises(InvalidArgumentError):
        sigmoid_coefficients("three")  # type: ignore[arg-type]
    with pytest.raises(InvalidArgumentError, match="polynomial degree"):
        polyval_depth(99)
    with pytest.raises(InvalidArgumentError):
        polyval_depth(None)  # type: ignore[arg-type]


def test_polyval_depth_is_nondecreasing() -> None:
    costs = [POLYVAL_DEPTH[d] for d in sorted(POLYVAL_DEPTH)]
    assert costs == sorted(costs)
    assert polyval_depth(3) == 2 and polyval_depth(5) == 3
