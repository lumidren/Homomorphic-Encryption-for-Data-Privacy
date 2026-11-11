"""Property-based proof that ``decrypt(op(enc(x))) ≈ op(x)`` for every operation and preset.

Tolerances come from the measured precision table (``ciphercompute_core.precision``). Inputs
are drawn within ``recommended_input_bound`` so intermediate values stay inside the integer
headroom of the parameter set. When a preset cannot carry an operation, the correct behaviour
is a *refusal* from ``budget.plan`` — asserted rather than skipped.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import numpy as np
import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from ciphercompute_core import EncryptedVector, KeyRing, PublicKeyBundle, apply_operation, plan
from ciphercompute_core.budget import DepthExhaustedError
from ciphercompute_core.ops import get_operation
from ciphercompute_core.params import CKKSParams
from ciphercompute_core.precision import recommended_input_bound, tolerance

MAX_EXAMPLES = int(os.environ.get("CC_PROPERTY_EXAMPLES", "10"))
MAX_LEN = 32

Draw = Callable[[st.SearchStrategy[Any]], Any]


def _floats(bound: float) -> st.SearchStrategy[float]:
    return st.floats(min_value=-bound, max_value=bound, allow_nan=False, allow_infinity=False, width=64)


def _vector(draw: Draw, n: int, bound: float) -> np.ndarray:
    return np.asarray(draw(st.lists(_floats(bound), min_size=n, max_size=n)), dtype=np.float64)


def _nonzero(values: list[float]) -> list[float]:
    if not any(v != 0.0 for v in values):
        values = list(values)
        values[0] = 1.0
    return values


def _bound(params: CKKSParams, n: int) -> float:
    return min(100.0, recommended_input_bound(params, n))


@dataclass(frozen=True)
class Case:
    name: str
    op: str
    build: Callable[[Draw, CKKSParams], tuple[list[np.ndarray], dict[str, Any]]]


def _vector_add(draw: Draw, params: CKKSParams):
    n = draw(st.integers(1, MAX_LEN))
    k = draw(st.integers(2, 3))
    b = _bound(params, n) / k
    return [_vector(draw, n, b) for _ in range(k)], {}


def _scalar_multiply(draw: Draw, params: CKKSParams):
    n = draw(st.integers(1, MAX_LEN))
    b = _bound(params, n)
    scalar = draw(_floats(b).filter(lambda s: s != 0.0))
    return [_vector(draw, n, b)], {"scalar": scalar}


def _elementwise_multiply(draw: Draw, params: CKKSParams):
    n = draw(st.integers(1, MAX_LEN))
    b = _bound(params, n)
    return [_vector(draw, n, b), _vector(draw, n, b)], {}


def _dot_product(draw: Draw, params: CKKSParams):
    return _elementwise_multiply(draw, params)


def _sum(draw: Draw, params: CKKSParams):
    n = draw(st.integers(1, MAX_LEN))
    return [_vector(draw, n, _bound(params, n))], {}


def _mean(draw: Draw, params: CKKSParams):
    xs, _ = _sum(draw, params)
    count = draw(st.one_of(st.none(), st.integers(1, len(xs[0]))))
    return xs, ({} if count is None else {"count": count})


def _variance(draw: Draw, params: CKKSParams):
    n = draw(st.integers(2, MAX_LEN))
    ddof = draw(st.sampled_from([0, 1]))
    return [_vector(draw, n, _bound(params, n))], {"ddof": ddof}


def _weighted_average(draw: Draw, params: CKKSParams):
    n = draw(st.integers(1, MAX_LEN))
    weights = draw(st.lists(st.floats(0.1, 1.0, allow_nan=False), min_size=n, max_size=n))
    return [_vector(draw, n, _bound(params, n))], {"weights": weights}


def _linear_sample(draw: Draw, params: CKKSParams):
    d = draw(st.integers(1, 16))
    b = _bound(params, d)
    weights = _nonzero(draw(st.lists(_floats(1.0), min_size=d, max_size=d)))
    return [_vector(draw, d, b)], {"weights": weights, "intercept": draw(_floats(1.0))}


def _linear_columns(draw: Draw, params: CKKSParams):
    d = draw(st.integers(1, 4))
    m = draw(st.integers(1, 16))
    b = _bound(params, m)
    weights = _nonzero(draw(st.lists(_floats(1.0), min_size=d, max_size=d)))
    return [_vector(draw, m, b) for _ in range(d)], {
        "weights": weights,
        "intercept": draw(_floats(1.0)),
        "layout": "columns",
    }


def _logistic(layout: str, degree: int):
    def build(draw: Draw, params: CKKSParams):
        d = draw(st.integers(1, 6))
        weights = _nonzero(draw(st.lists(_floats(1.0), min_size=d, max_size=d)))
        args = {"weights": weights, "intercept": draw(_floats(1.0)), "degree": degree, "layout": layout}
        if layout == "sample":
            return [_vector(draw, d, 1.0)], args
        m = draw(st.integers(1, 16))
        return [_vector(draw, m, 1.0) for _ in range(d)], args

    return build


def _matvec(draw: Draw, params: CKKSParams):
    n = draw(st.integers(1, 16))
    m = draw(st.integers(1, 8))
    b = _bound(params, n)
    matrix = [draw(st.lists(_floats(1.0), min_size=n, max_size=n)) for _ in range(m)]
    matrix[0] = _nonzero(matrix[0])
    return [_vector(draw, n, b)], {"matrix": matrix}


CASES = [
    Case("vector_add", "vector_add", _vector_add),
    Case("scalar_multiply", "scalar_multiply", _scalar_multiply),
    Case("elementwise_multiply", "elementwise_multiply", _elementwise_multiply),
    Case("dot_product", "dot_product", _dot_product),
    Case("sum", "sum", _sum),
    Case("mean", "mean", _mean),
    Case("variance", "variance", _variance),
    Case("weighted_average", "weighted_average", _weighted_average),
    Case("linear_regression[sample]", "linear_regression", _linear_sample),
    Case("linear_regression[columns]", "linear_regression", _linear_columns),
    Case("logistic_regression[sample,deg3]", "logistic_regression", _logistic("sample", 3)),
    Case("logistic_regression[columns,deg3]", "logistic_regression", _logistic("columns", 3)),
    Case("logistic_regression[sample,deg5]", "logistic_regression", _logistic("sample", 5)),
    Case("logistic_regression[columns,deg5]", "logistic_regression", _logistic("columns", 5)),
    Case("matvec_multiply", "matvec_multiply", _matvec),
]


def _magnitude(xs: list[np.ndarray], args: dict[str, Any], expected: np.ndarray) -> float:
    mags = [1.0, float(np.max(np.abs(expected)))] + [float(np.max(np.abs(x))) for x in xs]
    for key in ("scalar", "intercept"):
        if key in args:
            mags.append(abs(float(args[key])))
    for key in ("weights", "matrix"):
        if key in args:
            mags.append(float(np.max(np.abs(np.asarray(args[key])))))
    return max(mags)


@pytest.mark.parametrize("case", CASES, ids=[c.name for c in CASES])
@settings(
    max_examples=MAX_EXAMPLES,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large, HealthCheck.filter_too_much],
)
@given(data=st.data())
def test_decrypt_of_encrypted_op_matches_plaintext(
    case: Case, params: CKKSParams, ring: KeyRing, bundle: PublicKeyBundle, data: st.DataObject
) -> None:
    xs, args = case.build(data.draw, params)
    lengths = [len(x) for x in xs]
    spec = get_operation(case.op)
    normalized = spec.normalize(lengths, args)
    try:
        planned = plan(params, [(case.op, args)], input_lengths=lengths)
    except DepthExhaustedError as exc:
        # The parameter set is too shallow: refusing *before* execution is the specified behaviour.
        assert exc.details["required_depth"] == spec.depth_cost(normalized) > params.depth
        return
    assert planned.required_depth == spec.depth_cost(normalized)

    inputs = [EncryptedVector.encrypt(bundle, x) for x in xs]
    out = apply_operation(case.op, bundle, inputs, args)
    expected = spec.reference(xs, normalized)
    got = ring.decrypt(out)

    assert got.shape == expected.shape
    assert out.length == spec.output_length(lengths, normalized)
    assert out.levels_consumed == spec.depth_cost(normalized)

    magnitude = _magnitude(xs, args, expected)
    tol = tolerance(params, out.levels_consumed, magnitude)
    err = float(np.max(np.abs(got - expected)))
    assert err <= tol, (
        f"{case.name} on {params.describe()}: error {err:.3e} exceeds tolerance {tol:.3e} "
        f"(levels_consumed={out.levels_consumed}, magnitude={magnitude:.3g})"
    )
