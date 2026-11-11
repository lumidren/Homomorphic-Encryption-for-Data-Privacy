"""Exact level accounting, measured two independent ways on every parameter set.

1. ``levels_consumed`` is read from the ciphertext's own modulus chain.
2. The ciphertext is probed by multiplying copies until SEAL refuses; the number of
   successful multiplications must equal ``levels_remaining``.

Any change in TenSEAL's internals (``polyval`` strategy, rescaling policy) shows up here as a
mismatch between the declared cost table and reality, and fails CI.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

import numpy as np
import pytest

from ciphercompute_core import EncryptedVector, KeyRing, PublicKeyBundle, apply_operation, plan
from ciphercompute_core.budget import DepthExhaustedError
from ciphercompute_core.ops import get_operation
from ciphercompute_core.params import CKKSParams
from ciphercompute_core.sigmoid import POLYVAL_DEPTH

Step = tuple[str, int, dict[str, Any]]  # (operation, number of fresh inputs for the first step, args)

CHAINS: list[tuple[str, list[Step]]] = [
    ("vector_add", [("vector_add", 2, {})]),
    ("scalar_multiply", [("scalar_multiply", 1, {"scalar": 1.5})]),
    ("elementwise_multiply", [("elementwise_multiply", 2, {})]),
    ("dot_product", [("dot_product", 2, {})]),
    ("sum", [("sum", 1, {})]),
    ("mean", [("mean", 1, {})]),
    ("variance", [("variance", 1, {"ddof": 1})]),
    ("weighted_average", [("weighted_average", 1, {"weights": [0.2, 0.3, 0.5, 1.0]})]),
    ("linear_regression", [("linear_regression", 1, {"weights": [0.1, -0.2, 0.3, 0.4], "intercept": 0.5})]),
    ("linear_regression[columns]", [("linear_regression", 3, {"weights": [0.1, 0.0, 0.3], "layout": "columns"})]),
    ("logistic_regression[deg3]", [("logistic_regression", 1, {"weights": [0.1, -0.2, 0.3, 0.4], "degree": 3})]),
    ("logistic_regression[deg5]", [("logistic_regression", 1, {"weights": [0.1, -0.2, 0.3, 0.4], "degree": 5})]),
    ("matvec_multiply", [("matvec_multiply", 1, {"matrix": [[1.0, 0.0, 0.0, 0.0], [0.5, 0.5, 0.5, 0.5]]})]),
    ("add->scalar->mean", [("vector_add", 2, {}), ("scalar_multiply", 1, {"scalar": 0.5}), ("mean", 1, {})]),
    ("mul->variance", [("elementwise_multiply", 2, {}), ("variance", 1, {})]),
    ("scalar x4", [("scalar_multiply", 1, {"scalar": 0.9})] * 4),
]


def probe_remaining_levels(ev: EncryptedVector) -> int:
    """Count how many plaintext multiplications the ciphertext can still absorb."""
    count = 0
    current = ev.raw().copy()
    while count <= ev.params.depth + 1:
        try:
            current = current * 1.0
        except Exception:  # SEAL: "scale out of bounds" / "end of modulus chain reached"
            return count
        count += 1
    raise AssertionError("ciphertext accepted more multiplications than the chain has levels")


def _fresh_inputs(bundle: PublicKeyBundle, k: int) -> list[EncryptedVector]:
    rng = np.random.default_rng(7)
    return [EncryptedVector.encrypt(bundle, rng.uniform(-1, 1, 4)) for _ in range(k)]


@pytest.mark.parametrize(("label", "steps"), CHAINS, ids=[c[0] for c in CHAINS])
def test_declared_depth_matches_reality(
    label: str, steps: Sequence[Step], params: CKKSParams, ring: KeyRing, bundle: PublicKeyBundle
) -> None:
    expected_cost = 0
    lengths = [4] * steps[0][1]
    for name, _, args in steps:
        spec = get_operation(name)
        expected_cost += spec.depth_cost(spec.normalize(lengths, args))
        lengths = [spec.output_length(lengths, spec.normalize(lengths, args))]

    plan_steps = [(name, args) for name, _, args in steps]
    if expected_cost > params.depth:
        with pytest.raises(DepthExhaustedError) as excinfo:
            plan(params, plan_steps, input_lengths=[4] * steps[0][1])
        assert excinfo.value.details["required_depth"] == expected_cost
        return
    planned = plan(params, plan_steps, input_lengths=[4] * steps[0][1])
    assert planned.required_depth == expected_cost

    current = _fresh_inputs(bundle, steps[0][1])
    for name, _, args in steps:
        out = apply_operation(name, bundle, current, args)
        current = [out]
    result = current[0]
    assert result.levels_consumed == expected_cost, label
    assert probe_remaining_levels(result) == result.levels_remaining == params.depth - expected_cost, label
    # and the result is still meaningful
    assert np.all(np.isfinite(ring.decrypt(result)))


def test_polyval_depth_table(params: CKKSParams, bundle: PublicKeyBundle) -> None:
    ev = EncryptedVector.encrypt(bundle, [0.1, 0.2, 0.3, 0.4])
    for degree, cost in POLYVAL_DEPTH.items():
        if cost > params.depth:
            continue
        coeffs = [0.5] + [0.01 * (i + 1) for i in range(degree)]
        out = ev.spawn(ev.raw().polyval(coeffs), 4)
        assert out.levels_consumed == cost, f"polyval degree {degree}"
        assert probe_remaining_levels(out) == params.depth - cost
