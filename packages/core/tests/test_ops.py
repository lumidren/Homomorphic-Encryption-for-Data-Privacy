"""Argument validation and execution semantics of the operation registry."""

from __future__ import annotations

import numpy as np
import pytest

from ciphercompute_core import EncryptedVector, KeyRing, PublicKeyBundle, apply_operation
from ciphercompute_core.errors import InvalidArgumentError, KeyMismatchError, UnsupportedOperationError
from ciphercompute_core.ops import OPERATIONS, get_operation, list_operations


def test_registry_contents() -> None:
    names = [s.name for s in list_operations()]
    assert names == sorted(OPERATIONS)
    assert set(names) == {
        "vector_add",
        "scalar_multiply",
        "elementwise_multiply",
        "dot_product",
        "sum",
        "mean",
        "variance",
        "weighted_average",
        "linear_regression",
        "logistic_regression",
        "matvec_multiply",
    }
    described = get_operation("mean").describe()
    assert described["name"] == "mean" and described["reveals"] == ["count"] and described["max_inputs"] == 1
    with pytest.raises(UnsupportedOperationError, match="unknown operation 'nope'") as excinfo:
        get_operation("nope")
    assert excinfo.value.details["operation"] == "nope"


INVALID = [
    ("vector_add", [3, 4], {}, "equal length"),
    ("vector_add", [3, 3], {"x": 1}, "does not accept arguments"),
    ("scalar_multiply", [3], {}, "requires a 'scalar'"),
    ("scalar_multiply", [3], {"scalar": 0}, "non-zero"),
    ("scalar_multiply", [3], {"scalar": "a"}, "must be a number"),
    ("scalar_multiply", [3], {"scalar": float("inf")}, "must be finite"),
    ("elementwise_multiply", [2, 3], {}, "equal length"),
    ("dot_product", [2, 3], {}, "equal length"),
    ("sum", [3], {"count": 3}, "does not accept"),
    ("mean", [3], {"count": 0}, "count must be"),
    ("mean", [3], {"count": 4}, "count must be"),
    ("mean", [3], {"count": True}, "count must be"),
    ("mean", [3], {"count": "2"}, "count must be"),
    ("variance", [3], {"ddof": 2}, "ddof must be"),
    ("variance", [3], {"ddof": True}, "ddof must be"),
    ("variance", [3], {"count": 1, "ddof": 1}, "at least two"),
    ("weighted_average", [3], {}, "requires a 'weights'"),
    ("weighted_average", [3], {"weights": [1.0, -1.0, 0.0]}, "sum to zero"),
    ("weighted_average", [3], {"weights": [1.0, 2.0]}, "has 2 entries but the input vector has 3"),
    ("weighted_average", [3], {"weights": "abc"}, "list of numbers"),
    ("weighted_average", [3], {"weights": [[1.0, 2.0, 3.0]]}, "1-D"),
    ("weighted_average", [3], {"weights": []}, "non-empty"),
    ("weighted_average", [3], {"weights": [1.0, float("nan"), 1.0]}, "finite"),
    ("linear_regression", [3], {}, "requires a 'weights'"),
    ("linear_regression", [3], {"weights": [1.0, 1.0, 1.0], "layout": "rows"}, "layout must be"),
    ("linear_regression", [3, 3], {"weights": [1.0, 1.0, 1.0]}, "exactly one input"),
    ("linear_regression", [3, 4], {"weights": [1.0, 1.0], "layout": "columns"}, "equal length"),
    ("linear_regression", [3, 3], {"weights": [1.0, 1.0, 1.0], "layout": "columns"}, "has 3 entries but"),
    ("linear_regression", [3], {"weights": [0.0, 0.0, 0.0]}, "non-zero entry"),
    ("linear_regression", [3], {"weights": [1.0, 0.0, 0.0], "intercept": "x"}, "intercept must be a number"),
    ("logistic_regression", [3], {"weights": [1.0, 0.0, 0.0], "degree": 4}, "degree must be one of"),
    ("logistic_regression", [3], {"weights": [1.0, 0.0, 0.0], "degree": True}, "degree must be one of"),
    ("matvec_multiply", [3], {}, "requires a 'matrix'"),
    ("matvec_multiply", [3], {"matrix": [[1.0, 2.0]]}, "has 2 columns but the input vector has 3"),
    ("matvec_multiply", [3], {"matrix": [[0.0, 0.0, 0.0]]}, "non-zero entry"),
    ("matvec_multiply", [3], {"matrix": [1.0, 2.0, 3.0]}, "2-D matrix"),
    ("matvec_multiply", [3], {"matrix": "zzz"}, "2-D list of numbers"),
    ("matvec_multiply", [3], {"matrix": [[1.0, float("nan"), 0.0]]}, "finite"),
    ("matvec_multiply", [3], {"matrix": [[]]}, "2-D"),
]


@pytest.mark.parametrize(("name", "lengths", "args", "fragment"), INVALID, ids=[f"{c[0]}:{c[3][:20]}" for c in INVALID])
def test_invalid_arguments(name: str, lengths: list[int], args: dict, fragment: str) -> None:
    with pytest.raises(InvalidArgumentError, match=fragment) as excinfo:
        get_operation(name).normalize(lengths, args)
    assert excinfo.value.code == "invalid_argument"


def test_normalized_defaults() -> None:
    assert get_operation("mean").normalize([5], {}) == {"count": 5}
    assert get_operation("variance").normalize([5], {}) == {"count": 5, "ddof": 0}
    lin = get_operation("linear_regression").normalize([2], {"weights": [1, 2]})
    assert lin == {"weights": [1.0, 2.0], "intercept": 0.0, "layout": "sample"}
    log = get_operation("logistic_regression").normalize([2, 2], {"weights": [1, 0], "layout": "columns"})
    assert log["degree"] == 3 and log["layout"] == "columns"
    assert get_operation("logistic_regression").output_length([7, 7], log) == 7
    assert get_operation("matvec_multiply").output_length([2], {"matrix": [[1.0, 0.0], [0.0, 1.0], [1.0, 1.0]]}) == 3


def test_input_count_bounds(small_bundle: PublicKeyBundle) -> None:
    x = EncryptedVector.encrypt(small_bundle, [1.0, 2.0])
    with pytest.raises(InvalidArgumentError, match="takes exactly 1 input"):
        apply_operation("sum", small_bundle, [x, x])
    with pytest.raises(InvalidArgumentError, match="between 2 and any number of"):
        apply_operation("vector_add", small_bundle, [x])
    with pytest.raises(InvalidArgumentError, match="takes exactly 2 input"):
        apply_operation("dot_product", small_bundle, [x, x, x])


def test_ring_mismatch(small_ring: KeyRing, small_bundle: PublicKeyBundle) -> None:
    other = KeyRing.generate(small_ring.params).public_bundle()
    foreign = EncryptedVector.encrypt(other, [1.0])
    with pytest.raises(KeyMismatchError, match="different key ring"):
        apply_operation("sum", small_bundle, [foreign])


def test_mixed_level_inputs_are_not_mutated(small_ring: KeyRing, small_bundle: PublicKeyBundle) -> None:
    fresh = EncryptedVector.encrypt(small_bundle, [1.0, 2.0, 3.0])
    deeper = apply_operation(
        "scalar_multiply", small_bundle, [EncryptedVector.encrypt(small_bundle, [1.0, 1.0, 1.0])], {"scalar": 2.0}
    )
    assert (fresh.levels_consumed, deeper.levels_consumed) == (0, 1)
    out = apply_operation("vector_add", small_bundle, [fresh, deeper])
    assert out.levels_consumed == 1
    assert fresh.levels_consumed == 0, "the higher-level operand must not be switched down in place"
    assert small_ring.decrypt(out) == pytest.approx([3.0, 4.0, 5.0], abs=1e-5)


def test_regression_variants_execute(small_ring: KeyRing, small_bundle: PublicKeyBundle) -> None:
    cols = [EncryptedVector.encrypt(small_bundle, v) for v in ([1.0, 2.0], [3.0, 4.0], [5.0, 6.0])]
    # a zero weight is skipped, a non-zero intercept is added
    out = apply_operation(
        "linear_regression", small_bundle, cols, {"weights": [0.5, 0.0, 2.0], "intercept": 1.0, "layout": "columns"}
    )
    assert out.length == 2 and small_ring.decrypt(out) == pytest.approx([11.5, 14.0], abs=1e-5)
    # intercept of zero takes the no-add path
    out = apply_operation("linear_regression", small_bundle, cols[:1], {"weights": [3.0], "layout": "columns"})
    assert small_ring.decrypt(out) == pytest.approx([3.0, 6.0], abs=1e-5)
    sample = EncryptedVector.encrypt(small_bundle, [0.5, -0.5])
    out = apply_operation("linear_regression", small_bundle, [sample], {"weights": [1.0, 1.0], "intercept": 0.25})
    assert out.length == 1 and small_ring.decrypt(out) == pytest.approx([0.25], abs=1e-5)


def test_matvec_rows_exceed_slots(small_bundle: PublicKeyBundle) -> None:
    x = EncryptedVector.encrypt(small_bundle, [1.0])
    with pytest.raises(InvalidArgumentError, match="rows but the parameter set offers 4096 slots"):
        apply_operation("matvec_multiply", small_bundle, [x], {"matrix": [[1.0]] * 4097})


def test_variance_matches_numpy(small_ring: KeyRing, small_bundle: PublicKeyBundle) -> None:
    values = np.array([2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0])
    x = EncryptedVector.encrypt(small_bundle, values)
    pop = small_ring.decrypt(apply_operation("variance", small_bundle, [x], {}))[0]
    smp = small_ring.decrypt(apply_operation("variance", small_bundle, [x], {"ddof": 1}))[0]
    assert pop == pytest.approx(values.var(), abs=1e-4)
    assert smp == pytest.approx(values.var(ddof=1), abs=1e-4)
    # padded vector with explicit count
    padded = EncryptedVector.encrypt(small_bundle, values, pad_to=16)
    assert small_ring.decrypt(apply_operation("mean", small_bundle, [padded], {"count": 8}))[0] == pytest.approx(
        values.mean(), abs=1e-5
    )
    assert small_ring.decrypt(apply_operation("variance", small_bundle, [padded], {"count": 8}))[0] == pytest.approx(
        values.var(), abs=1e-4
    )


def test_precision_classes() -> None:
    rotating = {"dot_product", "sum", "mean", "variance", "weighted_average", "matvec_multiply"}
    for spec in list_operations():
        sample = spec.precision_class({"layout": "sample"})
        assert sample == (
            "rotations" if spec.name in rotating | {"linear_regression", "logistic_regression"} else "slotwise"
        ), spec.name
        assert spec.describe()["precision_class"] == sample
    # batched (column-layout) regression never rotates
    assert get_operation("linear_regression").precision_class({"layout": "columns"}) == "slotwise"
    assert get_operation("logistic_regression").precision_class({"layout": "columns"}) == "slotwise"


def test_matvec_entries_below_resolution(small_ring: KeyRing, small_bundle: PublicKeyBundle) -> None:
    """Tiny entries used to make SEAL fail with 'result ciphertext is transparent'."""
    x = EncryptedVector.encrypt(small_bundle, [1.0, 2.0, 3.0])
    out = apply_operation(
        "matvec_multiply", small_bundle, [x], {"matrix": [[1e-300, 0.0, 2.0], [1e-300, 1e-300, 1e-300]]}
    )
    assert out.levels_consumed == 1
    assert small_ring.decrypt(out) == pytest.approx([6.0, 0.0], abs=1e-4)
    zero = apply_operation("matvec_multiply", small_bundle, [x], {"matrix": [[1e-300, 1e-300, 1e-300]]})
    assert zero.levels_consumed == 1 and zero.length == 1
    assert small_ring.decrypt(zero) == pytest.approx([0.0], abs=1e-4)
