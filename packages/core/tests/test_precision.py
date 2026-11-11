from __future__ import annotations

import pytest

from ciphercompute_core import all_presets, standard_params
from ciphercompute_core.params import CKKSParams
from ciphercompute_core.precision import (
    calibrated_params,
    heuristic_precision_bits,
    load_table,
    precision_bits,
    recommended_input_bound,
    table_key,
    tolerance,
)

P = standard_params(8192, 128)


def test_table_is_shipped_and_covers_every_8192_and_16384_preset() -> None:
    table = load_table()
    assert table, "precision_table.json is empty — run scripts/calibrate_precision.py"
    calibrated = calibrated_params()
    for profile, params in all_presets():
        if params.poly_modulus_degree in (8192, 16384):
            assert params in calibrated, (profile, params.describe())
    assert len(calibrated) >= 11
    # retired presets must not linger in the shipped table
    assert all(any(key == table_key(p) for _, p in all_presets()) for key in table)
    entry = table[table_key(P)]
    assert entry["worst_normalized_error"]["0"] < entry["worst_normalized_error"][str(P.depth)]
    assert entry["input_bound"] > 0 and entry["trials"] >= 1


def test_measured_bits_are_used_for_presets() -> None:
    bits, measured = precision_bits(P, 0)
    assert measured and bits >= 20
    bits1, _ = precision_bits(P, P.depth)
    assert bits1 < bits


def test_heuristic_for_custom_params() -> None:
    custom = CKKSParams(8192, (60, 40, 40, 60), 39)
    bits, measured = precision_bits(custom, 0)
    assert not measured and bits == heuristic_precision_bits(custom, 0) == 39 - 13 - 2
    assert heuristic_precision_bits(custom, 2) == bits - 6
    assert heuristic_precision_bits(CKKSParams(8192, (30, 20, 20, 20, 30), 20), 3) == 1


def test_extrapolation_beyond_calibrated_levels(monkeypatch: pytest.MonkeyPatch) -> None:
    table = dict(load_table())
    table[table_key(P)] = {"worst_normalized_error": {"0": 2.0**-33}}
    monkeypatch.setattr("ciphercompute_core.precision._TABLE", table)
    assert precision_bits(P, 0) == (30, True)
    bits, measured = precision_bits(P, 2)
    assert (bits, measured) == (24, False)


def test_bits_from_worst_error() -> None:
    from ciphercompute_core.precision import bits_from_worst_error

    assert bits_from_worst_error(0.0) == 60
    assert bits_from_worst_error(2.0**-20) == 17
    assert bits_from_worst_error(3.0) == 1  # errors larger than the values: no usable bits


def test_invalid_levels() -> None:
    with pytest.raises(ValueError):
        precision_bits(P, -1)
    with pytest.raises(ValueError):
        precision_bits(P, P.depth + 1)


def test_tolerance_scales_with_magnitude() -> None:
    bits, _ = precision_bits(P, 1)
    assert tolerance(P, 1, 0.001) == 2.0**-bits
    assert tolerance(P, 1, 1000.0) == 1000.0 * 2.0**-bits
    assert tolerance(P, 0, 1.0) < tolerance(P, 1, 1.0)


def test_recommended_input_bound() -> None:
    assert recommended_input_bound(P, 1) == 2.0 ** (20 / 2 - 1)
    assert recommended_input_bound(P, 64) < recommended_input_bound(P, 8) < recommended_input_bound(P, 1)
    assert recommended_input_bound(standard_params(8192, 256), 32) < recommended_input_bound(P, 32)
    with pytest.raises(ValueError):
        recommended_input_bound(P, 0)
