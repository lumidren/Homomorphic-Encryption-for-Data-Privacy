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
    rotations = entry["worst_normalized_error"]["rotations"]
    slotwise = entry["worst_normalized_error"]["slotwise"]
    assert set(rotations) == {str(level) for level in range(P.depth + 1)}
    # slot-wise operations have no rotation noise floor: strictly more precise when fresh
    assert slotwise["0"] < rotations["0"]
    assert entry["input_bound"] > 0 and entry["key_rings"] >= 4 and entry["trials_per_ring"] >= 1


def test_measured_bits_are_used_for_presets() -> None:
    rot, measured = precision_bits(P, 0)
    assert measured and 10 <= rot <= 25  # key-switching noise floor of rotations
    slot, measured = precision_bits(P, 0, "slotwise")
    assert measured and slot > rot
    assert precision_bits(P, 0, "rotations") == (rot, True)
    with pytest.raises(ValueError, match="precision_class"):
        precision_bits(P, 0, "other")


def test_heuristic_for_custom_params() -> None:
    custom = CKKSParams(8192, (60, 40, 40, 60), 39)
    bits, measured = precision_bits(custom, 0)
    assert not measured and bits == heuristic_precision_bits(custom, 0) == 39 - 13 - 2
    assert heuristic_precision_bits(custom, 2) == bits - 6
    assert heuristic_precision_bits(CKKSParams(8192, (30, 20, 20, 20, 30), 20), 3) == 1


def test_extrapolation_beyond_calibrated_levels(monkeypatch: pytest.MonkeyPatch) -> None:
    table = dict(load_table())
    table[table_key(P)] = {"worst_normalized_error": {"rotations": {"0": 2.0**-33}, "slotwise": {}}}
    monkeypatch.setattr("ciphercompute_core.precision._TABLE", table)
    assert precision_bits(P, 0) == (29, True)
    bits, measured = precision_bits(P, 2)
    assert (bits, measured) == (23, False)
    # a class with no measurements falls back to the heuristic
    assert precision_bits(P, 0, "slotwise") == (heuristic_precision_bits(P, 0), False)


def test_bits_never_increase_with_depth_and_gaps_are_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    # Level 1 is not measured; level 2 is *better* than level 0 (different operations land there).
    table = dict(load_table())
    table[table_key(P)] = {"worst_normalized_error": {"rotations": {"0": 2.0**-20, "2": 2.0**-24}, "slotwise": {}}}
    monkeypatch.setattr("ciphercompute_core.precision._TABLE", table)
    assert precision_bits(P, 0) == (16, True)
    assert precision_bits(P, 1) == (16, False)  # bounded by both neighbours, flagged as not measured
    assert precision_bits(P, 2) == (16, True)  # a depth-2 computation may still contain the level-0 sum


def test_measured_bits_are_monotone_for_every_preset() -> None:
    from ciphercompute_core.params import all_presets

    for _, params in all_presets():
        for cls in ("slotwise", "rotations"):
            bits = [precision_bits(params, level, cls)[0] for level in range(params.depth + 1)]
            assert bits == sorted(bits, reverse=True), (params, cls, bits)


def test_bits_from_worst_error() -> None:
    from ciphercompute_core.precision import bits_from_worst_error

    assert bits_from_worst_error(0.0) == 60
    assert bits_from_worst_error(2.0**-20) == 16
    assert bits_from_worst_error(3.0) == 0  # errors larger than the values: no usable bits, said plainly


def test_invalid_levels() -> None:
    with pytest.raises(ValueError):
        precision_bits(P, -1)
    with pytest.raises(ValueError):
        precision_bits(P, P.depth + 1)


def test_tolerance_scales_with_magnitude() -> None:
    bits, _ = precision_bits(P, 1)
    assert tolerance(P, 1, 0.001) == 2.0**-bits
    assert tolerance(P, 1, 1000.0) == 1000.0 * 2.0**-bits
    assert tolerance(P, 0, 1.0) <= tolerance(P, P.depth, 1.0)
    assert tolerance(P, 0, 1.0, "slotwise") < tolerance(P, 0, 1.0, "rotations")


def test_recommended_input_bound() -> None:
    assert recommended_input_bound(P, 1) == 2.0 ** (20 / 2 - 1)
    assert recommended_input_bound(P, 64) < recommended_input_bound(P, 8) < recommended_input_bound(P, 1)
    assert recommended_input_bound(standard_params(8192, 256), 32) < recommended_input_bound(P, 32)
    with pytest.raises(ValueError):
        recommended_input_bound(P, 0)
