"""Depth planning and the parameter advisor (pure logic, no key generation)."""

from __future__ import annotations

import pytest

from ciphercompute_core import advise, plan, standard_params
from ciphercompute_core.budget import DepthReport
from ciphercompute_core.errors import DepthExhaustedError, InvalidArgumentError, UnsupportedOperationError

P8192 = standard_params(8192, 128)
P8192_DEEP = standard_params(8192, 128, "deep")
P16384 = standard_params(16384, 128)


def test_plan_single_step() -> None:
    p = plan(P8192, [("mean", {})], input_lengths=[16])
    assert p.required_depth == 1
    assert p.report.levels_total == 2 and p.report.levels_remaining == 1
    assert p.steps[0].operation == "mean" and p.steps[0].output_length == 1
    assert p.input_bound > 0
    d = p.to_dict()
    assert d["report"]["levels_consumed"] == 1 and d["steps"][0]["cost"] == 1


def test_plan_chain_feeds_outputs_forward() -> None:
    p = plan(P8192, [("elementwise_multiply", {}), ("sum", {})], input_lengths=[8, 8])
    assert [s.cost for s in p.steps] == [1, 0]
    assert [s.output_length for s in p.steps] == [8, 1]
    assert p.required_depth == 1


def test_plan_refuses_and_advises() -> None:
    with pytest.raises(DepthExhaustedError) as excinfo:
        plan(P8192, [("logistic_regression", {"weights": [1.0, 2.0], "degree": 3})], input_lengths=[2])
    err = excinfo.value
    assert err.code == "depth_exhausted"
    assert err.details["required_depth"] == 3 and err.details["available_depth"] == 2
    assert err.details["suggested_params"] == P8192_DEEP.to_dict()
    assert err.details["suggested_profile"] == "deep"
    assert "needs 3 multiplicative level(s)" in str(err)
    assert "poly_modulus_degree=8192 with the 'deep' profile" in str(err)


def test_plan_accounts_for_already_consumed_levels() -> None:
    assert plan(P8192, [("mean", {})], input_lengths=[4], initial_levels_consumed=1).report.levels_remaining == 0
    with pytest.raises(DepthExhaustedError, match="already consumed"):
        plan(P8192, [("mean", {})], input_lengths=[4], initial_levels_consumed=2)


def test_plan_nothing_fits() -> None:
    chain = [("scalar_multiply", {"scalar": 2.0})] * 40
    with pytest.raises(DepthExhaustedError, match="split the computation") as excinfo:
        plan(P8192, chain, input_lengths=[4])
    assert excinfo.value.details["suggested_params"] is None


def test_plan_validates_steps() -> None:
    with pytest.raises(ValueError, match="at least one step"):
        plan(P8192, [], input_lengths=[4])
    with pytest.raises(UnsupportedOperationError):
        plan(P8192, [("nope", {})], input_lengths=[4])
    with pytest.raises(InvalidArgumentError):
        plan(P8192, [("scalar_multiply", {})], input_lengths=[4])


def test_advise_picks_smallest_sufficient_set() -> None:
    a = advise([("logistic_regression", {"weights": [1.0], "degree": 5})], input_lengths=[1])
    assert a.params == P8192_DEEP and a.profile == "deep" and a.required_depth == 4
    assert a.report.levels_remaining == 0
    alternatives = [p for _, p in a.alternatives]
    assert P16384 in alternatives and standard_params(16384, 128, "deep") in alternatives
    assert a.to_dict()["profile"] == "deep"


def test_advise_prefers_balanced_when_it_fits() -> None:
    a = advise([("mean", {})], input_lengths=[4])
    assert a.params == P8192 and a.profile == "balanced"
    a = advise([("mean", {})], input_lengths=[4], prefer="deep")
    assert a.params == P8192_DEEP


def test_advise_respects_minimum_degree_security_and_slots() -> None:
    a = advise([("sum", {})], input_lengths=[4], min_poly_modulus_degree=16384)
    assert a.params == P16384
    a = advise([("sum", {})], input_lengths=[4], security_level=256)
    assert a.params == standard_params(8192, 256)
    a = advise([("sum", {})], input_lengths=[5000])
    assert a.params.poly_modulus_degree == 16384


def test_advise_can_require_precision() -> None:
    steps = [("logistic_regression", {"weights": [1.0], "degree": 3})]
    shallow = advise(steps, input_lengths=[1], security_level=192)
    assert shallow.params == standard_params(8192, 192, "deep")
    precise = advise(steps, input_lengths=[1], security_level=192, min_precision_bits=6)
    assert precise.params == standard_params(16384, 192)
    assert precise.report.precision_bits >= 6
    assert precise.report.precision_class == "rotations"
    with pytest.raises(DepthExhaustedError, match="with at least 60 bits of precision"):
        advise(steps, input_lengths=[1], min_precision_bits=60)


def test_advise_skips_absent_profiles() -> None:
    # (8192, 256) has no deep profile; the advisor must step over it, not crash
    a = advise([("variance", {})], input_lengths=[4], security_level=256, prefer="deep")
    assert a.params.poly_modulus_degree == 8192 and a.profile == "balanced"


def test_advise_nothing_fits() -> None:
    with pytest.raises(DepthExhaustedError, match="no standard parameter set") as excinfo:
        advise([("scalar_multiply", {"scalar": 2.0})] * 40, input_lengths=[4])
    assert excinfo.value.details["suggested_params"] is None


def test_depth_report_dict() -> None:
    r = DepthReport.for_params(P8192, 2)
    assert r.levels_remaining == 0
    assert set(r.to_dict()) == {
        "poly_modulus_degree",
        "security_level",
        "scale_bits",
        "levels_total",
        "levels_consumed",
        "levels_remaining",
        "precision_bits",
        "precision_measured",
        "precision_class",
    }
    assert DepthReport.for_params(P8192, 1, "slotwise").precision_class == "slotwise"
