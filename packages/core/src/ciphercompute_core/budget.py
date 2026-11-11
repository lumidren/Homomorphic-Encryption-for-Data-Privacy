"""Multiplicative-depth budgeting: refuse jobs that cannot run, and say what would.

CKKS has no BFV-style "noise budget"; what a multiplication consumes is a *level* of the
modulus chain. ``plan()`` walks a chain of operations, sums their declared costs and raises
:class:`DepthExhaustedError` — naming the smallest standard parameter set that would carry the
job — before any ciphertext is touched. ``advise()`` is the same search exposed to the
dashboard's parameter advisor.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from .errors import DepthExhaustedError
from .params import CKKSParams, PolyModulusDegree, Profile, SecurityLevel, all_presets
from .precision import precision_bits, recommended_input_bound

Step = tuple[str, Mapping[str, Any]]


@dataclass(frozen=True, slots=True)
class DepthReport:
    """What the API and dashboard show as the "noise budget" of a job or ciphertext."""

    poly_modulus_degree: int
    security_level: int
    scale_bits: int
    levels_total: int
    levels_consumed: int
    levels_remaining: int
    precision_bits: int
    precision_measured: bool

    @classmethod
    def for_params(cls, params: CKKSParams, levels_consumed: int) -> DepthReport:
        bits, measured = precision_bits(params, levels_consumed)
        return cls(
            poly_modulus_degree=params.poly_modulus_degree,
            security_level=int(params.security_level),
            scale_bits=params.scale_bits,
            levels_total=params.depth,
            levels_consumed=levels_consumed,
            levels_remaining=params.depth - levels_consumed,
            precision_bits=bits,
            precision_measured=measured,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "poly_modulus_degree": self.poly_modulus_degree,
            "security_level": self.security_level,
            "scale_bits": self.scale_bits,
            "levels_total": self.levels_total,
            "levels_consumed": self.levels_consumed,
            "levels_remaining": self.levels_remaining,
            "precision_bits": self.precision_bits,
            "precision_measured": self.precision_measured,
        }


@dataclass(frozen=True, slots=True)
class PlannedStep:
    operation: str
    cost: int
    levels_consumed_after: int
    output_length: int


@dataclass(frozen=True, slots=True)
class Plan:
    params: CKKSParams
    steps: tuple[PlannedStep, ...]
    report: DepthReport
    input_bound: float

    @property
    def required_depth(self) -> int:
        return self.report.levels_consumed

    def to_dict(self) -> dict[str, Any]:
        return {
            "params": self.params.to_dict(),
            "steps": [
                {
                    "operation": s.operation,
                    "cost": s.cost,
                    "levels_consumed_after": s.levels_consumed_after,
                    "output_length": s.output_length,
                }
                for s in self.steps
            ],
            "report": self.report.to_dict(),
            "input_bound": self.input_bound,
        }


@dataclass(frozen=True, slots=True)
class Advice:
    params: CKKSParams
    profile: Profile
    required_depth: int
    report: DepthReport
    alternatives: tuple[tuple[Profile, CKKSParams], ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "params": self.params.to_dict(),
            "profile": self.profile,
            "required_depth": self.required_depth,
            "report": self.report.to_dict(),
            "alternatives": [{"profile": pr, "params": p.to_dict()} for pr, p in self.alternatives],
        }


def _walk(
    steps: Sequence[Step], input_lengths: Sequence[int], initial_levels_consumed: int
) -> tuple[list[PlannedStep], int]:
    """Sequentially apply the declared costs; the output of a step feeds the next as its input."""
    from .ops import get_operation

    if not steps:
        raise ValueError("a plan needs at least one step")
    planned: list[PlannedStep] = []
    level = int(initial_levels_consumed)
    lengths = [int(n) for n in input_lengths]
    for name, args in steps:
        spec = get_operation(name)
        normalized = spec.normalize(lengths, dict(args))
        cost = spec.depth_cost(normalized)
        level += cost
        out_len = spec.output_length(lengths, normalized)
        planned.append(PlannedStep(spec.name, cost, level, out_len))
        lengths = [out_len]
    return planned, level


def plan(
    params: CKKSParams,
    steps: Sequence[Step],
    *,
    input_lengths: Sequence[int],
    initial_levels_consumed: int = 0,
) -> Plan:
    """Validate a chain of operations against ``params`` and return its depth plan.

    Raises:
        DepthExhaustedError: if the chain needs more levels than the set provides. The error's
            ``details['suggested_params']`` names the smallest standard set that would do.
    """
    planned, required = _walk(steps, input_lengths, initial_levels_consumed)
    # [TM:D-2] Jobs that would run out of levels are refused here, before enqueueing.
    if required > params.depth:
        suggestion = _suggest(steps, input_lengths, params.security_level)
        if suggestion is None:
            hint = (
                "even the deepest standard set (N=32768, deep profile) cannot carry this chain; "
                "split the computation into shorter jobs"
            )
        else:
            profile, sp = suggestion
            hint = (
                f"use poly_modulus_degree={sp.poly_modulus_degree} with the '{profile}' profile "
                f"(primes {list(sp.coeff_mod_bit_sizes)}, scale 2^{sp.scale_bits}, {sp.depth} levels)"
            )
        raise DepthExhaustedError(
            f"this job needs {required} multiplicative level(s) but the parameter set "
            f"(N={params.poly_modulus_degree}, primes {list(params.coeff_mod_bit_sizes)}, "
            f"{int(params.security_level)}-bit) provides {params.depth}"
            + (f" and {initial_levels_consumed} are already consumed by the inputs" if initial_levels_consumed else "")
            + f"; {hint}",
            required_depth=required,
            available_depth=params.depth,
            initial_levels_consumed=int(initial_levels_consumed),
            params=params.to_dict(),
            suggested_params=None if suggestion is None else suggestion[1].to_dict(),
            suggested_profile=None if suggestion is None else suggestion[0],
        )
    report = DepthReport.for_params(params, required)
    bound = recommended_input_bound(params, max(int(n) for n in input_lengths))
    return Plan(params, tuple(planned), report, bound)


def _candidates(security_level: SecurityLevel) -> list[tuple[Profile, CKKSParams]]:
    return [(profile, p) for profile, p in all_presets() if p.security_level == security_level]


def _suggest(
    steps: Sequence[Step], input_lengths: Sequence[int], level: SecurityLevel
) -> tuple[Profile, CKKSParams] | None:
    _, required = _walk(steps, input_lengths, 0)
    for profile, p in _candidates(level):
        if p.depth >= required and max(int(n) for n in input_lengths) <= p.slots:
            return profile, p
    return None


def advise(
    steps: Sequence[Step],
    *,
    input_lengths: Sequence[int],
    security_level: int | SecurityLevel = SecurityLevel.BITS_128,
    min_poly_modulus_degree: int | PolyModulusDegree = PolyModulusDegree.N_8192,
    prefer: Profile = "balanced",
    min_precision_bits: int = 0,
) -> Advice:
    """Recommend the smallest standard parameter set that carries ``steps``.

    Candidates are ordered by ring dimension, then by the preferred profile; the first set with
    enough depth, enough slots and at least ``min_precision_bits`` of measured precision at the
    required depth wins, and every other viable set is returned as an alternative.
    """
    level = SecurityLevel(int(security_level))
    min_degree = int(min_poly_modulus_degree)
    _, required = _walk(steps, input_lengths, 0)
    longest = max(int(n) for n in input_lengths)
    order: tuple[Profile, Profile] = ("balanced", "deep") if prefer == "balanced" else ("deep", "balanced")
    viable: list[tuple[Profile, CKKSParams]] = []
    for degree in PolyModulusDegree:
        if int(degree) < min_degree:
            continue
        for profile in order:
            candidate = next(
                (p for pr, p in _candidates(level) if pr == profile and p.poly_modulus_degree == int(degree)),
                None,
            )
            if candidate is None:
                continue  # e.g. no deep profile exists at (8192, 256-bit)
            if candidate.depth >= required and longest <= candidate.slots:
                bits, _ = precision_bits(candidate, required)
                if bits >= min_precision_bits:
                    viable.append((profile, candidate))
    if not viable:
        raise DepthExhaustedError(
            f"no standard parameter set at {int(level)}-bit security provides the {required} "
            f"level(s) this chain needs for vectors of length {longest}"
            + (f" with at least {min_precision_bits} bits of precision" if min_precision_bits else "")
            + "; split the computation or relax the requirement",
            required_depth=required,
            available_depth=max(p.depth for _, p in _candidates(level)),
            suggested_params=None,
            suggested_profile=None,
        )
    profile, chosen = viable[0]
    return Advice(chosen, profile, required, DepthReport.for_params(chosen, required), tuple(viable[1:]))
