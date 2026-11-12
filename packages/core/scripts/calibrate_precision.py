"""Measure the worst normalised CKKS error per parameter set and level, and write the table.

Usage::

    python scripts/calibrate_precision.py [--heavy] [--trials N] [--out path]

For each preset (N=32768 only with ``--heavy``) the script generates several key rings, runs
every registered operation on random, zero and constant inputs within
``recommended_input_bound``, and records ``max|got - expected| / M`` per precision class
(``slotwise`` / ``rotations``) and per number of levels consumed (see
``ciphercompute_core.precision`` for the error model).

Each preset is measured in its own subprocess: SEAL's memory pool never returns memory to the
operating system, so measuring many large rings in one process eventually fails to allocate.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

import numpy as np

from ciphercompute_core import EncryptedVector, KeyRing, all_presets, apply_operation
from ciphercompute_core.budget import plan
from ciphercompute_core.errors import DepthExhaustedError
from ciphercompute_core.ops import OPERATIONS
from ciphercompute_core.precision import (
    PRECISION_CLASSES,
    bits_from_worst_error,
    magnitude_class,
    recommended_input_bound,
    table_key,
)
from ciphercompute_core.sigmoid import SUPPORTED_DEGREES

LENGTH = 32


def cases(rng: np.random.Generator, bound: float, pattern: str = "uniform") -> list[tuple[str, list[np.ndarray], dict]]:
    """One instance of every operation (and variant) within the safe input bound.

    ``pattern`` shapes the encrypted inputs: random values, all zeros, or a constant. Zeros and
    constants expose the absolute noise floor that random data averages away.
    """

    def u(n: int, b: float = bound) -> np.ndarray:
        if pattern == "zeros":
            return np.zeros(n)
        if pattern == "constant":
            return np.full(n, b)
        return rng.uniform(-b, b, n)

    out: list[tuple[str, list[np.ndarray], dict]] = [
        ("vector_add", [u(LENGTH), u(LENGTH), u(LENGTH)], {}),
        ("scalar_multiply", [u(LENGTH)], {"scalar": float(rng.uniform(-bound, bound))}),
        ("elementwise_multiply", [u(LENGTH), u(LENGTH)], {}),
        ("dot_product", [u(LENGTH), u(LENGTH)], {}),
        ("sum", [u(LENGTH)], {}),
        ("mean", [u(LENGTH)], {}),
        ("variance", [u(LENGTH)], {"ddof": 0}),
        ("variance", [u(LENGTH)], {"ddof": 1}),
        ("weighted_average", [u(LENGTH)], {"weights": rng.uniform(0.1, 1.0, LENGTH).tolist()}),
        ("linear_regression", [u(8)], {"weights": rng.uniform(-1, 1, 8).tolist(), "intercept": 0.3}),
        (
            "linear_regression",
            [u(LENGTH) for _ in range(4)],
            {"weights": rng.uniform(-1, 1, 4).tolist(), "intercept": -0.2, "layout": "columns"},
        ),
        ("matvec_multiply", [u(LENGTH)], {"matrix": rng.uniform(-1, 1, (6, LENGTH)).tolist()}),
    ]
    for degree in SUPPORTED_DEGREES:
        feats = [rng.uniform(-1, 1, 6) for _ in range(1)]
        out.append(
            (
                "logistic_regression",
                feats,
                {"weights": rng.uniform(-1, 1, 6).tolist(), "intercept": 0.1, "degree": degree},
            )
        )
        cols = [rng.uniform(-1, 1, LENGTH) for _ in range(5)]
        out.append(
            (
                "logistic_regression",
                cols,
                {"weights": rng.uniform(-1, 1, 5).tolist(), "intercept": 0.0, "layout": "columns", "degree": degree},
            )
        )
    return out


def default_rings(params) -> int:
    """Key rings to sample. The noise floor varies 10-100x between fresh key rings with identical
    parameters, so one ring is never enough; larger rings are expensive, so they get fewer."""
    return {8192: 12, 16384: 4}.get(params.poly_modulus_degree, 2)


def measure_ring(
    params,
    ring: KeyRing,
    trials: int,
    rng: np.random.Generator,
    bound: float,
    worst: dict[str, dict[int, float]],
    skipped: set[str],
) -> int:
    """Run every operation on one key ring; fold worst errors into ``worst[class][level]``.

    Returns the size of the ring's public bundle.
    """
    bundle = ring.public_bundle()
    # Large inputs measure relative error; tiny, zero and constant inputs measure the absolute noise
    # floor (rotations, key switching), which does not shrink with the data.
    settings = [(bound, "uniform"), (1.0, "uniform"), (1e-3, "uniform"), (bound, "zeros"), (1.0, "constant")]
    for trial in range(trials):
        magnitude, pattern = settings[trial % len(settings)]
        for name, xs, args in cases(rng, magnitude, pattern):
            try:
                plan(params, [(name, args)], input_lengths=[len(x) for x in xs])
            except DepthExhaustedError:
                skipped.add(f"{name}:{args.get('degree', '')}")
                continue
            inputs = [EncryptedVector.encrypt(bundle, x) for x in xs]
            out = apply_operation(name, bundle, inputs, args)
            spec = OPERATIONS[name]
            normalized = spec.normalize([len(x) for x in xs], args)
            expected = spec.reference(xs, normalized)
            err = float(np.max(np.abs(ring.decrypt(out) - expected))) / magnitude_class(xs, args, expected)
            per_level = worst[spec.precision_class(normalized)]
            per_level[out.levels_consumed] = max(per_level.get(out.levels_consumed, 0.0), err)
    return bundle.size_bytes


def calibrate(params, trials: int, rng: np.random.Generator, rings: int | None = None) -> dict:
    t0 = time.time()
    rings = rings or default_rings(params)
    bound = min(100.0, recommended_input_bound(params, LENGTH))
    worst: dict[str, dict[int, float]] = {c: {} for c in PRECISION_CLASSES}
    skipped: set[str] = set()
    bundle_bytes = 0
    for _ in range(rings):
        bundle_bytes = measure_ring(params, KeyRing.generate(params), trials, rng, bound, worst, skipped)
    bits = {c: {str(k): bits_from_worst_error(v) for k, v in sorted(levels.items())} for c, levels in worst.items()}
    entry = {
        "poly_modulus_degree": params.poly_modulus_degree,
        "security_level": int(params.security_level),
        "coeff_mod_bit_sizes": list(params.coeff_mod_bit_sizes),
        "scale_bits": params.scale_bits,
        "input_bound": bound,
        "vector_length": LENGTH,
        "key_rings": rings,
        "trials_per_ring": trials,
        "worst_normalized_error": {c: {str(k): v for k, v in sorted(levels.items())} for c, levels in worst.items()},
        "precision_bits": bits,
        "skipped_as_too_deep": sorted(skipped),
        "public_bundle_bytes": bundle_bytes,
        "seconds": round(time.time() - t0, 1),
    }
    print(f"{params.describe():70s} rings={rings} bits={bits} ({entry['seconds']}s)", file=sys.stderr, flush=True)
    return entry


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--heavy", action="store_true", help="include N=32768 (several GB of RAM, minutes per set)")
    ap.add_argument("--trials", type=int, default=10, help="trials per key ring")
    ap.add_argument("--rings", type=int, default=None, help="key rings per preset (default: 12/4/2 by ring size)")
    ap.add_argument(
        "--out",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "src" / "ciphercompute_core" / "data" / "precision_table.json",
    )
    ap.add_argument(
        "--only", type=str, default=None, help="comma-separated substrings; only matching preset keys are re-measured"
    )
    ap.add_argument("--single", type=str, default=None, help=argparse.SUPPRESS)  # internal: one preset, JSON on stdout
    ns = ap.parse_args()

    presets = {table_key(p): (profile, p) for profile, p in all_presets()}
    if ns.single:
        profile, params = presets[ns.single]
        entry = calibrate(params, ns.trials, np.random.default_rng(abs(hash(ns.single)) % 2**32), ns.rings)
        entry["profile"] = profile
        print(json.dumps(entry))
        return 0

    table: dict = json.loads(ns.out.read_text(encoding="utf-8")) if ns.out.exists() else {}
    table = {k: v for k, v in table.items() if k in presets}  # drop retired presets
    for key, (_, params) in presets.items():
        if params.poly_modulus_degree == 32768 and not ns.heavy:
            continue
        if ns.only and not any(fragment in key for fragment in ns.only.split(",")):
            continue
        argv = [sys.executable, __file__, "--single", key, "--trials", str(ns.trials)]
        if ns.rings:
            argv += ["--rings", str(ns.rings)]
        result = subprocess.run(argv, capture_output=True, text=True, check=False)
        sys.stderr.write(result.stderr)
        if result.returncode != 0:
            print(f"calibration of {key} failed (exit {result.returncode})", file=sys.stderr)
            return 1
        table[key] = json.loads(result.stdout.strip().splitlines()[-1])
        ns.out.write_text(json.dumps(table, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {ns.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
