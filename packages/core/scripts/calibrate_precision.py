"""Measure the worst normalised CKKS error per parameter set and level, and write the table.

Usage::

    python scripts/calibrate_precision.py [--heavy] [--trials N] [--out path]

For each preset (N=32768 only with ``--heavy``) the script generates a key ring, runs every
registered operation on random inputs drawn within ``recommended_input_bound``, and records
``max|got - expected| / M`` grouped by the number of levels the output consumed (see
``ciphercompute_core.precision`` for the error model). The stored precision is
``floor(-log2(worst)) - CALIBRATION_MARGIN_BITS``.
"""

from __future__ import annotations

import argparse
import json
import math
import sys
import time
from pathlib import Path

import numpy as np

from ciphercompute_core import EncryptedVector, KeyRing, all_presets, apply_operation
from ciphercompute_core.budget import plan
from ciphercompute_core.errors import DepthExhaustedError
from ciphercompute_core.ops import OPERATIONS
from ciphercompute_core.precision import CALIBRATION_MARGIN_BITS, recommended_input_bound, table_key
from ciphercompute_core.sigmoid import SUPPORTED_DEGREES

LENGTH = 32


def cases(rng: np.random.Generator, bound: float) -> list[tuple[str, list[np.ndarray], dict]]:
    """One random instance of every operation (and variant) within the safe input bound."""
    u = lambda n, b=bound: rng.uniform(-b, b, n)
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


def calibrate(params, trials: int, rng: np.random.Generator) -> dict:
    t0 = time.time()
    ring = KeyRing.generate(params)
    bundle = ring.public_bundle()
    bound = min(100.0, recommended_input_bound(params, LENGTH))
    worst: dict[int, float] = {}
    skipped: set[str] = set()
    for _ in range(trials):
        for name, xs, args in cases(rng, bound):
            try:
                plan(params, [(name, args)], input_lengths=[len(x) for x in xs])
            except DepthExhaustedError:
                skipped.add(f"{name}:{args.get('degree', '')}")
                continue
            inputs = [EncryptedVector.encrypt(bundle, x) for x in xs]
            out = apply_operation(name, bundle, inputs, args)
            got = ring.decrypt(out)
            spec = OPERATIONS[name]
            expected = spec.reference(xs, spec.normalize([len(x) for x in xs], args))
            arg_mag = max(
                [abs(float(v)) for v in np.ravel([args.get("scalar", 0.0)])]
                + [float(np.max(np.abs(args[k]))) for k in ("weights", "matrix") if k in args]
                + [0.0]
            )
            magnitude = max(1.0, max(float(np.max(np.abs(x))) for x in xs), float(np.max(np.abs(expected))), arg_mag)
            err = float(np.max(np.abs(got - expected))) / magnitude
            level = out.levels_consumed
            worst[level] = max(worst.get(level, 0.0), err)
    levels = {
        str(k): int(math.floor(-math.log2(v)) - CALIBRATION_MARGIN_BITS) if v > 0 else 60
        for k, v in sorted(worst.items())
    }
    entry = {
        "poly_modulus_degree": params.poly_modulus_degree,
        "security_level": int(params.security_level),
        "coeff_mod_bit_sizes": list(params.coeff_mod_bit_sizes),
        "scale_bits": params.scale_bits,
        "input_bound": bound,
        "vector_length": LENGTH,
        "trials": trials,
        "worst_normalized_error": {str(k): v for k, v in sorted(worst.items())},
        "levels": levels,
        "skipped_as_too_deep": sorted(skipped),
        "public_bundle_bytes": bundle.size_bytes,
        "seconds": round(time.time() - t0, 1),
    }
    print(f"{params.describe():70s} levels={levels} skipped={sorted(skipped)} ({entry['seconds']}s)", flush=True)
    return entry


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--heavy", action="store_true", help="include N=32768 (several GB of RAM, minutes per set)")
    ap.add_argument("--trials", type=int, default=5)
    ap.add_argument(
        "--out",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "src" / "ciphercompute_core" / "data" / "precision_table.json",
    )
    ap.add_argument(
        "--only", type=str, default=None, help="comma-separated substrings; only matching preset keys are re-measured"
    )
    ns = ap.parse_args()
    rng = np.random.default_rng(2026)
    table: dict = {}
    if ns.out.exists():
        table = json.loads(ns.out.read_text(encoding="utf-8"))
    current_keys = {table_key(p) for _, p in all_presets()}
    table = {k: v for k, v in table.items() if k in current_keys}  # drop retired presets
    for profile, params in all_presets():
        if params.poly_modulus_degree == 32768 and not ns.heavy:
            continue
        key = table_key(params)
        if ns.only and not any(fragment in key for fragment in ns.only.split(",")):
            continue
        entry = calibrate(params, ns.trials, rng)
        entry["profile"] = profile
        table[key] = entry
        ns.out.write_text(json.dumps(table, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {ns.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
