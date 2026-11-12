#!/usr/bin/env python3
"""Measure CKKS cost and precision for the standard parameter sets.

For each preset: key generation time, public-bundle and ciphertext sizes, encryption and
decryption time for a full vector of slots, latency of every operation (median of ``--repeat``
runs), and the measured precision bits for that operation's class from the calibration table.
Each preset runs in its own process (SEAL's memory pool never shrinks). Results go to
``benchmarks/results/results.json`` and a Markdown table the whitepaper includes.

    python benchmarks/benchmark.py                 # N=8192 and N=16384
    python benchmarks/benchmark.py --heavy         # adds N=32768 (several GB of RAM)
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import statistics
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import numpy as np
import tenseal

from ciphercompute_core import EncryptedVector, KeyRing, all_presets, apply_operation, plan
from ciphercompute_core.errors import DepthExhaustedError
from ciphercompute_core.ops import get_operation
from ciphercompute_core.params import CKKSParams
from ciphercompute_core.precision import precision_bits

ROOT = Path(__file__).resolve().parent


def machine() -> dict[str, Any]:
    info: dict[str, Any] = {
        "python": platform.python_version(),
        "tenseal": tenseal.__version__,
        "os": f"{platform.system()} {platform.release()}",
        "cpu": platform.processor() or platform.machine(),
        "logical_cpus": os.cpu_count(),
    }
    try:
        import ctypes

        class MemoryStatus(ctypes.Structure):
            _fields_ = [
                ("dwLength", ctypes.c_ulong),
                ("dwMemoryLoad", ctypes.c_ulong),
                ("ullTotalPhys", ctypes.c_ulonglong),
            ] + [(f"_f{i}", ctypes.c_ulonglong) for i in range(6)]

        status = MemoryStatus()
        status.dwLength = ctypes.sizeof(MemoryStatus)
        if hasattr(ctypes, "windll") and ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
            info["ram_gb"] = round(status.ullTotalPhys / 2**30, 1)
    except Exception:  # noqa: S110 - best effort
        pass
    if "ram_gb" not in info and hasattr(os, "sysconf"):
        info["ram_gb"] = round(os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES") / 2**30, 1)
    return info


def timed(fn, repeat: int) -> tuple[float, Any]:  # type: ignore[no-untyped-def]
    samples, result = [], None
    for _ in range(repeat):
        start = time.perf_counter()
        result = fn()
        samples.append(time.perf_counter() - start)
    return statistics.median(samples), result


OPERATIONS: list[tuple[str, int, dict[str, Any]]] = [
    ("vector_add", 2, {}),
    ("scalar_multiply", 1, {"scalar": 1.5}),
    ("elementwise_multiply", 2, {}),
    ("dot_product", 2, {}),
    ("sum", 1, {}),
    ("mean", 1, {}),
    ("variance", 1, {}),
    ("weighted_average", 1, {"weights": None}),
    ("linear_regression", 4, {"weights": [0.5, -0.25, 0.75, 0.1], "intercept": 0.2, "layout": "columns"}),
    (
        "logistic_regression",
        4,
        {"weights": [0.5, -0.25, 0.75, 0.1], "intercept": 0.2, "layout": "columns", "degree": 3},
    ),
    (
        "logistic_regression",
        4,
        {"weights": [0.5, -0.25, 0.75, 0.1], "intercept": 0.2, "layout": "columns", "degree": 5},
    ),
    ("matvec_multiply", 1, {"matrix": None}),
]


def fresh_precision(params: CKKSParams) -> dict[str, int]:
    return {cls: precision_bits(params, 0, cls)[0] for cls in ("slotwise", "rotations")}


def bench(profile: str, params, repeat: int, rng: np.random.Generator) -> dict[str, Any]:  # type: ignore[no-untyped-def]
    n = params.slots
    keygen_s, ring = timed(lambda: KeyRing.generate(params), 1)
    bundle = ring.public_bundle()
    data = rng.uniform(-1, 1, n)
    enc_s, ev = timed(lambda: EncryptedVector.encrypt(bundle, data), repeat)
    dec_s, _ = timed(lambda: ring.decrypt(ev), repeat)
    inputs = [EncryptedVector.encrypt(bundle, rng.uniform(-1, 1, n)) for _ in range(4)]
    ops: dict[str, Any] = {}
    for name, k, args in OPERATIONS:
        args = dict(args)
        if name == "weighted_average":
            args["weights"] = rng.uniform(0.1, 1, n).tolist()
        if name == "matvec_multiply":
            # 16 x 64 matrix against the first 64 slots
            vec = EncryptedVector.encrypt(bundle, rng.uniform(-1, 1, 64))
            args["matrix"] = rng.uniform(-1, 1, (16, 64)).tolist()
            label = "matvec_multiply (16x64)"
            ins = [vec]
        else:
            label = name if name != "logistic_regression" else f"logistic_regression deg{args['degree']}"
            ins = inputs[:k]
        try:
            plan(params, [(name, args)], input_lengths=[x.length for x in ins])
        except DepthExhaustedError:
            ops[label] = {"seconds": None, "refused": "depth_exhausted"}
            continue
        seconds, out = timed(lambda: apply_operation(name, bundle, ins, args), repeat)  # noqa: B023
        ops[label] = {
            "seconds": round(seconds, 5),
            "levels_consumed": out.levels_consumed,
            "precision_class": get_operation(name).precision_class(args),
            "precision_bits": precision_bits(params, out.levels_consumed, get_operation(name).precision_class(args))[0],
        }
    result = {
        "profile": profile,
        "params": params.to_dict(),
        "depth": params.depth,
        "slots": n,
        "keygen_seconds": round(keygen_s, 3),
        "public_bundle_mb": round(bundle.size_bytes / 1e6, 1),
        "ciphertext_kb": round(len(ev.to_bytes()) / 1e3, 1),
        "encrypt_ms": round(enc_s * 1e3, 2),
        "decrypt_ms": round(dec_s * 1e3, 2),
        "precision_bits_fresh": fresh_precision(params),
        "operations": ops,
    }
    print(
        f"{params.describe():72s} keygen {keygen_s:5.1f}s bundle {result['public_bundle_mb']:6.1f} MB ct {result['ciphertext_kb']:6.0f} KB",
        flush=True,
    )
    return result


def markdown(results: list[dict[str, Any]], host: dict[str, Any]) -> str:
    lines = [
        f"Measured on {host['cpu']} ({host['logical_cpus']} logical CPUs, {host.get('ram_gb', '?')} GB RAM), "
        f"{host['os']}, Python {host['python']}, TenSEAL {host['tenseal']}; one process per parameter set, "
        "median of repeated runs.",
        "",
        "| N | security | profile | depth | slots | keygen | public bundle | ciphertext | encrypt | decrypt | fresh precision (slot-wise / rotating) |",
        "|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for r in results:
        p = r["params"]
        lines.append(
            f"| {p['poly_modulus_degree']} | {p['security_level']} | {r['profile']} | {r['depth']} | {r['slots']} | {r['keygen_seconds']} s | "
            f"{r['public_bundle_mb']} MB | {r['ciphertext_kb']} KB | {r['encrypt_ms']} ms | {r['decrypt_ms']} ms | {r['precision_bits_fresh']['slotwise']} / {r['precision_bits_fresh']['rotations']} bits |"
        )
    op_names = list(results[0]["operations"])
    lines += [
        "",
        "Operation latency (milliseconds; `—` = refused, not enough depth):",
        "",
        "| N / security / profile | " + " | ".join(op_names) + " |",
        "|---" * (len(op_names) + 1) + "|",
    ]
    for r in results:
        p = r["params"]
        cells = []
        for name in op_names:
            sec = r["operations"][name]["seconds"]
            cells.append("—" if sec is None else f"{sec * 1e3:.1f}")
        lines.append(
            f"| {p['poly_modulus_degree']} / {p['security_level']} / {r['profile']} | " + " | ".join(cells) + " |"
        )
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--heavy", action="store_true")
    parser.add_argument("--repeat", type=int, default=5)
    parser.add_argument("--only", type=int, help=argparse.SUPPRESS)  # internal: one preset, JSON on stdout
    parser.add_argument(
        "--markdown-only", action="store_true", help="re-render results.md from results.json without measuring"
    )
    ns = parser.parse_args()
    if ns.markdown_only:
        saved = json.loads((ROOT / "results" / "results.json").read_text(encoding="utf-8"))
        for r in saved["results"]:  # precision comes from the calibration table, not the timing run
            r["precision_bits_fresh"] = fresh_precision(CKKSParams.from_dict(r["params"]))
        (ROOT / "results" / "results.json").write_text(json.dumps(saved, indent=2) + "\n", encoding="utf-8")
        (ROOT / "results" / "results.md").write_text(markdown(saved["results"], saved["machine"]), encoding="utf-8")
        return 0
    presets = [(profile, p) for profile, p in all_presets() if ns.heavy or p.poly_modulus_degree != 32768]
    if ns.only is not None:
        profile, params = presets[ns.only]
        result = bench(profile, params, ns.repeat, np.random.default_rng(7 + ns.only))
        print("RESULT " + json.dumps(result), flush=True)
        return 0
    host = machine()
    results = []
    for index in range(len(presets)):
        argv = [sys.executable, __file__, "--only", str(index), "--repeat", str(ns.repeat)]
        if ns.heavy:
            argv.append("--heavy")
        proc = subprocess.run(argv, stdout=subprocess.PIPE, text=True, check=True)  # noqa: S603 - own script
        for line in proc.stdout.splitlines():
            if line.startswith("RESULT "):
                results.append(json.loads(line[len("RESULT ") :]))
            else:
                print(line, flush=True)
    out_dir = ROOT / "results"
    out_dir.mkdir(exist_ok=True)
    (out_dir / "results.json").write_text(
        json.dumps({"machine": host, "results": results}, indent=2) + "\n", encoding="utf-8"
    )
    (out_dir / "results.md").write_text(markdown(results, host), encoding="utf-8")
    print(f"wrote {out_dir / 'results.json'} and results.md")
    return 0


if __name__ == "__main__":
    sys.exit(main())
