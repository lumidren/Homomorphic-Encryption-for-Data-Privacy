#!/usr/bin/env python3
"""Generate SYNTHETIC patient vitals for the encrypted health-risk demo.

Nothing here is real patient data. Values are drawn from plausible adult-population ranges and a
hidden "ground-truth" logistic model (loosely shaped like published cardiovascular risk scores)
decides each synthetic patient's 10-year event label. The generator is seeded, so every run of the
walkthrough produces the same cohort.

    python generate_patients.py --patients 2000 --out data/patients.csv
"""

from __future__ import annotations

import argparse
import csv
from pathlib import Path

import numpy as np

FEATURES = ["age", "systolic_bp", "total_cholesterol", "hdl_cholesterol", "bmi", "smoker", "diabetic"]

# Hidden generating model (per standardised unit). Only used to label the synthetic cohort.
_TRUE_WEIGHTS = {
    "age": 1.05,
    "systolic_bp": 0.55,
    "total_cholesterol": 0.30,
    "hdl_cholesterol": -0.45,
    "bmi": 0.20,
    "smoker": 0.65,
    "diabetic": 0.55,
}
_TRUE_INTERCEPT = -2.1


def generate(n: int, seed: int = 2026) -> tuple[np.ndarray, np.ndarray]:
    rng = np.random.default_rng(seed)
    age = np.clip(rng.normal(55, 11, n), 30, 85)
    systolic = np.clip(rng.normal(118 + 0.55 * (age - 55), 15, n), 90, 200)
    total_chol = np.clip(rng.normal(205, 38, n), 120, 330)
    hdl = np.clip(rng.normal(52, 13, n), 20, 100)
    bmi = np.clip(rng.normal(27.5, 4.8, n), 17, 48)
    smoker = (rng.random(n) < 0.18).astype(float)
    diabetic = (rng.random(n) < np.clip(0.06 + 0.012 * (bmi - 25), 0.02, 0.4)).astype(float)
    x = np.column_stack([age, systolic, total_chol, hdl, bmi, smoker, diabetic])
    z = (x - x.mean(axis=0)) / x.std(axis=0)
    logit = _TRUE_INTERCEPT + z @ np.array([_TRUE_WEIGHTS[f] for f in FEATURES])
    label = (rng.random(n) < 1 / (1 + np.exp(-logit))).astype(int)
    return x, label


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--patients", type=int, default=2000)
    parser.add_argument("--seed", type=int, default=2026)
    parser.add_argument("--out", type=Path, default=Path(__file__).parent / "data" / "patients.csv")
    ns = parser.parse_args()
    x, y = generate(ns.patients, ns.seed)
    ns.out.parent.mkdir(parents=True, exist_ok=True)
    with ns.out.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["patient_id", *FEATURES, "event_10y"])
        for i, (row, label) in enumerate(zip(x, y, strict=True)):
            writer.writerow(
                [
                    f"SYN-{i:05d}",
                    *[
                        f"{v:.1f}" if f not in ("smoker", "diabetic") else int(v)
                        for f, v in zip(FEATURES, row, strict=True)
                    ],
                    int(label),
                ]
            )
    print(f"wrote {ns.patients} synthetic patients to {ns.out} (event rate {y.mean():.1%})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
