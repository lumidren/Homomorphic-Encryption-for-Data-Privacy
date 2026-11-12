#!/usr/bin/env python3
"""Train the plaintext cardiovascular-risk model used by the encrypted demo.

Logistic regression on standardised features, fitted by Newton's method (IRLS) with a small L2
penalty, on a training split of the SYNTHETIC cohort. The script also checks the property the
encrypted inference depends on: the model's logits stay inside [-8, 8], where the degree-3/5
polynomial sigmoid is a valid approximation, and it reports how much the approximation changes
the scores.

    python train_model.py --data data/patients.csv --out model/model.json
"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

import numpy as np

from ciphercompute_core.sigmoid import SIGMOID_DOMAIN, sigmoid, sigmoid_poly

HERE = Path(__file__).parent


def load(path: Path) -> tuple[list[str], np.ndarray, np.ndarray]:
    with path.open(newline="", encoding="utf-8") as fh:
        rows = list(csv.reader(fh))
    header, body = rows[0], rows[1:]
    features = header[1:-1]
    x = np.array([[float(v) for v in r[1:-1]] for r in body])
    y = np.array([int(r[-1]) for r in body])
    return features, x, y


def fit_logistic(z: np.ndarray, y: np.ndarray, l2: float = 1e-2, iterations: int = 50) -> tuple[np.ndarray, float]:
    design = np.column_stack([np.ones(len(z)), z])
    beta = np.zeros(design.shape[1])
    penalty = l2 * np.eye(design.shape[1])
    penalty[0, 0] = 0.0  # do not shrink the intercept
    for _ in range(iterations):
        p = sigmoid(design @ beta)
        gradient = design.T @ (p - y) + penalty @ beta
        hessian = design.T @ (design * (p * (1 - p))[:, None]) + penalty
        step = np.linalg.solve(hessian, gradient)
        beta -= step
        if np.max(np.abs(step)) < 1e-10:
            break
    return beta[1:], float(beta[0])


def auc(scores: np.ndarray, labels: np.ndarray) -> float:
    """Area under the ROC curve via the Mann-Whitney U statistic (ties counted half)."""
    order = np.argsort(scores)
    ranks = np.empty(len(scores))
    ranks[order] = np.arange(1, len(scores) + 1)
    for value in np.unique(scores):
        tie = scores == value
        ranks[tie] = ranks[tie].mean()
    positives = labels == 1
    n_pos, n_neg = positives.sum(), (~positives).sum()
    return float((ranks[positives].sum() - n_pos * (n_pos + 1) / 2) / (n_pos * n_neg))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--data", type=Path, default=HERE / "data" / "patients.csv")
    parser.add_argument("--out", type=Path, default=HERE / "model" / "model.json")
    parser.add_argument("--train-fraction", type=float, default=0.7)
    ns = parser.parse_args()

    features, x, y = load(ns.data)
    split = int(len(y) * ns.train_fraction)
    means, stds = x[:split].mean(axis=0), x[:split].std(axis=0)
    z = (x - means) / stds
    weights, intercept = fit_logistic(z[:split], y[:split])

    test_logits = z[split:] @ weights + intercept
    exact = sigmoid(test_logits)
    report = {
        "test_auc_exact_sigmoid": round(auc(exact, y[split:]), 4),
        "logit_range": [round(float(test_logits.min()), 3), round(float(test_logits.max()), 3)],
        "logits_within_domain": bool(np.all((test_logits >= SIGMOID_DOMAIN[0]) & (test_logits <= SIGMOID_DOMAIN[1]))),
    }
    for degree in (3, 5):
        approx = sigmoid_poly(test_logits, degree)
        report[f"test_auc_poly_deg{degree}"] = round(auc(approx, y[split:]), 4)
        report[f"max_abs_score_change_deg{degree}"] = round(float(np.max(np.abs(approx - exact))), 4)

    model = {
        "description": "Logistic regression for 10-year cardiovascular event risk, trained on SYNTHETIC data only.",
        "features": features,
        "standardization": {"mean": means.round(6).tolist(), "std": stds.round(6).tolist()},
        "weights": weights.round(6).tolist(),
        "intercept": round(intercept, 6),
        "sigmoid_degree": 3,
        "training": {"patients": int(split), "event_rate": round(float(y[:split].mean()), 4)},
        "evaluation": report,
    }
    ns.out.parent.mkdir(parents=True, exist_ok=True)
    ns.out.write_text(json.dumps(model, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    print(f"wrote {ns.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
