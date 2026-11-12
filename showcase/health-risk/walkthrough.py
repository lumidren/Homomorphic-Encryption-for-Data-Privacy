#!/usr/bin/env python3
"""Encrypted Health Risk Scoring — scripted walkthrough.

A hospital scores its patients' cardiovascular risk with a logistic-regression model that runs on
a server it does not trust with patient data:

  1. the hospital generates CKKS keys locally (the secret key never leaves this machine);
  2. it standardises and encrypts each vital-sign column locally and uploads only ciphertexts;
  3. the server evaluates  sigmoid(w . x + b)  on the ciphertexts — it never decrypts anything;
  4. the hospital downloads the encrypted scores and decrypts them locally;
  5. the script compares them with the plaintext model and shows exactly what the server saw.

Run against the local dev stack (python scripts/devstack.py) or any deployment:

    python walkthrough.py                                  # http://127.0.0.1:8000
    python walkthrough.py --server https://api.example.com
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import secrets
import shutil
import sys
import time
import uuid
from pathlib import Path

import numpy as np
from rich.console import Console
from rich.table import Table

from ciphercompute_client import CipherComputeClient, KeyStore, TransportConfig, verify_sample
from ciphercompute_core.envelope import MAGIC_CIPHERTEXT, unpack
from ciphercompute_core.sigmoid import sigmoid, sigmoid_poly

HERE = Path(__file__).parent

# Windows consoles default to a legacy code page that cannot print the table borders.
for stream in (sys.stdout, sys.stderr):
    if hasattr(stream, "reconfigure"):
        stream.reconfigure(encoding="utf-8", errors="replace")
console = Console()


def step(n: int, title: str) -> None:
    console.rule(f"[bold]{n}. {title}")


def load_cohort(path: Path, features: list[str]) -> tuple[list[str], np.ndarray, np.ndarray]:
    with path.open(newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    ids = [r["patient_id"] for r in rows]
    x = np.array([[float(r[f]) for f in features] for r in rows])
    y = np.array([int(r["event_10y"]) for r in rows])
    return ids, x, y


def auc(scores: np.ndarray, labels: np.ndarray) -> float:
    pos, neg = scores[labels == 1], scores[labels == 0]
    return float((pos[:, None] > neg[None, :]).mean() + 0.5 * (pos[:, None] == neg[None, :]).mean())


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--server", default=os.environ.get("CC_SERVER", "http://127.0.0.1:8000"))
    parser.add_argument(
        "--patients", type=int, default=600, help="how many synthetic patients to score (max 4096 per ciphertext)"
    )
    parser.add_argument("--keys", type=Path, default=HERE / "keys" / "hospital")
    parser.add_argument("--out", type=Path, default=HERE / "output")
    ns = parser.parse_args()
    started = time.perf_counter()

    model = json.loads((HERE / "model" / "model.json").read_text(encoding="utf-8"))
    features: list[str] = model["features"]
    weights = np.array(model["weights"])
    intercept = float(model["intercept"])
    ids, raw, labels = load_cohort(HERE / "data" / "patients.csv", features)
    ids, raw, labels = ids[-ns.patients :], raw[-ns.patients :], labels[-ns.patients :]  # the held-out tail

    local = ns.server.startswith("http://")
    client = CipherComputeClient(ns.server, transport_config=TransportConfig(allow_insecure_http=local))

    step(1, "Hospital signs up and generates CKKS keys locally")
    email = f"radiology-{uuid.uuid4().hex[:6]}@hospital.example.com"
    client.register(email, secrets.token_urlsafe(18), "St. Example Hospital (synthetic demo)")
    advice = client.advise(
        [("logistic_regression", {"weights": weights.tolist(), "layout": "columns", "degree": 3})],
        [ns.patients] * len(features),
    )
    console.print(
        f"Parameter advisor: logistic regression needs [bold]{advice['required_depth']}[/] multiplicative levels -> "
        f"N={advice['params']['poly_modulus_degree']}, primes {advice['params']['coeff_mod_bit_sizes']}, "
        f"{advice['params']['security_level']}-bit security ({advice['profile']} profile)"
    )
    if ns.keys.exists():
        shutil.rmtree(ns.keys)
    passphrase = os.environ.get("CC_KEY_PASSPHRASE")
    keys = KeyStore.create(
        ns.keys,
        poly_modulus_degree=advice["params"]["poly_modulus_degree"],
        security_level=advice["params"]["security_level"],
        profile=advice["profile"],
        passphrase=passphrase,
        allow_unencrypted=passphrase is None,
    )
    console.print(
        f"Key ring {keys.ring_id[:12]}… written to {ns.keys} "
        f"({'passphrase-protected' if passphrase else 'throwaway demo keys, unencrypted'}). The secret key stays here."
    )

    step(2, "Upload only the PUBLIC key bundle")
    project = client.create_project("cardiovascular-risk")
    bundle = client.upload_key_bundle(project["id"], keys.ring)
    console.print(
        f"Server accepted bundle {bundle['id'][:8]}… ({bundle['size_bytes'] / 1e6:.0f} MB of public, "
        "relinearization and Galois keys; no secret key)"
    )

    step(3, "Standardise and encrypt each vital-sign column on the hospital's machine")
    means, stds = np.array(model["standardization"]["mean"]), np.array(model["standardization"]["std"])
    standardised = (raw - means) / stds
    dataset = client.create_dataset(project["id"], "vitals-2026-q4", bundle["id"])
    cts = client.encrypt_columns_and_upload(dataset["id"], keys.public_bundle(), standardised, labels=features)
    total = sum(c["size_bytes"] for c in cts)
    console.print(
        f"Uploaded {len(cts)} ciphertexts ({len(features)} features x {ns.patients} patients, "
        f"{total / 1e6:.1f} MB). No plaintext left this machine."
    )

    step(4, "Server evaluates sigmoid(w . x + b) on ciphertexts")
    args = {"weights": weights.tolist(), "intercept": intercept, "layout": "columns", "degree": 3}
    job = client.submit_job(project["id"], "logistic_regression", [c["id"] for c in cts], args)
    for update in client.events(job["id"]):
        report = update.get("depth_report") or {}
        console.print(
            f"  job {update['status']:<10} levels {report.get('levels_consumed')}/{report.get('levels_total')}"
        )
    finished = client.get_job(job["id"])
    console.print(f"Computed in {finished['compute_seconds']:.2f} s on the server.")

    step(5, "Hospital downloads and decrypts the risk scores locally")
    scores = client.decrypt_result(job["id"], keys.ring)
    logits = standardised @ weights + intercept
    exact, poly = sigmoid(logits), sigmoid_poly(logits, 3)
    err_vs_poly = float(np.max(np.abs(scores - poly)))
    err_vs_exact = float(np.max(np.abs(scores - exact)))
    table = Table(title="Highest-risk synthetic patients (decrypted locally)")
    for column in ("patient", "encrypted score", "plaintext model", "age", "systolic BP", "smoker", "event"):
        table.add_column(column, justify="right")
    for i in np.argsort(-scores)[:8]:
        table.add_row(
            ids[i],
            f"{scores[i]:.3f}",
            f"{exact[i]:.3f}",
            f"{raw[i, 0]:.0f}",
            f"{raw[i, 1]:.0f}",
            "yes" if raw[i, 5] else "no",
            str(labels[i]),
        )
    console.print(table)
    console.print(
        f"Max |encrypted - plaintext polynomial model| = [bold]{err_vs_poly:.2e}[/] (CKKS approximation error)"
    )
    console.print(f"Max |encrypted - exact sigmoid|            = {err_vs_exact:.3f} (degree-3 sigmoid approximation)")
    console.print(f"AUC: encrypted {auc(scores, labels):.3f} vs plaintext {auc(exact, labels):.3f}")

    step(6, "What the server saw")
    ct_meta = client.list_ciphertexts(dataset["id"])[0]
    stored = client._transport.download(client._call("GET", f"/v1/ciphertexts/{ct_meta['id']}/download")["url"])
    header, payload = unpack(MAGIC_CIPHERTEXT, stored)
    console.print(
        f"Stored object for '{ct_meta['label']}': {len(stored):,} bytes. Readable part (header): {json.dumps(header)}"
    )
    printable = sum(32 <= b < 127 for b in payload[:4096]) / 4096
    console.print(
        f"The remaining {len(payload):,} bytes are CKKS ciphertext: {printable:.0%} of them are printable, "
        "which is what uniformly random bytes look like (95/256 = 37%). No patient value is in there."
    )
    console.print(
        "Plaintext the server could read: the model weights and intercept you chose to send "
        f"({len(weights)} numbers), never patient values."
    )
    events = client.audit_events(limit=20)
    console.print("Audit trail: " + ", ".join(sorted({e["action"] for e in events})))
    console.print(f"Audit hash chain intact: {client.verify_audit_chain()['valid']}")

    step(7, "Spot-check the untrusted server")
    client.verify_manifest(finished, keys.ring)
    # raises VerificationError if the decrypted result disagrees with the plaintext recomputation
    verify_sample(client, keys.ring, job["id"], [standardised[:, i] for i in range(len(features))])
    console.print("Manifest matches what was submitted, and the result matches a local plaintext recomputation.")

    ns.out.mkdir(parents=True, exist_ok=True)
    with (ns.out / "risk_scores.csv").open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["patient_id", "encrypted_score", "plaintext_score"])
        writer.writerows([pid, f"{s:.6f}", f"{e:.6f}"] for pid, s, e in zip(ids, scores, exact, strict=True))
    console.rule()
    console.print(
        f"Done in {time.perf_counter() - started:.0f} s. Scores written to {ns.out / 'risk_scores.csv'} (local only)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
