"""Spot-checking an untrusted server.

FHE protects confidentiality, not the correctness of the computation: a malicious server could
return a well-formed but wrong ciphertext. ``verify_sample`` re-runs a job's operation on the
plaintext the client still holds and compares it with the decrypted result, within the measured
CKKS tolerance. Running it on a random fraction of jobs makes systematic cheating detectable.
"""

from __future__ import annotations

import random
from collections.abc import Sequence
from typing import Any

import numpy as np

from ciphercompute_core import KeyRing, get_operation
from ciphercompute_core.params import CKKSParams
from ciphercompute_core.precision import magnitude_class, tolerance

from .client import CipherComputeClient


class VerificationError(Exception):
    def __init__(self, message: str, *, max_error: float, tolerance: float) -> None:
        super().__init__(message)
        self.max_error = max_error
        self.tolerance = tolerance


def check_result(
    job: dict[str, Any], decrypted: np.ndarray, plaintext_inputs: Sequence[Sequence[float] | np.ndarray]
) -> tuple[float, float]:
    """Return ``(max_error, tolerance)``; raise :class:`VerificationError` when out of bounds."""
    # [TM:T-2] Probabilistic detection of a server that returns wrong (but well-formed) results.
    spec = get_operation(job["operation"])
    xs = [np.asarray(x, dtype=np.float64) for x in plaintext_inputs]
    args = spec.normalize([len(x) for x in xs], job["args"])
    expected = spec.reference(xs, args)
    params = CKKSParams.from_dict(job["plan"]["params"])
    levels = int(job["depth_report"]["levels_consumed"])
    tol = tolerance(params, levels, magnitude_class(xs, args, expected))
    got = np.asarray(decrypted, dtype=np.float64)[: expected.size]
    if got.shape != expected.shape:
        raise VerificationError(
            f"result has {got.size} values, expected {expected.size}", max_error=float("inf"), tolerance=tol
        )
    err = float(np.max(np.abs(got - expected)))
    if err > tol:
        raise VerificationError(
            f"job {job['id']}: decrypted result differs from the plaintext recomputation "
            f"by {err:.3e} (tolerance {tol:.3e})",
            max_error=err,
            tolerance=tol,
        )
    return err, tol


def verify_sample(
    client: CipherComputeClient,
    ring: KeyRing,
    job_id: str,
    plaintext_inputs: Sequence[Sequence[float] | np.ndarray],
    *,
    probability: float = 1.0,
    rng: random.Random | None = None,
) -> bool:
    """With ``probability``, verify the job's result against a local plaintext recomputation.

    Also checks the job manifest (operation, arguments, input fingerprints) against what this
    client uploaded. Returns True when a check ran and passed, False when it was skipped.
    """
    if (rng or random.Random()).random() >= probability:  # noqa: S311 - sampling, not cryptography
        return False
    job = client.wait(job_id)
    client.verify_manifest(job, ring)
    check_result(job, client.decrypt_result(job_id, ring), plaintext_inputs)
    return True
