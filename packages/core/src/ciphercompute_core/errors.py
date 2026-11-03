"""Exception hierarchy for the crypto core.

Every error carries a machine-readable ``code`` so the API can map it to a stable error
envelope without string matching.
"""

from __future__ import annotations

from typing import Any


class CipherComputeError(Exception):
    """Base class for all CipherCompute errors."""

    code: str = "ciphercompute_error"

    def __init__(self, message: str, **details: Any) -> None:
        super().__init__(message)
        self.message = message
        self.details: dict[str, Any] = details

    def to_dict(self) -> dict[str, Any]:
        return {"code": self.code, "message": self.message, "details": self.details}


class InsecureParametersError(CipherComputeError, ValueError):
    """A CKKS parameter set violates the HE Security Standard bounds or SEAL's limits."""

    code = "insecure_parameters"


class SecretKeyLeakError(CipherComputeError):
    """Raised when secret-key material shows up where only public material is allowed."""

    code = "secret_key_leak"


class DepthExhaustedError(CipherComputeError):
    """A job needs more multiplicative depth than the parameter set provides.

    ``details`` always contains ``required_depth``, ``available_depth`` and a
    ``suggested_params`` dictionary naming the smallest standard parameter set that would
    carry the job at the same security level.
    """

    code = "depth_exhausted"


class UnsupportedOperationError(CipherComputeError):
    """An operation name is not in the registry."""

    code = "unsupported_operation"


class InvalidArgumentError(CipherComputeError, ValueError):
    """Operation arguments fail validation (shape, range, type)."""

    code = "invalid_argument"


class SerializationError(CipherComputeError, ValueError):
    """A serialized bundle or ciphertext envelope is malformed."""

    code = "serialization_error"


class KeyMismatchError(CipherComputeError):
    """A ciphertext was produced under a different key bundle than the one supplied."""

    code = "key_mismatch"
