"""ciphercompute-core — CKKS crypto core for CipherCompute.

Public API::

    from ciphercompute_core import (
        CKKSParams, SecurityLevel, PolyModulusDegree, standard_params,
        KeyRing, PublicKeyBundle, EncryptedVector,
        apply_operation, plan, advise, DepthReport,
    )
"""

from __future__ import annotations

from .budget import Advice, DepthReport, Plan, PlannedStep, advise, plan
from .ciphertext import EncryptedVector
from .errors import (
    CipherComputeError,
    DepthExhaustedError,
    InsecureParametersError,
    InvalidArgumentError,
    KeyMismatchError,
    SecretKeyLeakError,
    SerializationError,
    UnsupportedOperationError,
)
from .ids import is_uuid7, uuid7
from .keys import KeyRing, PublicKeyBundle
from .ops import OperationSpec, apply_operation, get_operation, list_operations
from .params import (
    DEEP_PARAMS,
    MAX_COEFF_MODULUS_BITS,
    STANDARD_PARAMS,
    CKKSParams,
    PolyModulusDegree,
    SecurityLevel,
    all_presets,
    standard_params,
)
from .precision import precision_bits, recommended_input_bound, tolerance

__version__ = "0.1.0"

__all__ = [
    "DEEP_PARAMS",
    "MAX_COEFF_MODULUS_BITS",
    "STANDARD_PARAMS",
    "Advice",
    "CKKSParams",
    "CipherComputeError",
    "DepthExhaustedError",
    "DepthReport",
    "EncryptedVector",
    "InsecureParametersError",
    "InvalidArgumentError",
    "KeyMismatchError",
    "KeyRing",
    "OperationSpec",
    "Plan",
    "PlannedStep",
    "PolyModulusDegree",
    "PublicKeyBundle",
    "SecretKeyLeakError",
    "SecurityLevel",
    "SerializationError",
    "UnsupportedOperationError",
    "__version__",
    "advise",
    "all_presets",
    "apply_operation",
    "get_operation",
    "is_uuid7",
    "list_operations",
    "plan",
    "precision_bits",
    "recommended_input_bound",
    "standard_params",
    "tolerance",
    "uuid7",
]
