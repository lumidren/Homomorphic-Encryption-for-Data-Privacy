"""ciphercompute-client — compute on encrypted data without giving anyone your key.

from ciphercompute_client import CipherComputeClient, KeyStore, SecurityLevel

keys = KeyStore.create("~/.ciphercompute/keys/cardio", poly_modulus_degree=8192,
                       security_level=SecurityLevel.BITS_128, passphrase="…")
with CipherComputeClient("https://api.ciphercompute.dev", api_key="cc_…") as cc:
    project = cc.create_project("cardio")
    bundle = cc.upload_key_bundle(project["id"], keys.ring)
    dataset = cc.create_dataset(project["id"], "vitals", bundle["id"])
    ct = cc.encrypt_and_upload(dataset["id"], keys.ring, [120.0, 135.5, 142.0], label="systolic")
    job = cc.submit_job(project["id"], "mean", [ct["id"]])
    print(cc.wait_and_decrypt(job["id"], keys.ring))      # decrypted locally
"""

from __future__ import annotations

from ciphercompute_core import CKKSParams, PolyModulusDegree, SecurityLevel, standard_params

from .client import CipherComputeClient, JobFailedError
from .errors import ApiError
from .keystore import KeyStore
from .transport import TransportConfig
from .verify import VerificationError, verify_sample

__version__ = "0.1.0"

__all__ = [
    "ApiError",
    "CKKSParams",
    "CipherComputeClient",
    "JobFailedError",
    "KeyStore",
    "PolyModulusDegree",
    "SecurityLevel",
    "TransportConfig",
    "VerificationError",
    "__version__",
    "standard_params",
    "verify_sample",
]
