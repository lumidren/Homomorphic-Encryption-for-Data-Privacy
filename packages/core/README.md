# ciphercompute-core

The cryptographic core shared by the CipherCompute SDK, API and worker.

* `params` — `SecurityLevel`, `PolyModulusDegree`, `CKKSParams`; every parameter set is
  validated against the HE Security Standard bounds at construction time.
* `keys` — `KeyRing` (client-only: owns the secret key) and `PublicKeyBundle` (the only key
  object the server ever sees; refuses to load a context that contains a secret key).
* `ciphertext` — `EncryptedVector`, a CKKS ciphertext with depth accounting and a fingerprint.
* `ops` — the registry of homomorphic operations with declared multiplicative-depth costs.
* `budget` — `plan()` refuses jobs that would exhaust the modulus chain and `advise()` names the
  smallest parameter set that would carry them.
* `precision` — measured error bounds per parameter set.

```python
from ciphercompute_core import CKKSParams, KeyRing, EncryptedVector, SecurityLevel, standard_params
from ciphercompute_core.ops import apply_operation

params = standard_params(8192, SecurityLevel.BITS_128)
ring = KeyRing.generate(params)
bundle = ring.public_bundle()  # no secret key inside — ever

x = EncryptedVector.encrypt(bundle, [1.0, 2.0, 3.0])
result = apply_operation("mean", bundle, [x], {})
print(ring.decrypt(result)[0])  # ≈ 2.0
```
