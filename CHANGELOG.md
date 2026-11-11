# Changelog

All notable changes to CipherCompute are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/). Each package (`ciphercompute-core`,
`ciphercompute-client`, server images) is versioned together until 1.0.

## [Unreleased]

### Added
- Architecture document with C4 diagrams, data flow and the CKKS/TenSEAL rationale.
- STRIDE threat model whose mitigation references are resolved to exact `file:line` by
  `scripts/resolve_threat_refs.py` and checked in CI.
- `ciphercompute-core` 0.1.0:
  - `CKKSParams` validated at construction against the HE Security Standard bounds for 128/192/256-bit
    security; 18 standard presets (balanced and deep profiles for N = 8192/16384/32768).
  - `KeyRing` (client-only secret key owner) and `PublicKeyBundle`, whose loader refuses any
    context that contains a secret key.
  - `EncryptedVector` with level accounting read from the ciphertext itself and tamper-checked headers.
  - Operation registry: vector add, scalar multiply, element-wise multiply, dot product, sum, mean,
    variance, weighted average, linear regression (single-sample and batched column layouts),
    logistic regression with degree-3/5 polynomial sigmoid, matrix-vector multiply.
  - Depth budgeting (`plan`, `advise`) that refuses jobs before execution and names the smallest
    parameter set that would carry them.
  - Measured precision table and calibration script; property-based tests (Hypothesis) for every
    operation on every preset; depth regression tests measured two independent ways; UUIDv7.
