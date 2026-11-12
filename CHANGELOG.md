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
  - Precision is reported per operation class (slot-wise vs. rotating), calibrated across 12 key
    rings per N = 8192 set and 4 per N = 16384 set with a 4-bit margin.
- API service (FastAPI): OAuth2 password flow with JWT access and rotating refresh tokens, scoped
  API keys, Argon2id, RBAC (owner/admin/analyst/viewer), row-level tenant isolation, hash-chained
  audit log with PostgreSQL immutability triggers, presigned S3 uploads with SSE, rate limiting,
  idempotent job submission with depth pre-checks, SSE job progress, parameter advisor, usage,
  health and readiness endpoints, OpenAPI 3.1 at `/docs`.
- Worker service (Celery + Redis): acks-late delivery, retries with backoff, per-tenant weighted
  concurrency, fingerprint and depth verification, Prometheus metrics, OpenTelemetry traces
  continuing the API's trace, process recycling before SEAL's memory pool reaches the pod limit.
- `ciphercompute-client` SDK and Typer CLI: local key generation and encryption, AES-256-GCM key
  store with Argon2id, TLS 1.3 transport with optional mTLS, result integrity checks and plaintext
  spot-checks of an untrusted server.
- Next.js 15 dashboard: projects, jobs with live progress, depth-budget visualization, parameter
  advisor, audit viewer, API keys and usage; httpOnly-cookie sessions behind a same-origin proxy;
  light/dark themes with WCAG AA contrast verified in tests.
- Deployment: non-root multi-stage images, docker-compose stack, TLS 1.3 Nginx edge, Helm chart
  (HPA, PDB, NetworkPolicy, cert-manager ingress, migrations hook), Terraform for AWS, Prometheus
  alerts, Grafana dashboard and OpenTelemetry collector, backup/restore drill.
- CI/CD: lint, strict typing, tests with coverage gates, SAST, dependency audit, Trivy, Lighthouse,
  staging deploys on `main`, approval-gated production with automatic rollback.
- Showcase: encrypted health risk scoring on a synthetic cohort; benchmark and load-test harnesses;
  whitepaper generated from measured results; zero-dependency local dev stack.

### Fixed
- Operations on operands at different levels now align levels explicitly, and the higher-level
  operand is copied rather than mutated in place.
- Matrix-vector products with entries below the encoding resolution no longer fail with a
  "transparent ciphertext" error.
- Secret ring envelopes missing evaluation keys are rejected instead of silently regenerated.
- Line endings are normalised to LF through `.gitattributes`.
