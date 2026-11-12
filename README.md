# CipherCompute

**Statistics and machine-learning inference on encrypted data.** Clients encrypt locally with
CKKS (Microsoft SEAL via TenSEAL); the service computes means, variances, regressions and
logistic-regression risk scores *on the ciphertexts*; only the client can decrypt the result.
The server never holds a secret key, and there is no code path by which it could decrypt.

```
 hospital laptop                          CipherCompute (untrusted)
 ┌──────────────────────┐   ciphertexts   ┌─────────────────────────────────────┐
 │ KeyRing (secret key) │ ──────────────▶ │ API ─▶ queue ─▶ worker: sigmoid(w·x+b)│
 │ encrypt / decrypt    │ ◀────────────── │ public keys only · audit · S3 (SSE)  │
 └──────────────────────┘ encrypted result└─────────────────────────────────────┘
```

| | |
|---|---|
| Crypto core | CKKS parameter sets validated against the HE Security Standard (128/192/256-bit); 11 homomorphic operations; depth budgeting that refuses impossible jobs *before* running them and names parameters that would work; precision measured across many key rings |
| Service | FastAPI + Celery/Redis + PostgreSQL 16 + S3; multi-tenant (UUIDv7, row-level isolation), JWT + rotating refresh tokens, scoped API keys, RBAC, rate limits, hash-chained append-only audit log |
| Client | `ciphercompute-client` Python SDK and `ciphercompute` CLI: local keys (AES-256-GCM + Argon2id at rest), TLS 1.3, optional mTLS, integrity checks, plaintext spot-checks of an untrusted server |
| Dashboard | Next.js 15, strict TypeScript; live job progress (SSE), depth-budget visualisation, parameter advisor, audit viewer, API keys, usage; WCAG AA contrast verified in tests; tokens never reach browser JavaScript |
| Operations | Docker, docker-compose, Helm (HPA, PDB, NetworkPolicy, cert-manager), Terraform for AWS, GitHub Actions with SAST/Trivy/coverage gates, Prometheus + Grafana + OpenTelemetry, backup/restore drill |

## 5-minute quickstart (no Docker)

Requires **64-bit Python 3.12** (TenSEAL ships no 32-bit wheels) and [uv](https://docs.astral.sh/uv/).

```bash
git clone https://github.com/lumidren/Homomorphic-Encryption-for-Data-Privacy
cd Homomorphic-Encryption-for-Data-Privacy
uv venv .venv --python 3.12
uv pip install --python .venv -e packages/core -e packages/client -e services/api -e services/worker "moto[server]" fakeredis
```

**Terminal 1** — the whole backend in one process (real API and worker; SQLite, fakeredis and a
local S3 server stand in for PostgreSQL, Redis and S3):

```bash
.venv/bin/python scripts/devstack.py        # Windows: .venv\Scripts\python scripts\devstack.py
```

**Terminal 2** — encrypt, compute, decrypt:

```bash
source .venv/bin/activate                  # Windows: .venv\Scripts\activate
export CC_SERVER=http://127.0.0.1:8000 CC_INSECURE_HTTP=1 CC_KEY_PASSPHRASE="a long local passphrase" CC_PASSWORD="correct horse battery staple"

ciphercompute register --email you@example.com --organization "My Lab"
ciphercompute keys generate ./keys                      # secret key stays in ./keys, encrypted
ciphercompute --json projects create demo               # note the project id
ciphercompute --json bundles upload <PROJECT_ID> ./keys # public keys only
ciphercompute --json datasets create <PROJECT_ID> vitals <BUNDLE_ID>
ciphercompute --json datasets encrypt-upload <DATASET_ID> ./keys --values "120,135.5,142,118.25" --label systolic
ciphercompute --json jobs submit <PROJECT_ID> mean -i <CIPHERTEXT_ID>
ciphercompute jobs result <JOB_ID> ./keys               # decrypted locally: ≈ 128.94
```

API reference: http://127.0.0.1:8000/docs (OpenAPI 3.1). Dashboard: `cd dashboard && npm ci && CC_API_URL=http://127.0.0.1:8000 npm run dev`.

The production-like stack (PostgreSQL, Redis, MinIO, Nginx with TLS 1.3) runs with
`cp .env.example .env && ./scripts/gen-dev-certs.sh && docker compose up --build`.

## Showcase: encrypted health-risk scoring

`showcase/health-risk/` — a hospital scores synthetic patients with a logistic-regression model
on a server that never sees a vital sign:

```bash
cd showcase/health-risk && ../../.venv/bin/python walkthrough.py
```

Encrypted scores match the plaintext model to 2.4×10⁻⁴; AUC 0.861 encrypted vs 0.861 plaintext;
about 10 seconds end to end. See [its README](showcase/health-risk/README.md).

## Documentation

| | |
|---|---|
| [ARCHITECTURE.md](ARCHITECTURE.md) | C4 diagrams, data flow, why CKKS (not BFV) and why TenSEAL, parameter sets, depth costs |
| [THREAT_MODEL.md](THREAT_MODEL.md) | STRIDE register; every mitigation points at the enforcing `file:line` (checked in CI) |
| [SECURITY.md](SECURITY.md) | Disclosure policy, what the cryptography does and does not guarantee |
| [RUNBOOK.md](RUNBOOK.md) | On-call procedures for every alert, rollback, restore, key and secret rotation |
| [docs/whitepaper.md](docs/whitepaper.md) ([PDF](docs/whitepaper.pdf)) | CKKS explained for undergraduates, with measured precision and performance |
| [CONTRIBUTING.md](CONTRIBUTING.md) · [CHANGELOG.md](CHANGELOG.md) | Development workflow and release notes |

## Repository layout

```
packages/core      ciphercompute_core    CKKS params, keys, ciphertexts, operations, depth planning, precision
packages/client    ciphercompute_client  SDK + `ciphercompute` CLI
services/api       ciphercompute_api     FastAPI service, Alembic migrations
services/worker    ciphercompute_worker  Celery worker
dashboard/                               Next.js 15 dashboard
infra/                                   Docker, Nginx, Helm, Terraform, observability, policy tests
showcase/health-risk                     end-to-end demo
benchmarks/, loadtest/                   measured performance
scripts/                                 dev stack, calibration, restore drill, doc generators
```

## Tests

```bash
cd packages/core   && ../../.venv/bin/pytest     # property tests (Hypothesis) on every preset, 100% coverage gate
cd services/api    && ../../.venv/bin/pytest     # 80+ tests, >= 90% coverage
cd services/worker && ../../.venv/bin/pytest
cd packages/client && ../../.venv/bin/pytest     # SDK + CLI end to end against API, S3 and worker
cd dashboard && npm test
```

## License

MIT © lumidren
