# Security Policy

## Reporting a vulnerability

Email **security@ciphercompute.dev** (PGP key fingerprint published at
`https://ciphercompute.dev/.well-known/security.txt`). Please include a reproduction and the
commit hash. We acknowledge within 2 business days and aim to ship a fix for confirmed HIGH/CRITICAL
issues within 14 days. Do not open public issues for security reports.

Coordinated disclosure: we credit reporters in `CHANGELOG.md` unless asked not to.

## Supported versions

| Component | Supported |
|---|---|
| `ciphercompute-core`, `ciphercompute-client` | latest minor on the current major |
| Server images | tags built from `main` and the latest release |

## What the cryptography guarantees — and what it does not

CipherCompute uses CKKS (Microsoft SEAL via TenSEAL). Read [THREAT_MODEL.md](THREAT_MODEL.md)
for the full STRIDE register. The short version:

* **Confidentiality of your data against the server is cryptographic.** The server holds only
  public, relinearisation and Galois keys. A fully compromised server cannot recover plaintext.
* **Integrity of the computation is not cryptographic.** A malicious server could return a wrong
  result. Use `client.verify_sample()` to re-check a random subset of jobs on plaintext, and treat
  the service as an untrusted compute provider.
* **Never send decrypted results back to the service** (or to any party that holds your
  ciphertexts). Approximate-decryption leakage (Li–Micciancio 2021) can recover a CKKS secret key
  from decrypted outputs. The SDK exposes no API that does this; keep it that way in your own code.
* **Plaintext job arguments** (scalars, regression weights, matrices) are visible to the server.
  Encrypt them client-side if they are sensitive; the cost is one extra multiplicative level.

## Operator hardening checklist

- [ ] `JWT_SECRET` ≥ 32 random bytes, sourced from Vault / AWS Secrets Manager — never from the repo.
- [ ] TLS 1.3 only at the edge; HSTS enabled; mTLS enabled for SDK clients where feasible.
- [ ] Object-store buckets have SSE enforced and public access blocked (Terraform does this).
- [ ] Database role used by the API has no `DELETE`/`UPDATE` on `audit_events` (the trigger blocks
      it anyway; least privilege is a second gate).
- [ ] Rate limits and per-tenant concurrency configured for your capacity (see RUNBOOK.md).
- [ ] `pip-audit`, `npm audit`, Bandit, Semgrep and Trivy are green on the deployed commit.
- [ ] Backups verified by the restore drill in `scripts/restore_drill.sh` within the last 30 days.

## Secret handling rules for contributors

* No secret in the repository, ever. `.env.example` documents every variable with a dummy value.
* Compare secrets with `hmac.compare_digest` only (Semgrep rule `no-plain-secret-compare`).
* Never log request bodies, tokens, key material or ciphertext bytes; the log scrubber is a safety
  net, not a licence.
* The server packages must not import `ciphercompute_core.keys.KeyRing`; CI enforces it.
