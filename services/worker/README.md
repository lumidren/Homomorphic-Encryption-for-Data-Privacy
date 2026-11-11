# ciphercompute-worker

Celery worker that executes CipherCompute jobs. It loads the client's **public** key bundle,
verifies every input ciphertext against the fingerprint recorded at upload, runs the requested
homomorphic operation, stores the encrypted result and records the measured depth report. It
has no access to any secret key and contains no decryption code path.

```bash
celery -A ciphercompute_worker.celery_app worker --loglevel=INFO --concurrency=2 --prefetch-multiplier=1
```

* Idempotent: a job row is claimed with `SELECT … FOR UPDATE SKIP LOCKED`; a redelivered or
  duplicate message for a job that is no longer `queued` is a no-op.
* Retries: transient failures (storage, database, broker) retry with exponential backoff and jitter,
  up to `CC_WORKER_MAX_ATTEMPTS`; cryptographic or validation failures fail the job immediately.
* Fairness: a per-organization weighted semaphore in Redis caps concurrent jobs
  (`CC_TENANT_MAX_CONCURRENT_JOBS`); N=16384 jobs weigh 2, N=32768 jobs weigh 4.
* Metrics on `:9100/metrics`: job latency (queue wait and compute), levels consumed per job,
  ciphertext sizes, per-tenant throughput, busy workers.
