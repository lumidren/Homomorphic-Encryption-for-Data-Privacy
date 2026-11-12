# Load test report — N = 8192, 128-bit security

Run on 2026-11-12 with `loadtest/locustfile.py` (Locust 2.47.0). Raw outputs are committed next
to this file: `results/run_stats.csv`, `results/run_stats_history.csv`, `results/run.html`.

## Summary

At **N = 8192, 128-bit security (balanced, scale 2^40)**, 20 simulated analysts sharing one
organisation submitted `mean`, `dot_product` and `variance` jobs over full-width ciphertexts
(4,096 slots, 332 KB each) for 5 minutes, each keeping at most 4 jobs in flight.

| metric | result |
|---|---|
| HTTP requests | 12,034, **0 failures** |
| jobs completed | 3,680 accepted, 3,680 succeeded, 0 retried |
| sustained job throughput | **12.3 jobs/s** (saturated) |
| `POST /jobs` latency (accept, depth pre-check, enqueue) | p50 80 ms · p95 240 ms · p99 540 ms |
| `GET /jobs/{id}` latency | p50 32 ms · p95 130 ms · p99 320 ms |
| job latency, accepted → succeeded (server timestamps) | p50 1.7 s · p95 3.0 s · p99 3.2 s |
| of which queue wait | p50 1.4 s · p95 2.7 s |
| of which execution (fetch, verify, compute, store) | p50 0.26 s · p95 0.39 s |

The system stayed correct under saturation: no errors, no retries, every result stored with its
fingerprint and depth report. Job latency is dominated by queueing, because the test pushed one
tenant past what four executors can serve. The platform's per-tenant limit is also four
concurrent jobs, so adding executors would not raise this tenant's throughput. It would raise
the platform's total throughput across tenants.

## Environment, and what it does and does not represent

* **Hardware:** one laptop (Intel Core, 20 logical CPUs, 15.7 GB RAM, Windows 11), shared by the
  load generator and the system under test.
* **System under test:** `scripts/devstack.py --job-workers 4`, which runs the real FastAPI
  application and the real job executor (`ciphercompute_worker.executor.run_job`) in **one Python
  process**, with SQLite in place of PostgreSQL 16, fakeredis in place of Redis 7 and a moto S3
  server in place of S3. The per-key rate limit was raised (`CC_RATE_LIMIT_PER_MINUTE=100000`)
  because all simulated users share one API key. In production each user would hit their own limit.
* Run it again with:

  ```bash
  CC_RATE_LIMIT_PER_MINUTE=100000 python scripts/devstack.py --port 8100 --s3-port 9100 --job-workers 4
  locust -f loadtest/locustfile.py --host http://127.0.0.1:8100 --headless -u 20 -r 5 -t 5m \
      --csv loadtest/results/run --html loadtest/results/run.html
  ```

This measures the application code paths (authentication, tenancy, depth planning, idempotency,
audit, storage, executor) under concurrency. It does **not** measure the production topology
(Kubernetes, separate Celery worker pods, PostgreSQL, Redis, S3). Production throughput was not
measured in this repository.

## Analysis

**Where job time goes.** In isolation a `mean` over 4,096 slots takes 18 ms (see
`benchmarks/results/results.md`). Under this load the executor recorded p50 0.21 s of compute per
job. All four executors are threads in one Python process, sharing it with the API, the S3 stand-in
and SQLite, while the load generator runs on the same machine. The ~10× inflation is contention
for that process and those cores, not CKKS cost. In the production layout each Celery worker is a
separate process with its own cores (`infra/helm`), and the HPA scales workers on queue depth.

**The API path stays fast while the queue is saturated.** `POST /jobs` validates inputs, checks
the depth budget against the key bundle's parameters, writes the job and an audit event, and
enqueues it. Its p95 stayed at 240 ms while the executors were saturated, so submission does not
degrade with queue depth.

**Correctness held under load.** 3,680 of 3,680 jobs succeeded on their first attempt. Each
re-verified its input fingerprints and the depth it consumed, and the job count matched the
number of accepted submissions.

**Measurement note.** The first version of the scenario timed jobs from the client's side, and
it reported 5–20 s "latency" that was really the gap between a job finishing and the simulated
user next polling it. The scenario now limits each user to 4 jobs in flight and reports job
latency from the server's own `created_at` → `finished_at` timestamps.
