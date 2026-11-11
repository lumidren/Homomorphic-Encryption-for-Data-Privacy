"""Worker Prometheus metrics (scraped from ``:9100/metrics``)."""

from __future__ import annotations

from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram

registry = CollectorRegistry(auto_describe=True)

_LATENCY_BUCKETS = (0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10, 30, 60, 120, 300, 600)

JOB_COMPUTE_SECONDS = Histogram(
    "ciphercompute_job_compute_seconds",
    "Time spent executing a job (download, verify, compute, upload)",
    ["operation", "poly_modulus_degree"],
    registry=registry,
    buckets=_LATENCY_BUCKETS,
)
JOB_END_TO_END_SECONDS = Histogram(
    "ciphercompute_job_end_to_end_seconds",
    "Time from submission to completion",
    ["operation"],
    registry=registry,
    buckets=_LATENCY_BUCKETS,
)
JOB_QUEUE_WAIT_SECONDS = Histogram(
    "ciphercompute_job_queue_wait_seconds",
    "Time from submission until a worker started the job",
    registry=registry,
    buckets=_LATENCY_BUCKETS,
)
JOBS_FINISHED = Counter(
    "ciphercompute_jobs_finished_total",
    "Finished jobs by outcome",
    ["operation", "status", "organization"],
    registry=registry,
)
JOB_RETRIES = Counter("ciphercompute_job_retries_total", "Retries by reason", ["reason"], registry=registry)
LEVELS_CONSUMED_RATIO = Histogram(
    "ciphercompute_job_levels_consumed_ratio",
    "Share of the modulus chain (multiplicative depth) a job consumed: the CKKS noise budget usage",
    ["operation"],
    registry=registry,
    buckets=(0.0, 0.25, 0.5, 0.75, 0.9, 1.0),
)
CIPHERTEXT_INPUT_BYTES = Histogram(
    "ciphercompute_ciphertext_input_bytes",
    "Size of ciphertexts read by the worker",
    registry=registry,
    buckets=(64e3, 256e3, 1e6, 4e6, 16e6, 64e6),
)
RESULT_BYTES = Histogram(
    "ciphercompute_result_ciphertext_bytes",
    "Size of result ciphertexts",
    registry=registry,
    buckets=(64e3, 256e3, 1e6, 4e6, 16e6, 64e6),
)
WORKERS_BUSY = Gauge("ciphercompute_worker_busy", "Jobs currently executing in this process", registry=registry)
TENANT_THROTTLED = Counter(
    "ciphercompute_tenant_throttled_total",
    "Times a job waited because its organization was at its concurrency limit",
    ["organization"],
    registry=registry,
)
