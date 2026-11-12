"""Worker configuration (prefix ``CC_``), sharing names with the API where they overlap."""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class WorkerSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="CC_", env_file=".env", env_file_encoding="utf-8", extra="ignore")

    env: Literal["dev", "test", "staging", "prod"] = "dev"
    log_level: str = "INFO"
    service_name: str = "ciphercompute-worker"
    version: str = "0.1.0"

    database_url: str = "postgresql+asyncpg://ciphercompute:ciphercompute@localhost:5432/ciphercompute"
    redis_url: str = "redis://localhost:6379/0"
    celery_broker_url: str | None = None
    celery_task_name: str = "ciphercompute_worker.tasks.execute_job"

    s3_bucket: str = "ciphercompute"
    s3_region: str = "us-east-1"
    s3_endpoint_url: str | None = None
    s3_access_key_id: SecretStr | None = None
    s3_secret_access_key: SecretStr | None = None
    s3_sse: Literal["AES256", "aws:kms"] = "AES256"
    s3_kms_key_id: str | None = None
    s3_force_path_style: bool = True
    presign_ttl_seconds: int = 300

    max_ciphertext_bytes: int = 64 * 1024 * 1024
    max_bundle_bytes: int = 4 * 1024 * 1024 * 1024

    tenant_max_concurrent_jobs: int = 4
    #: Lease on a semaphore slot; a crashed worker's slot frees itself after this long.
    tenant_slot_lease_seconds: int = 900
    worker_max_attempts: int = 5
    retry_backoff_base_seconds: float = 2.0
    retry_backoff_max_seconds: float = 300.0
    #: How long a job may wait for a tenant slot before it is failed as starved.
    max_queue_wait_seconds: int = 3600
    job_soft_time_limit_seconds: int = 600
    job_hard_time_limit_seconds: int = 660
    #: SEAL's memory pool never returns memory to the OS; once a worker process's resident memory
    #: passes this ceiling (KiB) Celery replaces it after the current job. Set below the pod limit.
    max_memory_per_child_kib: int = 6 * 1024 * 1024
    bundle_cache_size: int = 4

    metrics_port: int = 9100
    otel_exporter_otlp_endpoint: str | None = None
    otel_sample_ratio: float = 1.0

    @property
    def broker_url(self) -> str:
        return self.celery_broker_url or self.redis_url


@lru_cache(maxsize=1)
def get_settings() -> WorkerSettings:
    return WorkerSettings()
