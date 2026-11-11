"""Runtime configuration, read from the environment (prefix ``CC_``).

Every secret is a ``SecretStr`` so it never appears in ``repr``/logs, and every value is
documented in ``.env.example``. Nothing here has a production-safe default for a secret.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_MIN_JWT_SECRET_BYTES = 32


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="CC_", env_file=".env", env_file_encoding="utf-8", extra="ignore")

    env: Literal["dev", "test", "staging", "prod"] = "dev"
    log_level: str = "INFO"
    service_name: str = "ciphercompute-api"
    version: str = "0.1.0"

    # ----- persistence --------------------------------------------------------------------
    database_url: str = "postgresql+asyncpg://ciphercompute:ciphercompute@localhost:5432/ciphercompute"
    database_pool_size: int = 10
    redis_url: str = "redis://localhost:6379/0"

    # ----- object storage (S3 / MinIO) ----------------------------------------------------
    s3_bucket: str = "ciphercompute"
    s3_region: str = "us-east-1"
    s3_endpoint_url: str | None = None
    s3_access_key_id: SecretStr | None = None
    s3_secret_access_key: SecretStr | None = None
    s3_sse: Literal["AES256", "aws:kms"] = "AES256"
    s3_kms_key_id: str | None = None
    s3_force_path_style: bool = True
    presign_ttl_seconds: int = 300

    # ----- limits --------------------------------------------------------------------------
    max_ciphertext_bytes: int = 64 * 1024 * 1024
    max_bundle_bytes: int = 4 * 1024 * 1024 * 1024
    max_inputs_per_job: int = 64
    rate_limit_per_minute: int = 600
    login_rate_limit_per_minute: int = 10
    tenant_max_concurrent_jobs: int = 4
    idempotency_ttl_seconds: int = 24 * 3600

    # ----- auth ----------------------------------------------------------------------------
    jwt_secret: SecretStr = Field(default=SecretStr(""))
    jwt_previous_secret: SecretStr | None = None
    jwt_kid: str = "v1"
    jwt_previous_kid: str = "v0"
    jwt_issuer: str = "ciphercompute"
    access_token_ttl_seconds: int = 900
    refresh_token_ttl_seconds: int = 30 * 24 * 3600
    argon2_time_cost: int = 3
    argon2_memory_kib: int = 65536
    argon2_parallelism: int = 4
    allow_self_registration: bool = True

    # ----- edge ----------------------------------------------------------------------------
    cors_origins: list[str] = Field(default_factory=lambda: ["http://localhost:3000"])
    trust_x_forwarded_for: bool = False

    # ----- queue / events ------------------------------------------------------------------
    queue_backend: Literal["celery", "memory"] = "celery"
    celery_broker_url: str | None = None
    celery_task_name: str = "ciphercompute_worker.tasks.execute_job"
    job_poll_interval_seconds: float = 2.0

    # ----- observability -------------------------------------------------------------------
    otel_exporter_otlp_endpoint: str | None = None
    otel_sample_ratio: float = 1.0
    metrics_enabled: bool = True

    @field_validator("jwt_secret")
    @classmethod
    def _jwt_secret_long_enough(cls, value: SecretStr) -> SecretStr:
        raw = value.get_secret_value()
        if len(raw.encode("utf-8")) < _MIN_JWT_SECRET_BYTES:
            raise ValueError(f"CC_JWT_SECRET must be at least {_MIN_JWT_SECRET_BYTES} bytes of random data")
        return value

    @field_validator("cors_origins", mode="before")
    @classmethod
    def _split_origins(cls, value: object) -> object:
        if isinstance(value, str):
            return [v.strip() for v in value.split(",") if v.strip()]
        return value

    @property
    def broker_url(self) -> str:
        return self.celery_broker_url or self.redis_url

    @property
    def is_production(self) -> bool:
        return self.env == "prod"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
