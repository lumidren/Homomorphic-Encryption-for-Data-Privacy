from __future__ import annotations

import time
import uuid

import fakeredis
import pytest

from ciphercompute_worker import tasks
from ciphercompute_worker.celery_app import app
from ciphercompute_worker.concurrency import TenantSemaphore, job_weight
from ciphercompute_worker.executor import Outcome


async def test_semaphore_limits_per_tenant() -> None:
    sem = TenantSemaphore(fakeredis.FakeAsyncRedis(), limit=4, lease_seconds=60)
    org, other = uuid.uuid4(), uuid.uuid4()
    jobs = [uuid.uuid4() for _ in range(3)]
    assert await sem.acquire(org, jobs[0], 2)
    assert await sem.acquire(org, jobs[1], 2)
    assert not await sem.acquire(org, jobs[2], 1)  # tenant full
    assert await sem.acquire(other, uuid.uuid4(), 4)  # other tenants unaffected
    assert await sem.in_use(org) == 4
    assert await sem.acquire(org, jobs[0], 2)  # redelivery of a holder is idempotent
    await sem.release(org, jobs[0], 2)
    assert await sem.acquire(org, jobs[2], 1) and await sem.in_use(org) == 3


async def test_heavy_job_admitted_when_idle() -> None:
    sem = TenantSemaphore(fakeredis.FakeAsyncRedis(), limit=2, lease_seconds=60)
    org = uuid.uuid4()
    assert await sem.acquire(org, uuid.uuid4(), job_weight(32768))
    assert not await sem.acquire(org, uuid.uuid4(), 1)


async def test_expired_leases_free_their_slots(monkeypatch: pytest.MonkeyPatch) -> None:
    sem = TenantSemaphore(fakeredis.FakeAsyncRedis(), limit=1, lease_seconds=10)
    org = uuid.uuid4()
    assert await sem.acquire(org, uuid.uuid4(), 1)
    later = time.time() + 11
    monkeypatch.setattr("ciphercompute_worker.concurrency.time.time", lambda: later)
    assert await sem.acquire(org, uuid.uuid4(), 1)  # the crashed holder's lease expired


def test_weights() -> None:
    assert [job_weight(n) for n in (8192, 16384, 32768, 65536)] == [1, 2, 4, 4]


def test_celery_reliability_settings() -> None:
    conf = app.conf
    assert conf.task_acks_late and conf.task_reject_on_worker_lost
    assert conf.worker_prefetch_multiplier == 1
    assert 0 < conf.worker_max_memory_per_child <= 8 * 1024 * 1024  # recycled before the 8 GiB pod limit
    assert conf.broker_transport_options["visibility_timeout"] > conf.task_time_limit > conf.task_soft_time_limit
    assert "ciphercompute_worker.tasks.execute_job" in app.tasks


@pytest.mark.parametrize(
    ("outcome", "state"),
    [(Outcome("succeeded"), "SUCCESS"), (Outcome("noop", "x"), "SUCCESS"), (Outcome("failed", "y"), "SUCCESS")],
)
def test_task_returns_terminal_outcomes(monkeypatch: pytest.MonkeyPatch, outcome: Outcome, state: str) -> None:
    async def fake_run(job_id: uuid.UUID, org: uuid.UUID) -> Outcome:
        return outcome

    monkeypatch.setattr(tasks, "_run", fake_run)
    job_id = str(uuid.uuid4())
    result = tasks.execute_job.apply(args=[job_id, str(uuid.uuid4())])
    assert result.state == state
    assert result.result == {"job_id": job_id, "outcome": outcome.kind, "detail": outcome.detail}


@pytest.mark.parametrize("kind", ["retry", "throttled"])
def test_task_retries_with_countdown(monkeypatch: pytest.MonkeyPatch, kind: str) -> None:
    async def fake_run(job_id: uuid.UUID, org: uuid.UUID) -> Outcome:
        return Outcome(kind, "later", countdown=7.5)  # type: ignore[arg-type]

    monkeypatch.setattr(tasks, "_run", fake_run)
    seen: dict[str, float] = {}

    def fake_retry(countdown: float, **_: object) -> Exception:
        seen["countdown"] = countdown
        return RuntimeError("retry scheduled")

    task = app.tasks["ciphercompute_worker.tasks.execute_job"]  # the real task behind the proxy
    monkeypatch.setattr(task, "retry", fake_retry)
    with pytest.raises(RuntimeError, match="retry scheduled"):
        task.run(str(uuid.uuid4()), str(uuid.uuid4()))
    assert seen == {"countdown": 7.5}


def test_process_init_starts_metrics_and_tracing(monkeypatch: pytest.MonkeyPatch) -> None:
    from ciphercompute_worker import celery_app, tracing

    started: list[int] = []
    monkeypatch.setattr(celery_app, "start_http_server", lambda port, registry: started.append(port))
    monkeypatch.setattr(celery_app, "configure_logging", lambda *a, **k: None)
    celery_app._init_process()
    assert started == [celery_app.settings.metrics_port]
    assert tracing.tracer_provider(celery_app.settings) is tracing.tracer_provider(celery_app.settings)
    celery_app._shutting_down(sig="SIGTERM", how="warm")


def test_tracer_exports_when_endpoint_configured(monkeypatch: pytest.MonkeyPatch) -> None:
    from ciphercompute_worker import tracing
    from ciphercompute_worker.config import WorkerSettings

    monkeypatch.setattr(tracing, "_provider", None)
    provider = tracing.tracer_provider(
        WorkerSettings(otel_exporter_otlp_endpoint="http://otel-collector:4318/v1/traces")
    )
    assert provider._active_span_processor._span_processors  # an exporter is attached
    monkeypatch.setattr(tracing, "_provider", None)


def test_main_starts_single_slot_worker(monkeypatch: pytest.MonkeyPatch) -> None:
    from ciphercompute_worker import celery_app

    argv: list[list[str]] = []
    monkeypatch.setattr(celery_app.app, "worker_main", lambda args: argv.append(args))
    monkeypatch.setattr(celery_app.sys, "argv", ["ciphercompute-worker", "--hostname=w1"])
    celery_app.main()
    assert argv == [["worker", "--loglevel=INFO", "--concurrency=1", "--prefetch-multiplier=1", "--hostname=w1"]]
