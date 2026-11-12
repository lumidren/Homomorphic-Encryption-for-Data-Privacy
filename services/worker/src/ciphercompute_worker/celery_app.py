"""Celery application.

One job at a time per process (``prefetch_multiplier=1``, ``acks_late``): a worker that is
killed or rolled mid-job leaves its message unacknowledged, so the broker redelivers it and the
executor's claim logic picks it up again. Scale with more processes/pods, not more threads.
"""

from __future__ import annotations

import sys
from typing import Any

from celery import Celery
from celery.signals import worker_process_init, worker_shutting_down
from prometheus_client import start_http_server

from ciphercompute_api.logging import configure_logging, get_logger

from .config import get_settings
from .metrics import registry

settings = get_settings()
log = get_logger(__name__)

app = Celery("ciphercompute-worker", broker=settings.broker_url, include=["ciphercompute_worker.tasks"])
app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_backend=None,
    task_ignore_result=True,
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    worker_prefetch_multiplier=1,
    worker_max_memory_per_child=settings.max_memory_per_child_kib,
    task_soft_time_limit=settings.job_soft_time_limit_seconds,
    task_time_limit=settings.job_hard_time_limit_seconds,
    # Must exceed the hard time limit or Redis redelivers jobs that are still running.
    broker_transport_options={"visibility_timeout": settings.job_hard_time_limit_seconds * 2},
    broker_connection_retry_on_startup=True,
    worker_cancel_long_running_tasks_on_connection_loss=False,
    worker_send_task_events=True,
    task_send_sent_event=True,
)


@worker_process_init.connect
def _init_process(**_: Any) -> None:
    configure_logging(settings.log_level, json=settings.env != "dev")
    start_http_server(settings.metrics_port, registry=registry)
    from opentelemetry.instrumentation.celery import CeleryInstrumentor

    from .tracing import tracer_provider

    CeleryInstrumentor().instrument(tracer_provider=tracer_provider(settings))
    log.info("worker_process_started", metrics_port=settings.metrics_port)


@worker_shutting_down.connect
def _shutting_down(sig: str | None = None, how: str | None = None, **_: Any) -> None:
    # Warm shutdown (SIGTERM): Celery stops consuming and lets the current job finish within the
    # pod's terminationGracePeriodSeconds; unacknowledged work is redelivered elsewhere.
    log.info("worker_shutting_down", signal=sig, how=how)


def main() -> None:
    app.worker_main(["worker", "--loglevel=INFO", "--concurrency=1", "--prefetch-multiplier=1", *sys.argv[1:]])
