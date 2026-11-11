"""Hand-off from the API to the worker queue.

The API never imports the worker: it sends the task by name. The Celery ``task_id`` is the job
id, so a re-sent message for the same job is recognisable end to end.
"""

from __future__ import annotations

import asyncio
import uuid
from typing import Protocol

from .config import Settings


class JobQueue(Protocol):
    async def enqueue(self, job_id: uuid.UUID, organization_id: uuid.UUID) -> None: ...

    async def ping(self) -> bool: ...


class CeleryQueue:
    def __init__(self, settings: Settings) -> None:
        from celery import Celery

        self._task_name = settings.celery_task_name
        self._app = Celery("ciphercompute-api", broker=settings.broker_url)
        self._app.conf.update(task_serializer="json", accept_content=["json"], broker_connection_retry_on_startup=True)

    async def enqueue(self, job_id: uuid.UUID, organization_id: uuid.UUID) -> None:
        def _send() -> None:
            self._app.send_task(
                self._task_name,
                args=[str(job_id)],
                kwargs={"organization_id": str(organization_id)},
                task_id=str(job_id),
            )

        await asyncio.to_thread(_send)

    async def ping(self) -> bool:
        def _ping() -> bool:
            with self._app.connection_for_write() as conn:
                conn.ensure_connection(max_retries=1)
            return True

        try:
            return await asyncio.to_thread(_ping)
        except Exception:
            return False


class MemoryQueue:
    """In-process queue for tests and single-process demos."""

    def __init__(self) -> None:
        self.items: list[tuple[uuid.UUID, uuid.UUID]] = []
        self.fail_next = False

    async def enqueue(self, job_id: uuid.UUID, organization_id: uuid.UUID) -> None:
        if self.fail_next:
            self.fail_next = False
            raise ConnectionError("broker unavailable")
        self.items.append((job_id, organization_id))

    async def ping(self) -> bool:
        return True


def make_queue(settings: Settings) -> JobQueue:
    if settings.queue_backend == "memory":
        return MemoryQueue()
    return CeleryQueue(settings)
