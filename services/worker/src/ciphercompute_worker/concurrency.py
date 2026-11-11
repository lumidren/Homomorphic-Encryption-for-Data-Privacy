"""Per-organization weighted semaphore in Redis.

Each running job holds a *lease* (a sorted-set member scored by its expiry). Expired leases are
dropped on every acquire, so a worker that dies mid-job cannot starve its tenant forever. The
check-and-add is an optimistic transaction (``WATCH``/``MULTI``) so two workers cannot both take
the last slot.
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Final

from redis.asyncio import Redis
from redis.exceptions import WatchError

#: Larger rings cost more CPU and memory; they count more against the tenant's budget.
WEIGHT_BY_DEGREE: Final = {8192: 1, 16384: 2, 32768: 4}


def _text(member: Any) -> str:
    return member.decode() if isinstance(member, bytes) else str(member)


def job_weight(poly_modulus_degree: int) -> int:
    return WEIGHT_BY_DEGREE.get(int(poly_modulus_degree), 4)


class TenantSemaphore:
    def __init__(self, redis: Redis, limit: int, lease_seconds: int) -> None:
        self._redis = redis
        self._limit = limit
        self._lease = lease_seconds

    @staticmethod
    def key(organization_id: uuid.UUID) -> str:
        return f"tenant:{organization_id}:running"

    @staticmethod
    def _member(job_id: uuid.UUID, weight: int) -> str:
        return f"{job_id}:{weight}"

    async def in_use(self, organization_id: uuid.UUID) -> int:
        members = await self._redis.zrangebyscore(self.key(organization_id), time.time(), "+inf")
        return sum(int(_text(m).rsplit(":", 1)[1]) for m in members)

    async def acquire(self, organization_id: uuid.UUID, job_id: uuid.UUID, weight: int) -> bool:
        """Take ``weight`` units for ``job_id``; False when the tenant is at its limit.

        A single job heavier than the whole limit is admitted when nothing else runs, so large
        rings are throttled rather than starved.
        """
        # [TM:D-4] One tenant's burst cannot occupy every worker: excess jobs wait in the queue.
        key = self.key(organization_id)
        member = self._member(job_id, weight)
        async with self._redis.pipeline(transaction=True) as pipe:
            while True:
                try:
                    await pipe.watch(key)
                    now = time.time()
                    await pipe.zremrangebyscore(key, "-inf", now)
                    members = await pipe.zrange(key, 0, -1)
                    held = {_text(m) for m in members}
                    if member in held:
                        await pipe.unwatch()  # type: ignore[no-untyped-call]
                        return True  # redelivery of a job that already holds its slot
                    used = sum(int(m.rsplit(":", 1)[1]) for m in held)
                    if used and used + weight > self._limit:
                        await pipe.unwatch()  # type: ignore[no-untyped-call]
                        return False
                    pipe.multi()  # type: ignore[no-untyped-call]
                    pipe.zadd(key, {member: now + self._lease})
                    pipe.expire(key, self._lease)
                    await pipe.execute()
                    return True
                except WatchError:
                    continue

    async def release(self, organization_id: uuid.UUID, job_id: uuid.UUID, weight: int) -> None:
        await self._redis.zrem(self.key(organization_id), self._member(job_id, weight))
