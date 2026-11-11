"""Fixed-window rate limiting in Redis, per principal (or per IP before authentication)."""

from __future__ import annotations

import time

from redis.asyncio import Redis

from .errors import RateLimitedError


class RateLimiter:
    def __init__(self, redis: Redis, default_limit_per_minute: int) -> None:
        self._redis = redis
        self._default = default_limit_per_minute

    async def check(self, identity: str, *, limit: int | None = None, bucket: str = "api") -> int:
        """Count one request; raise ``RateLimitedError`` beyond ``limit`` per minute.

        Returns the remaining allowance.
        """
        limit = limit or self._default
        now = int(time.time())
        window = now - now % 60
        key = f"rl:{bucket}:{identity}:{window}"
        count = await self._redis.incr(key)
        if count == 1:
            await self._redis.expire(key, 60)
        if count > limit:
            # [TM:D-3] Over-limit callers get 429 + Retry-After and do no further work.
            raise RateLimitedError("rate limit exceeded", retry_after=window + 60 - now, limit=limit)
        return limit - int(count)
