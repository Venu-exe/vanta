"""Politeness controls: a token-bucket rate limiter and a per-host concurrency
guard.

Good red-team tooling is *quiet* and *predictable*. Hammering a target gets you
blocked, alerted on, and (on a bounty programme) reported by the very people
you are trying to help. These primitives keep request rates and parallelism
inside bounds the engagement file declares.
"""

from __future__ import annotations

import asyncio
import time
from collections import defaultdict


class TokenBucket:
    """Classic token bucket. ``rate`` tokens/sec, burst up to ``capacity``."""

    def __init__(self, rate: float, capacity: float | None = None) -> None:
        self.rate = max(rate, 0.01)
        self.capacity = capacity if capacity is not None else max(rate, 1.0)
        self._tokens = self.capacity
        self._updated = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self, tokens: float = 1.0) -> None:
        async with self._lock:
            while True:
                now = time.monotonic()
                self._tokens = min(
                    self.capacity, self._tokens + (now - self._updated) * self.rate
                )
                self._updated = now
                if self._tokens >= tokens:
                    self._tokens -= tokens
                    return
                deficit = tokens - self._tokens
                await asyncio.sleep(deficit / self.rate)


class HostLimiter:
    """Combines a global bucket with per-host buckets and a semaphore."""

    def __init__(
        self,
        global_rate: float = 20.0,
        per_host_rate: float = 5.0,
        max_concurrency: int = 10,
    ) -> None:
        self.global_bucket = TokenBucket(global_rate, capacity=max(global_rate, 1.0))
        self.per_host_rate = per_host_rate
        self._host_buckets: dict[str, TokenBucket] = defaultdict(
            lambda: TokenBucket(per_host_rate, capacity=max(per_host_rate, 1.0))
        )
        self.semaphore = asyncio.Semaphore(max_concurrency)

    async def __aenter__(self) -> "HostLimiter":
        await self.semaphore.acquire()
        return self

    async def __aexit__(self, *exc: object) -> None:
        self.semaphore.release()

    async def wait(self, host: str) -> None:
        await self.global_bucket.acquire()
        await self._host_buckets[host].acquire()
