"""Token bucket rate limiter for API calls."""
from __future__ import annotations

import asyncio
import time

import structlog

logger = structlog.get_logger(__name__)


class RateLimiter:
    """Async token bucket rate limiter.

    Controls the rate of API calls to stay within service limits.

    Args:
        rate: Tokens added per second.
        burst: Maximum tokens available (bucket capacity).
    """

    def __init__(self, rate: float, burst: int) -> None:
        self.rate = rate
        self.burst = burst
        self._tokens = float(burst)
        self._last_refill = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self, tokens: int = 1) -> None:
        """Acquire tokens, waiting if necessary.

        Args:
            tokens: Number of tokens to consume.
        """
        async with self._lock:
            while True:
                self._refill()
                if self._tokens >= tokens:
                    self._tokens -= tokens
                    return
                # Calculate wait time for enough tokens
                deficit = tokens - self._tokens
                wait_time = deficit / self.rate
                logger.debug("rate_limit_wait", wait_seconds=round(wait_time, 2))
                await asyncio.sleep(wait_time)

    def _refill(self) -> None:
        """Refill tokens based on elapsed time."""
        now = time.monotonic()
        elapsed = now - self._last_refill
        self._tokens = min(self.burst, self._tokens + elapsed * self.rate)
        self._last_refill = now


# Pre-configured rate limiters for each API
GRAPH_RATE_LIMITER = RateLimiter(rate=100.0, burst=200)
ARM_RATE_LIMITER = RateLimiter(rate=50.0, burst=100)
FABRIC_RATE_LIMITER = RateLimiter(rate=20.0, burst=40)
POWERBI_RATE_LIMITER = RateLimiter(rate=20.0, burst=40)
DEVOPS_RATE_LIMITER = RateLimiter(rate=30.0, burst=60)
