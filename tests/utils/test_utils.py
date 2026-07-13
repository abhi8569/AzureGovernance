"""Tests for utility modules: id_generator, rate_limiter."""
from __future__ import annotations

import time

import pytest

from src.utils.id_generator import generate_surrogate_key, generate_composite_key
from src.utils.rate_limiter import RateLimiter


class TestGenerateSurrogateKey:
    """Tests for deterministic surrogate key generation."""

    def test_deterministic(self) -> None:
        """Same inputs always produce the same key."""
        key1 = generate_surrogate_key("entra", "user-001")
        key2 = generate_surrogate_key("entra", "user-001")
        assert key1 == key2

    def test_different_sources(self) -> None:
        """Different sources produce different keys."""
        k1 = generate_surrogate_key("entra", "obj-1")
        k2 = generate_surrogate_key("azure", "obj-1")
        assert k1 != k2

    def test_different_ids(self) -> None:
        """Different object IDs produce different keys."""
        k1 = generate_surrogate_key("entra", "obj-1")
        k2 = generate_surrogate_key("entra", "obj-2")
        assert k1 != k2

    def test_returns_int(self) -> None:
        """Key should be a Python int."""
        key = generate_surrogate_key("test", "value")
        assert isinstance(key, int)

    def test_no_collision_similar_inputs(self) -> None:
        """Similar but different inputs should not collide."""
        keys = set()
        for i in range(1000):
            keys.add(generate_surrogate_key("test", f"id-{i}"))
        assert len(keys) == 1000


class TestGenerateCompositeKey:
    """Tests for composite key generation."""

    def test_basic(self) -> None:
        """Test composite key from multiple parts."""
        key = generate_composite_key("a", "b", "c")
        assert isinstance(key, int)

    def test_deterministic(self) -> None:
        """Same parts produce same key."""
        k1 = generate_composite_key("x", "y", "z")
        k2 = generate_composite_key("x", "y", "z")
        assert k1 == k2

    def test_order_matters(self) -> None:
        """Different order produces different key."""
        k1 = generate_composite_key("a", "b")
        k2 = generate_composite_key("b", "a")
        assert k1 != k2


class TestRateLimiter:
    """Tests for async rate limiter."""

    @pytest.mark.asyncio
    async def test_no_delay_within_burst(self) -> None:
        """Acquiring within burst should not delay."""
        limiter = RateLimiter(rate=100.0, burst=10)
        start = time.monotonic()
        for _ in range(5):
            await limiter.acquire()
        elapsed = time.monotonic() - start
        assert elapsed < 0.5

    @pytest.mark.asyncio
    async def test_delay_when_exhausted(self) -> None:
        """Should delay when tokens are exhausted."""
        limiter = RateLimiter(rate=10.0, burst=2)
        await limiter.acquire(2)
        start = time.monotonic()
        await limiter.acquire(1)
        elapsed = time.monotonic() - start
        assert elapsed >= 0.05
