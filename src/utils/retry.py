"""Retry utilities for EAIP API calls.

Provides configurable retry logic with exponential backoff for transient
HTTP errors, rate-limit handling, and connection failures. Built on top
of :pypi:`tenacity` and :pypi:`httpx`.
"""

from __future__ import annotations

import functools
from collections.abc import Callable
from typing import Any, ParamSpec, TypeVar

import httpx
import structlog
from tenacity import (
    RetryCallState,
    retry,
    retry_if_exception,
    stop_after_attempt,
    wait_random_exponential,
)

logger = structlog.get_logger(__name__)

P = ParamSpec("P")
T = TypeVar("T")

# HTTP status codes that warrant an automatic retry.
_RETRYABLE_STATUS_CODES: frozenset[int] = frozenset({429, 500, 502, 503, 504})


class RetryableError(Exception):
    """An error that signals the caller should retry after a delay.

    Attributes:
        retry_after_seconds: Suggested number of seconds to wait before
            the next attempt.  May be ``None`` if no ``Retry-After``
            header was present.
    """

    def __init__(
        self,
        message: str = "Retryable error encountered",
        *,
        retry_after_seconds: float | None = None,
    ) -> None:
        super().__init__(message)
        self.retry_after_seconds: float | None = retry_after_seconds


def _is_retryable(exc: BaseException) -> bool:
    """Return ``True`` when *exc* represents a transient failure."""
    if isinstance(exc, (ConnectionError, TimeoutError, RetryableError)):
        return True
    if isinstance(exc, httpx.HTTPStatusError):
        return exc.response.status_code in _RETRYABLE_STATUS_CODES
    return False


def _log_before_sleep(retry_state: RetryCallState) -> None:
    """Emit a warning log entry before tenacity sleeps between attempts."""
    exception = retry_state.outcome.exception() if retry_state.outcome else None
    wait_seconds = retry_state.next_action.sleep if retry_state.next_action else 0  # type: ignore[union-attr]
    logger.warning(
        "retry_before_sleep",
        attempt=retry_state.attempt_number,
        wait_seconds=round(wait_seconds, 2),
        exception_type=type(exception).__name__ if exception else None,
        exception_message=str(exception) if exception else None,
    )


def api_retry(
    fn: Callable[P, T] | None = None,
    *,
    max_attempts: int = 5,
    multiplier: float = 1,
    wait_min: float = 2,
    wait_max: float = 60,
) -> Callable[P, T] | Callable[[Callable[P, T]], Callable[P, T]]:
    """Decorator that adds retry logic to an async (or sync) API call.

    By default the decorated function will be retried up to 5 times on:

    * :class:`ConnectionError`
    * :class:`TimeoutError`
    * :class:`httpx.HTTPStatusError` with a ``429`` or ``5xx`` status code
    * :class:`RetryableError`

    The wait strategy is random exponential back-off (jitter) bounded
    between *wait_min* and *wait_max* seconds.

    The decorator can be used with or without arguments::

        @api_retry
        async def fetch(url: str) -> dict: ...

        @api_retry(max_attempts=10, wait_max=120)
        async def resilient_fetch(url: str) -> dict: ...

    Args:
        fn: The function to wrap (set automatically when the decorator
            is used without parentheses).
        max_attempts: Maximum number of attempts before giving up.
        multiplier: Multiplier for the exponential back-off.
        wait_min: Minimum wait time in seconds.
        wait_max: Maximum wait time in seconds.

    Returns:
        The decorated function with retry behaviour.
    """

    decorator = retry(
        retry=retry_if_exception(_is_retryable),
        wait=wait_random_exponential(multiplier=multiplier, min=wait_min, max=wait_max),
        stop=stop_after_attempt(max_attempts),
        before_sleep=_log_before_sleep,
        reraise=True,
    )

    if fn is not None:
        # Called without parentheses: @api_retry
        return decorator(fn)  # type: ignore[return-value]

    # Called with parentheses: @api_retry(...)
    def wrapper(func: Callable[P, T]) -> Callable[P, T]:
        return decorator(func)  # type: ignore[return-value]

    return wrapper  # type: ignore[return-value]


def handle_retry_after(response: httpx.Response) -> None:
    """Inspect the ``Retry-After`` header and raise if present.

    If the response carries a ``Retry-After`` header (typically
    accompanying a ``429 Too Many Requests`` status), this function
    parses the value and raises a :class:`RetryableError` so that
    the :func:`api_retry` decorator can honour the requested delay.

    Args:
        response: The HTTP response to inspect.

    Raises:
        RetryableError: When the ``Retry-After`` header is present.
    """
    retry_after_raw: str | None = response.headers.get("Retry-After")
    if retry_after_raw is None:
        return

    try:
        retry_after_seconds = float(retry_after_raw)
    except (ValueError, TypeError):
        # RFC 7231 §7.1.3 also allows an HTTP-date, but Microsoft APIs
        # overwhelmingly use the delta-seconds form.  Fall back to a
        # sensible default when parsing fails.
        logger.warning(
            "retry_after_parse_failed",
            raw_value=retry_after_raw,
        )
        retry_after_seconds = 30.0

    logger.info(
        "retry_after_detected",
        status_code=response.status_code,
        retry_after_seconds=retry_after_seconds,
    )
    raise RetryableError(
        f"Server requested retry after {retry_after_seconds}s "
        f"(HTTP {response.status_code})",
        retry_after_seconds=retry_after_seconds,
    )
