"""Structured logging setup for EAIP."""
from __future__ import annotations

import logging
import re
import sys

import structlog

# Patterns to redact from logs
_SENSITIVE_PATTERNS = [
    re.compile(r'(eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)'),  # JWT tokens
    re.compile(r'(Bearer\s+)[a-zA-Z0-9_.-]+', re.IGNORECASE),  # Bearer tokens
    re.compile(r'(client_secret["\']?\s*[:=]\s*["\']?)[^"\',\s]+'),  # Client secrets
    re.compile(r'(password["\']?\s*[:=]\s*["\']?)[^"\',\s]+', re.IGNORECASE),  # Passwords
]


def _redact_sensitive_data(
    logger: logging.Logger, method_name: str, event_dict: dict
) -> dict:
    """Structlog processor that redacts sensitive data from log entries."""
    for key, value in event_dict.items():
        if isinstance(value, str):
            for pattern in _SENSITIVE_PATTERNS:
                value = pattern.sub(r'\1[REDACTED]', value)
            event_dict[key] = value
    return event_dict


def setup_logging(log_level: str = "INFO", json_output: bool = False) -> None:
    """Configure structured logging for the application.

    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL).
        json_output: If True, output JSON; otherwise colored console.
    """
    shared_processors: list[structlog.types.Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.UnicodeDecoder(),
        _redact_sensitive_data,
    ]

    if json_output:
        renderer = structlog.processors.JSONRenderer()
    else:
        renderer = structlog.dev.ConsoleRenderer(colors=sys.stderr.isatty())

    structlog.configure(
        processors=[
            *shared_processors,
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    formatter = structlog.stdlib.ProcessorFormatter(
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            renderer,
        ],
    )

    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(formatter)

    root_logger = logging.getLogger()
    root_logger.handlers.clear()
    root_logger.addHandler(handler)
    root_logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))

    # Quiet noisy libraries
    for noisy in ["azure", "msal", "urllib3", "httpx", "httpcore"]:
        logging.getLogger(noisy).setLevel(logging.WARNING)


def get_logger(name: str) -> structlog.stdlib.BoundLogger:
    """Get a named structured logger.

    Args:
        name: Logger name (typically __name__).

    Returns:
        A bound structlog logger.
    """
    return structlog.get_logger(name)
