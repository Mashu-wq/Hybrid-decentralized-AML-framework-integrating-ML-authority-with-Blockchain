"""
Structured logging configuration for the ML service.
Uses structlog with JSON output, mirroring the zerolog format used by Go services.
Call configure_logging() once at service startup before any other imports.
"""
from __future__ import annotations

import logging
import sys
from typing import Any

import structlog
from structlog.types import EventDict, Processor


def _drop_pii_processor(
    logger: Any, method: str, event_dict: EventDict  # noqa: ANN401
) -> EventDict:
    """Scrub known PII field names from log entries.

    This is a safety net — services should never log PII in the first place.
    If a PII field appears, it is replaced with '[REDACTED]'.
    """
    PII_KEYS = {
        "full_name", "name", "date_of_birth", "dob", "ssn", "passport",
        "email", "phone", "phone_number", "address", "document_number",
        "plaintext", "password", "secret", "private_key", "token",
    }
    for key in list(event_dict.keys()):
        if key.lower() in PII_KEYS:
            event_dict[key] = "[REDACTED]"
    return event_dict


def configure_logging(level: str = "info", pretty: bool = False) -> None:
    """Configure structlog for structured JSON logging.

    Args:
        level:  Log level string ("debug", "info", "warn", "error").
        pretty: If True, use colored human-readable output (local dev only).
    """
    log_level = getattr(logging, level.upper(), logging.INFO)

    shared_processors: list[Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.stdlib.add_logger_name,
        _drop_pii_processor,
        structlog.processors.StackInfoRenderer(),
        structlog.processors.ExceptionRenderer(),
    ]

    if pretty:
        renderer: Processor = structlog.dev.ConsoleRenderer(colors=True)
    else:
        renderer = structlog.processors.JSONRenderer()

    structlog.configure(
        processors=shared_processors + [renderer],
        wrapper_class=structlog.make_filtering_bound_logger(log_level),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(sys.stdout),
        cache_logger_on_first_use=True,
    )

    # Also configure stdlib logging so third-party libraries (uvicorn, grpc) use structlog
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=log_level,
    )
    logging.getLogger("uvicorn.access").handlers = []
    logging.getLogger("grpc").setLevel(logging.WARNING)


def get_logger(name: str) -> structlog.BoundLogger:
    """Get a bound logger for a module. Usage: log = get_logger(__name__)"""
    return structlog.get_logger(name)
