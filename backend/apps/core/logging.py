"""Structured logging configuration (structlog + standard library ``logging``).

- Application code logs with ``structlog.get_logger(__name__)`` using event names and key/value
  pairs; Django's and third-party standard-library logs go through the same pipeline.
- Output is JSON in production (one object per line) and human-readable in development.
- Every entry carries the request context (``request_id``; later ``user_id``/``organization_id``).
- Values under sensitive keys (passwords, tokens, cookies, authorization headers, secrets...) are
  replaced with ``[REDACTED]``; messages and rendered tracebacks are text-sanitized (see
  :mod:`apps.core.sanitization`). Code must still never log raw request headers, query strings or
  bodies; redaction is a safety net, not a licence.
"""

import logging
from typing import Any, Literal

import structlog
from structlog.typing import EventDict, Processor, WrappedLogger

from .sanitization import (
    REDACTED,
    is_sensitive_key,
    redact_structure,
    sanitize_text,
)

LogFormat = Literal["json", "console"]
LOG_FORMATS: tuple[LogFormat, ...] = ("json", "console")


def redact_sensitive_values(
    logger: WrappedLogger, method_name: str, event_dict: EventDict
) -> EventDict:
    """structlog processor: redact sensitive keys (recursively, bounded) and scrub free text.

    The ``event`` message is text-sanitized (credentials in URLs, ``password=...`` pairs, bearer
    tokens...); values under sensitive keys become ``[REDACTED]``; nested structures are copied
    with bounded depth/size and cycle detection (see :mod:`apps.core.sanitization`).
    ``exc_info`` is left for :func:`sanitize_exception` after the traceback is rendered.
    """
    for key in list(event_dict):
        value = event_dict[key]
        if key == "exc_info":
            continue
        if key == "event":
            event_dict[key] = sanitize_text(value) if isinstance(value, str) else value
        elif is_sensitive_key(key):
            event_dict[key] = REDACTED
        else:
            event_dict[key] = redact_structure(value)
    return event_dict


def sanitize_exception(logger: WrappedLogger, method_name: str, event_dict: EventDict) -> EventDict:
    """Formatter processor: scrub the rendered traceback (runs after ``format_exc_info``).

    Tracebacks are rendered without local variables; exception messages can still embed
    credentials (e.g. database errors, URLs), so the text is sanitized before output.
    """
    exception = event_dict.get("exception")
    if isinstance(exception, str):
        event_dict["exception"] = sanitize_text(exception)
    return event_dict


PATH_REDACTED = "[path redacted]"


class RedactRequestPathFilter(logging.Filter):
    """Remove raw request paths/query strings from Django's own request log records.

    ``django.request`` logs ``"<reason>: <request.path>"`` for every 4xx/5xx response and the
    development server (``django.server``) logs the full request line including the query string.
    Paths and query strings can carry secrets (e.g. one-time tokens), so they are redacted here;
    the access log records the matched route pattern instead (see ``apps.core.middleware``).
    """

    def filter(self, record: logging.LogRecord) -> bool:
        args = record.args
        if not isinstance(args, tuple) or not args:
            return True
        if record.name == "django.request" and len(args) >= 2:  # noqa: PLR2004
            record.args = (args[0], PATH_REDACTED, *args[2:])
        elif record.name == "django.server":
            method = str(args[0]).split(" ", 1)[0]
            record.args = (f"{method} {PATH_REDACTED}", *args[1:])
        return True


def shared_processors() -> list[Processor]:
    """Processors applied to both structlog and standard-library log records."""
    return [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        redact_sensitive_values,
    ]


def configure_structlog() -> None:
    """Route structlog through the standard library so Django's LOGGING settings apply."""
    structlog.configure(
        processors=[
            *shared_processors(),
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.StackInfoRenderer(),
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )


def build_formatter(log_format: LogFormat) -> structlog.stdlib.ProcessorFormatter:
    """Return the formatter used by log handlers for the given output format."""
    renderer: Processor
    if log_format == "json":
        renderer = structlog.processors.JSONRenderer(sort_keys=True)
    else:
        renderer = structlog.dev.ConsoleRenderer(colors=False)
    return structlog.stdlib.ProcessorFormatter(
        foreign_pre_chain=shared_processors(),
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            structlog.processors.format_exc_info,
            sanitize_exception,
            renderer,
        ],
    )


def build_logging_config(*, level: str, log_format: LogFormat) -> dict[str, Any]:
    """Return a ``LOGGING`` dict for Django settings."""
    if log_format not in LOG_FORMATS:
        msg = f"Unsupported log format {log_format!r}; expected one of {LOG_FORMATS}."
        raise ValueError(msg)
    return {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "structured": {
                "()": build_formatter,
                "log_format": log_format,
            },
        },
        "filters": {
            "redact_request_path": {"()": RedactRequestPathFilter},
        },
        "handlers": {
            "console": {"class": "logging.StreamHandler", "formatter": "structured"},
        },
        "root": {"handlers": ["console"], "level": level},
        "loggers": {
            "django": {"handlers": [], "level": level, "propagate": True},
            "django.request": {
                "handlers": [],
                "level": level,
                "propagate": True,
                "filters": ["redact_request_path"],
            },
            "django.server": {
                "handlers": [],
                "level": level,
                "propagate": True,
                "filters": ["redact_request_path"],
            },
            # Never emit SQL statements (they can contain sensitive parameters), even with DEBUG.
            "django.db.backends": {"handlers": [], "level": "WARNING", "propagate": True},
        },
    }
