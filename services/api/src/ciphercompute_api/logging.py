"""Structured JSON logging with mandatory secret scrubbing.

Every log record passes through :func:`scrub_processor` before rendering. It redacts values
under secret-looking keys *and* any value that looks like key material regardless of its key.
The scrubber is a safety net; callers are still forbidden from logging bodies or tokens.
"""

from __future__ import annotations

import logging
import re
import sys
from collections.abc import Mapping, MutableMapping
from typing import Any

import structlog

REDACTED = "[REDACTED]"

_SECRET_KEY_RE = re.compile(
    r"(password|passwd|secret|token|authorization|cookie|api[_-]?key|key[_-]?hash|private|"
    r"bundle|ciphertext|payload|credential|refresh)",
    re.IGNORECASE,
)

#: Value patterns that are redacted wherever they occur. Each is anchored on a recognisable
#: prefix so ordinary words are never touched.
_SECRET_VALUE_PATTERNS = (
    re.compile(r"cc_[A-Za-z0-9]{16,}"),  # API keys
    re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),  # JWTs
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"(?i)bearer\s+[A-Za-z0-9._~+/=-]{16,}"),
    re.compile(r"CCSK[\x00-\xff]{4,}"),  # secret-ring envelope magic
    re.compile(r"AKIA[0-9A-Z]{16}"),  # AWS access key ids
    re.compile(r"(?i)postgres(?:ql)?(?:\+\w+)?://[^:\s]+:[^@\s]+@"),  # DSN passwords
    re.compile(r"(?i)redis://[^:\s]*:[^@\s]+@"),
)


def scrub_value(value: Any) -> Any:
    if isinstance(value, str):
        out = value
        for pattern in _SECRET_VALUE_PATTERNS:
            out = pattern.sub(REDACTED, out)
        return out
    if isinstance(value, bytes | bytearray):
        return f"<{len(value)} bytes>"
    if isinstance(value, Mapping):
        return {
            k: (REDACTED if isinstance(k, str) and _SECRET_KEY_RE.search(k) else scrub_value(v))
            for k, v in value.items()
        }
    if isinstance(value, list | tuple | set):
        return [scrub_value(v) for v in value]
    return value


def scrub_processor(_logger: Any, _method: str, event_dict: MutableMapping[str, Any]) -> MutableMapping[str, Any]:
    # [TM:I-3] Runs on every record, before rendering: secret-looking keys and token-shaped
    # values never reach a sink.
    for key in list(event_dict):
        if isinstance(key, str) and _SECRET_KEY_RE.search(key) and key not in {"event", "logger", "level", "timestamp"}:
            event_dict[key] = REDACTED
        else:
            event_dict[key] = scrub_value(event_dict[key])
    return event_dict


def configure_logging(level: str = "INFO", *, json: bool = True) -> None:
    """Configure structlog + stdlib logging so every line is a single JSON object."""
    shared: list[Any] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        scrub_processor,
    ]
    renderer: Any = structlog.processors.JSONRenderer() if json else structlog.dev.ConsoleRenderer()
    structlog.configure(
        processors=[*shared, structlog.stdlib.ProcessorFormatter.wrap_for_formatter],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=False,
    )
    formatter = structlog.stdlib.ProcessorFormatter(
        foreign_pre_chain=shared, processors=[structlog.stdlib.ProcessorFormatter.remove_processors_meta, renderer]
    )
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level.upper())
    for noisy in ("uvicorn.access", "botocore", "boto3", "urllib3"):
        logging.getLogger(noisy).setLevel(max(logging.WARNING, root.level))


def get_logger(name: str | None = None) -> structlog.stdlib.BoundLogger:
    return structlog.get_logger(name)  # type: ignore[no-any-return]
