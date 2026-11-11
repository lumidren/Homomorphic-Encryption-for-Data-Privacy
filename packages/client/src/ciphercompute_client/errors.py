"""Errors raised by the SDK."""

from __future__ import annotations

from typing import Any


class ApiError(Exception):
    """The server answered with an error envelope ``{"error": {code, message, details, request_id}}``."""

    def __init__(
        self, status_code: int, code: str, message: str, details: Any = None, request_id: str | None = None
    ) -> None:
        super().__init__(f"{status_code} {code}: {message}")
        self.status_code = status_code
        self.code = code
        self.message = message
        self.details = details
        self.request_id = request_id


class KeyStoreError(Exception):
    """A key file is missing, corrupt, has unsafe permissions, or the passphrase is wrong."""
