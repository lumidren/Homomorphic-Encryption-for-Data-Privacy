"""Uniform error envelope and exception handlers.

Every error response has the shape ``{"error": {"code", "message", "details", "request_id"}}``.
Unexpected exceptions become a generic 500 with only a request id — stack traces go to the
logs, never to the client.
"""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette import status

from ciphercompute_core.errors import (
    CipherComputeError,
    DepthExhaustedError,
    InsecureParametersError,
    InvalidArgumentError,
    KeyMismatchError,
    SecretKeyLeakError,
    SerializationError,
    UnsupportedOperationError,
)

from .logging import get_logger

log = get_logger(__name__)


class ApiError(Exception):
    """An error with a stable machine-readable code and an HTTP status."""

    status_code: int = status.HTTP_400_BAD_REQUEST
    code: str = "bad_request"

    def __init__(
        self, message: str, *, status_code: int | None = None, code: str | None = None, **details: Any
    ) -> None:
        super().__init__(message)
        self.message = message
        if status_code is not None:
            self.status_code = status_code
        if code is not None:
            self.code = code
        self.details = details


class NotFoundError(ApiError):
    status_code = status.HTTP_404_NOT_FOUND
    code = "not_found"


class ConflictError(ApiError):
    status_code = status.HTTP_409_CONFLICT
    code = "conflict"


class UnauthorizedError(ApiError):
    status_code = status.HTTP_401_UNAUTHORIZED
    code = "unauthorized"


class ForbiddenError(ApiError):
    status_code = status.HTTP_403_FORBIDDEN
    code = "forbidden"


class RateLimitedError(ApiError):
    status_code = status.HTTP_429_TOO_MANY_REQUESTS
    code = "rate_limited"


class PayloadTooLargeError(ApiError):
    status_code = 413
    code = "payload_too_large"


class UnprocessableError(ApiError):
    status_code = 422
    code = "unprocessable"


_CORE_STATUS: dict[type[CipherComputeError], int] = {
    DepthExhaustedError: 422,
    InsecureParametersError: 422,
    InvalidArgumentError: 422,
    UnsupportedOperationError: 422,
    SerializationError: 422,
    KeyMismatchError: status.HTTP_409_CONFLICT,
    SecretKeyLeakError: 422,
}


def envelope(code: str, message: str, request_id: str | None, details: Any = None) -> dict[str, Any]:
    body: dict[str, Any] = {"code": code, "message": message, "request_id": request_id}
    if details:
        body["details"] = details
    return {"error": body}


def _request_id(request: Request) -> str | None:
    return getattr(request.state, "request_id", None)


def install_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(ApiError)
    async def _api_error(request: Request, exc: ApiError) -> JSONResponse:
        headers = {"Retry-After": str(exc.details["retry_after"])} if exc.code == "rate_limited" else None
        return JSONResponse(
            status_code=exc.status_code,
            content=envelope(exc.code, exc.message, _request_id(request), exc.details),
            headers=headers,
        )

    @app.exception_handler(CipherComputeError)
    async def _core_error(request: Request, exc: CipherComputeError) -> JSONResponse:
        status_code = _CORE_STATUS.get(type(exc), 422)
        if isinstance(exc, SecretKeyLeakError):
            log.warning("secret_key_rejected", code=exc.code)
        return JSONResponse(
            status_code=status_code, content=envelope(exc.code, exc.message, _request_id(request), exc.details)
        )

    @app.exception_handler(RequestValidationError)
    async def _validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
        details = [{"loc": list(e.get("loc", ())), "msg": e.get("msg"), "type": e.get("type")} for e in exc.errors()]
        return JSONResponse(
            status_code=422,
            content=envelope("validation_error", "request validation failed", _request_id(request), details),
        )

    @app.exception_handler(HTTPException)
    async def _http_error(request: Request, exc: HTTPException) -> JSONResponse:
        code = {401: "unauthorized", 403: "forbidden", 404: "not_found", 405: "method_not_allowed"}.get(
            exc.status_code, "http_error"
        )
        return JSONResponse(
            status_code=exc.status_code,
            content=envelope(code, str(exc.detail), _request_id(request)),
            headers=getattr(exc, "headers", None),
        )

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception) -> JSONResponse:
        # Fallback for errors raised outside the request middleware (e.g. in lifespan hooks).
        log.exception("unhandled_error", request_id=_request_id(request), path=request.url.path)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content=envelope("internal_error", "an internal error occurred", _request_id(request)),
        )
