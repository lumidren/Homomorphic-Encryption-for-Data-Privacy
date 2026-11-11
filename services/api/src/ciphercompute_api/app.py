"""Application factory.

Run in production with::

    gunicorn 'ciphercompute_api.app:create_app()' -k uvicorn.workers.UvicornWorker --graceful-timeout 30

``SIGTERM`` flips the app into *draining*: ``/readyz`` turns 503 so the load balancer stops
routing new requests while in-flight ones finish (zero-downtime rolling deploys).
"""

from __future__ import annotations

import secrets
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from redis.asyncio import Redis

from . import __version__
from .auth.passwords import PasswordService
from .auth.tokens import TokenService
from .config import Settings, get_settings
from .db.base import make_engine, make_session_factory
from .deps import AppState
from .errors import PayloadTooLargeError, envelope, install_exception_handlers
from .logging import configure_logging, get_logger
from .queue import JobQueue, make_queue
from .ratelimit import RateLimiter
from .routers import (
    api_keys,
    audit,
    auth,
    catalog,
    ciphertexts,
    datasets,
    health,
    jobs,
    keys,
    organization,
    projects,
    usage,
)
from .storage.objects import ObjectStore
from .telemetry import HTTP_LATENCY, HTTP_REQUESTS, instrument_app, instrument_engine

log = get_logger(__name__)

#: Bodies on every route except the bundle upload are small JSON documents.
MAX_JSON_BODY = 1024 * 1024
_STREAMING_UPLOAD_SUFFIX = "/key-bundles"

DESCRIPTION = """
CipherCompute computes statistics and model inference on **CKKS-encrypted** data.
The server holds public, relinearization and Galois keys only — it cannot decrypt anything.

* Authenticate with `Authorization: Bearer <access token>` (from `/v1/auth/login`) or
  `Authorization: Bearer cc_…` (an API key).
* Every error has the shape `{"error": {"code", "message", "details", "request_id"}}`.
* Jobs whose multiplicative depth exceeds the key bundle's parameters are refused with
  `422 depth_exhausted`, and `details.suggested_params` names a set that would work.
"""


def create_app(
    settings: Settings | None = None,
    *,
    redis: Redis | None = None,
    store: ObjectStore | None = None,
    queue: JobQueue | None = None,
) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(settings.log_level, json=settings.env != "dev")

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        engine = make_engine(settings.database_url, pool_size=settings.database_pool_size)
        instrument_engine(engine.sync_engine, settings)
        redis_client = redis or Redis.from_url(settings.redis_url)
        state = AppState(
            settings=settings,
            engine=engine,
            session_factory=make_session_factory(engine),
            redis=redis_client,
            store=store or ObjectStore(settings),
            queue=queue or make_queue(settings),
            tokens=TokenService(settings),
            passwords=PasswordService(settings),
            limiter=RateLimiter(redis_client, settings.rate_limit_per_minute),
        )
        app.state.cc = state
        try:
            await state.store.ensure_bucket()
        except Exception as exc:  # readiness reports it; the process still starts
            log.warning("object_storage_unavailable_at_startup", error=type(exc).__name__)
        log.info("api_started", version=__version__, env=settings.env)
        try:
            yield
        finally:
            state.draining = True
            log.info("api_draining")
            await engine.dispose()
            if redis is None:
                await state.redis.aclose()

    app = FastAPI(
        title="CipherCompute API",
        version=__version__,
        description=DESCRIPTION,
        lifespan=lifespan,
        openapi_tags=[
            {"name": "auth", "description": "Registration, login, token refresh, logout"},
            {"name": "organization", "description": "Organization and membership (RBAC)"},
            {"name": "projects"},
            {"name": "key-bundles", "description": "Public key bundles (never secret keys)"},
            {"name": "datasets"},
            {"name": "ciphertexts", "description": "Presigned upload, confirmation, download"},
            {"name": "jobs", "description": "Homomorphic computation jobs"},
            {"name": "catalog", "description": "Operations, parameter sets, advisor"},
            {"name": "audit", "description": "Hash-chained audit log"},
            {"name": "api-keys"},
            {"name": "usage"},
            {"name": "health"},
        ],
    )
    install_exception_handlers(app)
    instrument_app(app, settings)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=False,
        allow_methods=["GET", "POST", "PATCH", "DELETE"],
        allow_headers=["Authorization", "Content-Type", "Idempotency-Key", "X-Request-ID"],
        expose_headers=["X-Request-ID", "Retry-After"],
    )

    @app.middleware("http")
    async def request_middleware(request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        incoming = request.headers.get("x-request-id", "")
        request_id = (
            incoming if 8 <= len(incoming) <= 64 and incoming.replace("-", "").isalnum() else secrets.token_hex(12)
        )
        request.state.request_id = request_id
        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(request_id=request_id)
        declared = request.headers.get("content-length")
        if (
            declared is not None
            and declared.isdigit()
            and int(declared) > MAX_JSON_BODY
            and not request.url.path.endswith(_STREAMING_UPLOAD_SUFFIX)
        ):
            err = PayloadTooLargeError("request body too large", limit=MAX_JSON_BODY)
            return JSONResponse(
                status_code=413,
                content=envelope(err.code, err.message, request_id, err.details),
                headers={"X-Request-ID": request_id},
            )
        start = time.perf_counter()
        try:
            response = await call_next(request)
        except Exception:
            # [TM:I-9] Same envelope as the registered handler, but produced here so the 500
            # still carries X-Request-ID and is counted in the metrics.
            log.exception("unhandled_error", path=request.url.path)
            response = JSONResponse(
                status_code=500, content=envelope("internal_error", "an internal error occurred", request_id)
            )
        elapsed = time.perf_counter() - start
        route = request.scope.get("route")
        route_path = getattr(route, "path", "unmatched")
        HTTP_REQUESTS.labels(request.method, route_path, str(response.status_code)).inc()
        HTTP_LATENCY.labels(request.method, route_path).observe(elapsed)
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Frame-Options"] = "DENY"
        if not request.url.path.startswith(("/docs", "/redoc")):
            response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
        if route_path not in {"/healthz", "/readyz", "/metrics"}:
            log.info(
                "request",
                method=request.method,
                route=route_path,
                status=response.status_code,
                duration_ms=round(elapsed * 1000, 2),
            )
        return response

    for module in (
        health,
        auth,
        organization,
        projects,
        keys,
        datasets,
        ciphertexts,
        jobs,
        catalog,
        audit,
        api_keys,
        usage,
    ):
        app.include_router(module.router)
    return app
