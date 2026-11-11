"""Prometheus metrics and OpenTelemetry tracing."""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI
from opentelemetry import trace
from opentelemetry.sdk.resources import SERVICE_NAME, SERVICE_VERSION, Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.sdk.trace.sampling import ParentBased, TraceIdRatioBased
from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram

from .config import Settings

registry = CollectorRegistry(auto_describe=True)

HTTP_REQUESTS = Counter(
    "ciphercompute_http_requests_total", "HTTP requests", ["method", "route", "status"], registry=registry
)
HTTP_LATENCY = Histogram(
    "ciphercompute_http_request_duration_seconds",
    "HTTP request latency",
    ["method", "route"],
    registry=registry,
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10),
)
JOBS_SUBMITTED = Counter(
    "ciphercompute_jobs_submitted_total",
    "Jobs accepted for execution",
    ["operation", "organization"],
    registry=registry,
)
JOBS_REFUSED = Counter("ciphercompute_jobs_refused_total", "Jobs refused before enqueue", ["reason"], registry=registry)
CIPHERTEXT_BYTES = Histogram(
    "ciphercompute_ciphertext_bytes",
    "Size of confirmed ciphertext uploads",
    registry=registry,
    buckets=(64e3, 256e3, 1e6, 4e6, 16e6, 64e6),
)
BUNDLE_BYTES = Histogram(
    "ciphercompute_key_bundle_bytes",
    "Size of confirmed key bundle uploads",
    registry=registry,
    buckets=(16e6, 64e6, 256e6, 1e9, 4e9),
)
QUEUE_DEPTH = Gauge("ciphercompute_queue_depth", "Jobs in QUEUED state", registry=registry)
AUDIT_CHAIN_VALID = Gauge(
    "ciphercompute_audit_chain_valid",
    "1 when the last verification of an org chain passed",
    ["organization"],
    registry=registry,
)


_provider: TracerProvider | None = None


def tracer_provider(settings: Settings) -> TracerProvider:
    """Process-wide provider; exports to OTLP/HTTP only when an endpoint is configured."""
    global _provider
    if _provider is None:
        resource = Resource.create(
            {
                SERVICE_NAME: settings.service_name,
                SERVICE_VERSION: settings.version,
                "deployment.environment": settings.env,
            }
        )
        _provider = TracerProvider(
            resource=resource, sampler=ParentBased(TraceIdRatioBased(settings.otel_sample_ratio))
        )
        if settings.otel_exporter_otlp_endpoint:
            from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

            _provider.add_span_processor(
                BatchSpanProcessor(OTLPSpanExporter(endpoint=settings.otel_exporter_otlp_endpoint))
            )
        trace.set_tracer_provider(_provider)
        from opentelemetry.instrumentation.redis import RedisInstrumentor

        RedisInstrumentor().instrument(tracer_provider=_provider)
    return _provider


def instrument_app(app: FastAPI, settings: Settings) -> None:
    """Must run before the app starts (it adds ASGI middleware)."""
    from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor

    FastAPIInstrumentor.instrument_app(
        app, tracer_provider=tracer_provider(settings), excluded_urls="healthz,readyz,metrics"
    )


def instrument_engine(engine: Any, settings: Settings) -> None:
    from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor

    SQLAlchemyInstrumentor().instrument(engine=engine, tracer_provider=tracer_provider(settings))


def current_trace_id() -> str | None:
    span = trace.get_current_span()
    ctx = span.get_span_context()
    if ctx is None or not ctx.is_valid:
        return None
    return format(ctx.trace_id, "032x")
