"""OpenTelemetry for the worker; trace context arrives in Celery message headers from the API."""

from __future__ import annotations

from opentelemetry import trace
from opentelemetry.sdk.resources import SERVICE_NAME, SERVICE_VERSION, Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.sdk.trace.sampling import ParentBased, TraceIdRatioBased

from .config import WorkerSettings

_provider: TracerProvider | None = None


def tracer_provider(settings: WorkerSettings) -> TracerProvider:
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
    return _provider
