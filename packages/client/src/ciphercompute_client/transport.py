"""HTTP transport: TLS 1.3 only, certificate verification on, optional mutual TLS, polite retries."""

from __future__ import annotations

import random
import ssl
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import httpx

from .errors import ApiError

RETRY_STATUSES = frozenset({429, 502, 503, 504})


@dataclass(frozen=True)
class TransportConfig:
    """How the SDK talks to the server.

    Attributes:
        ca_file: Extra CA bundle (private PKI); system trust store otherwise.
        client_cert / client_key: PEM files for mutual TLS (terminated at Nginx).
        allow_insecure_http: Permit plain ``http://`` — only for localhost development.
        timeout: Seconds per request; uploads of large bundles get ``upload_timeout``.
        max_retries: Retries for 429/502/503/504 and connection errors, honouring ``Retry-After``.
    """

    ca_file: str | None = None
    client_cert: str | None = None
    client_key: str | None = None
    allow_insecure_http: bool = False
    timeout: float = 30.0
    upload_timeout: float = 600.0
    max_retries: int = 4
    backoff_base: float = 0.5
    extra_headers: dict[str, str] = field(default_factory=dict)


def tls_context(config: TransportConfig) -> ssl.SSLContext:
    # [TM:S-4] TLS 1.3 is the *minimum*; hostname checking and certificate verification stay on.
    ctx = ssl.create_default_context(cafile=config.ca_file)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    if config.client_cert:
        ctx.load_cert_chain(config.client_cert, config.client_key)
    return ctx


def check_base_url(base_url: str, config: TransportConfig) -> str:
    url = httpx.URL(base_url)
    if url.scheme == "https":
        return base_url.rstrip("/")
    local = url.host in {"localhost", "127.0.0.1", "::1"} or url.host.endswith(".localhost")
    if url.scheme == "http" and config.allow_insecure_http and local:
        return base_url.rstrip("/")
    raise ValueError(
        "the server URL must use https:// (plain http is allowed only for localhost with allow_insecure_http=True)"
    )


def raise_for_envelope(response: httpx.Response) -> None:
    if response.is_success:
        return
    try:
        error = response.json().get("error", {})
    except ValueError:
        error = {}
    raise ApiError(
        response.status_code,
        str(error.get("code", "http_error")),
        str(error.get("message", response.reason_phrase or "request failed")),
        error.get("details"),
        error.get("request_id") or response.headers.get("X-Request-ID"),
    )


class Transport:
    """Thin wrapper over ``httpx.Client`` adding auth, retries and the error envelope."""

    def __init__(
        self,
        base_url: str,
        config: TransportConfig,
        *,
        auth_header: Callable[[], dict[str, str]],
        http: httpx.Client | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.base_url = check_base_url(base_url, config) if http is None else base_url.rstrip("/")
        self.config = config
        self._auth_header = auth_header
        self._sleep = sleep
        self._http = http or httpx.Client(
            base_url=self.base_url,
            verify=tls_context(config),
            timeout=config.timeout,
            headers={"User-Agent": "ciphercompute-client/0.1.0", **config.extra_headers},
            follow_redirects=False,
        )
        # Presigned object-storage URLs live on a different host and must not receive our token.
        self._storage = (
            httpx.Client(verify=tls_context(config), timeout=config.upload_timeout) if http is None else http
        )

    def close(self) -> None:
        self._http.close()
        if self._storage is not self._http:
            self._storage.close()

    def request(
        self, method: str, path: str, *, authenticated: bool = True, timeout: float | None = None, **kwargs: Any
    ) -> httpx.Response:
        headers = dict(kwargs.pop("headers", {}) or {})
        if authenticated:
            headers.update(self._auth_header())
        attempt = 0
        while True:
            try:
                response = self._http.request(
                    method, path, headers=headers, timeout=timeout or self.config.timeout, **kwargs
                )
            except (httpx.ConnectError, httpx.ReadError, httpx.RemoteProtocolError, httpx.TimeoutException):
                if attempt >= self.config.max_retries:
                    raise
                self._sleep(self._delay(attempt, None))
                attempt += 1
                continue
            if response.status_code in RETRY_STATUSES and attempt < self.config.max_retries:
                self._sleep(self._delay(attempt, response.headers.get("Retry-After")))
                attempt += 1
                continue
            raise_for_envelope(response)
            return response

    def _delay(self, attempt: int, retry_after: str | None) -> float:
        if retry_after is not None:
            try:
                return min(60.0, max(0.0, float(retry_after)))
            except ValueError:
                pass
        return float(self.config.backoff_base * 2**attempt * (0.5 + random.random()))  # noqa: S311 - jitter

    def json(self, method: str, path: str, **kwargs: Any) -> Any:
        response = self.request(method, path, **kwargs)
        return None if response.status_code == 204 or not response.content else response.json()

    def upload_presigned(self, url: str, fields: dict[str, str], data: bytes, filename: str) -> None:
        """S3/MinIO presigned POST: form fields first, then the file. No API token is sent."""
        response = self._storage.post(
            url,
            data=fields,
            files={"file": (filename, data, "application/octet-stream")},
            timeout=self.config.upload_timeout,
        )
        if response.status_code not in (200, 201, 204):
            raise ApiError(response.status_code, "storage_upload_failed", response.text[:300])

    def download(self, url: str) -> bytes:
        response = self._storage.get(url, timeout=self.config.upload_timeout)
        if response.status_code != 200:
            raise ApiError(response.status_code, "storage_download_failed", response.text[:300])
        return response.content

    def stream_lines(self, path: str) -> Any:
        return self._http.stream("GET", path, headers=self._auth_header(), timeout=None)
