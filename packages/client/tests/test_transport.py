from __future__ import annotations

import datetime as dt
import ssl
from pathlib import Path

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from ciphercompute_client.errors import ApiError
from ciphercompute_client.transport import Transport, TransportConfig, check_base_url, raise_for_envelope, tls_context


def test_tls13_minimum() -> None:
    ctx = tls_context(TransportConfig())
    assert ctx.minimum_version == ssl.TLSVersion.TLSv1_3
    assert ctx.check_hostname is True
    assert ctx.verify_mode == ssl.CERT_REQUIRED


def _self_signed(tmp_path: Path) -> tuple[str, str]:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "sdk-test-client")])
    now = dt.datetime.now(dt.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + dt.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = tmp_path / "client.pem", tmp_path / "client.key"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    )
    return str(cert_path), str(key_path)


def test_mutual_tls_loads_client_certificate(tmp_path: Path) -> None:
    cert, key = _self_signed(tmp_path)
    ctx = tls_context(TransportConfig(client_cert=cert, client_key=key))
    assert ctx.minimum_version == ssl.TLSVersion.TLSv1_3
    with pytest.raises(ssl.SSLError):
        tls_context(TransportConfig(client_cert=cert, client_key=cert))  # wrong key file


def test_base_url_rules() -> None:
    assert check_base_url("https://api.example.com/", TransportConfig()) == "https://api.example.com"
    assert check_base_url("http://localhost:8000", TransportConfig(allow_insecure_http=True)) == "http://localhost:8000"
    with pytest.raises(ValueError, match="https"):
        check_base_url("http://api.example.com", TransportConfig(allow_insecure_http=True))
    with pytest.raises(ValueError, match="https"):
        check_base_url("http://localhost:8000", TransportConfig())
    # a real (non-injected) transport validates the URL and builds TLS-1.3 clients
    t = Transport("https://api.example.com", TransportConfig(), auth_header=dict)
    t.close()


def _transport(handler, **config) -> tuple[Transport, list[float]]:  # type: ignore[no-untyped-def]
    sleeps: list[float] = []
    http = httpx.Client(transport=httpx.MockTransport(handler), base_url="https://api.test")
    t = Transport(
        "https://api.test",
        TransportConfig(**config),
        auth_header=lambda: {"Authorization": "Bearer t"},
        http=http,
        sleep=sleeps.append,
    )
    return t, sleeps


def test_retries_honour_retry_after_then_succeed() -> None:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        assert request.headers["Authorization"] == "Bearer t"
        if calls["n"] == 1:
            return httpx.Response(
                429, headers={"Retry-After": "3"}, json={"error": {"code": "rate_limited", "message": "slow"}}
            )
        if calls["n"] == 2:
            return httpx.Response(503, headers={"Retry-After": "soon"})
        return httpx.Response(200, json={"ok": True})

    t, sleeps = _transport(handler, max_retries=3, backoff_base=0.1)
    assert t.json("GET", "/x") == {"ok": True}
    assert sleeps[0] == 3.0 and 0.05 <= sleeps[1] <= 0.3


def test_retries_exhausted_raise_envelope() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, json={"error": {"code": "unavailable", "message": "down", "request_id": "r1"}})

    t, sleeps = _transport(handler, max_retries=2, backoff_base=0.0)
    with pytest.raises(ApiError) as excinfo:
        t.request("GET", "/x")
    assert excinfo.value.status_code == 503 and excinfo.value.code == "unavailable" and excinfo.value.request_id == "r1"
    assert len(sleeps) == 2


def test_connection_errors_retry_then_raise() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    t, sleeps = _transport(handler, max_retries=2, backoff_base=0.0)
    with pytest.raises(httpx.ConnectError):
        t.request("GET", "/x")
    assert len(sleeps) == 2


def test_unauthenticated_requests_and_204() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert "Authorization" not in request.headers
        return httpx.Response(204)

    t, _ = _transport(handler)
    assert t.json("POST", "/v1/auth/login", authenticated=False) is None


def test_non_json_error_and_storage_failures() -> None:
    with pytest.raises(ApiError) as excinfo:
        raise_for_envelope(
            httpx.Response(502, text="<html>bad gateway</html>", request=httpx.Request("GET", "https://x"))
        )
    assert excinfo.value.code == "http_error"

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, text="AccessDenied")

    t, _ = _transport(handler)
    with pytest.raises(ApiError, match="storage_upload_failed"):
        t.upload_presigned("https://s3.example/b", {"key": "k"}, b"data", "f")
    with pytest.raises(ApiError, match="storage_download_failed"):
        t.download("https://s3.example/b/k")
