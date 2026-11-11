"""High-level SDK client.

Everything that touches plaintext happens here, on the caller's machine: encryption before upload
and decryption after download. [TM:I-8] There is deliberately no method that sends a decrypted
value — or anything derived from one — back to the server: approximate CKKS decryptions can leak
the secret key (Li-Micciancio 2021).
"""

from __future__ import annotations

import json
import time
import uuid
from collections.abc import Iterator, Sequence
from typing import Any, cast

import httpx
import numpy as np

from ciphercompute_core import EncryptedVector, KeyRing, PublicKeyBundle
from ciphercompute_core.manifest import manifest_hash, object_fingerprint

from .errors import ApiError
from .transport import Transport, TransportConfig, raise_for_envelope

TERMINAL = {"succeeded", "failed", "cancelled"}
Keys = KeyRing | PublicKeyBundle


class JobFailedError(Exception):
    def __init__(self, job: dict[str, Any]) -> None:
        error = job.get("error") or {}
        super().__init__(f"job {job.get('id')} {job.get('status')}: {error.get('code')} — {error.get('message')}")
        self.job = job


class IntegrityError(Exception):
    """A downloaded object or a job manifest does not match what the client committed to."""


def _bundle_of(keys: Keys) -> PublicKeyBundle:
    return keys.public_bundle() if isinstance(keys, KeyRing) else keys


class CipherComputeClient:
    """Synchronous client for the CipherCompute API.

    Authenticate with an API key (``cc_…``) or with tokens from :meth:`login`; access tokens are
    refreshed automatically when a refresh token is available.
    """

    def __init__(
        self,
        base_url: str,
        *,
        api_key: str | None = None,
        access_token: str | None = None,
        refresh_token: str | None = None,
        transport_config: TransportConfig | None = None,
        http: httpx.Client | None = None,
    ) -> None:
        self.api_key = api_key
        self.access_token = access_token
        self.refresh_token = refresh_token
        self._transport = Transport(
            base_url, transport_config or TransportConfig(), auth_header=self._auth_header, http=http
        )
        # fingerprints of what this client uploaded, for manifest verification
        self._uploaded: dict[str, str] = {}

    # ----- lifecycle / auth ------------------------------------------------------------------

    def __enter__(self) -> CipherComputeClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        self._transport.close()

    def _auth_header(self) -> dict[str, str]:
        token = self.api_key or self.access_token
        return {"Authorization": f"Bearer {token}"} if token else {}

    def _call(self, method: str, path: str, **kwargs: Any) -> Any:
        try:
            return self._transport.json(method, path, **kwargs)
        except ApiError as exc:
            if exc.status_code == 401 and self.refresh_token and not self.api_key and exc.code != "refresh_token_reuse":
                self.refresh()
                return self._transport.json(method, path, **kwargs)
            raise

    def _store_tokens(self, body: dict[str, Any]) -> dict[str, Any]:
        self.access_token = body["access_token"]
        self.refresh_token = body["refresh_token"]
        return body

    def register(self, email: str, password: str, organization_name: str) -> dict[str, Any]:
        body = self._transport.json(
            "POST",
            "/v1/auth/register",
            authenticated=False,
            json={"email": email, "password": password, "organization_name": organization_name},
        )
        return self._store_tokens(body)

    def login(self, email: str, password: str, organization_id: str | None = None) -> dict[str, Any]:
        payload: dict[str, Any] = {"email": email, "password": password}
        if organization_id:
            payload["organization_id"] = organization_id
        return self._store_tokens(self._transport.json("POST", "/v1/auth/login", authenticated=False, json=payload))

    def refresh(self) -> dict[str, Any]:
        if not self.refresh_token:
            raise ValueError("no refresh token; log in first")
        return self._store_tokens(
            self._transport.json(
                "POST", "/v1/auth/refresh", authenticated=False, json={"refresh_token": self.refresh_token}
            )
        )

    def logout(self) -> None:
        self._call("POST", "/v1/auth/logout", json={"refresh_token": self.refresh_token})
        self.access_token = self.refresh_token = None

    def me(self) -> dict[str, Any]:
        return cast("dict[str, Any]", self._call("GET", "/v1/auth/me"))

    # ----- projects / keys / datasets --------------------------------------------------------

    def create_project(self, name: str, description: str = "") -> dict[str, Any]:
        return cast(
            "dict[str, Any]", self._call("POST", "/v1/projects", json={"name": name, "description": description})
        )

    def list_projects(self) -> list[dict[str, Any]]:
        return list(self._paginate("/v1/projects"))

    def upload_key_bundle(self, project_id: str, keys: Keys | bytes) -> dict[str, Any]:
        """Upload the *public* half of a key ring. Raw bytes are checked locally first."""
        if isinstance(keys, bytes | bytearray):
            data = bytes(keys)
            PublicKeyBundle.load(data)  # refuses secret-key material before it leaves this machine
        else:
            data = _bundle_of(keys).to_bytes()
        return cast(
            "dict[str, Any]",
            self._call(
                "POST",
                f"/v1/projects/{project_id}/key-bundles",
                content=data,
                headers={"Content-Type": "application/octet-stream"},
                timeout=self._transport.config.upload_timeout,
            ),
        )

    def list_key_bundles(self, project_id: str) -> list[dict[str, Any]]:
        return cast("list[dict[str, Any]]", self._call("GET", f"/v1/projects/{project_id}/key-bundles"))

    def create_dataset(self, project_id: str, name: str, key_bundle_id: str, description: str = "") -> dict[str, Any]:
        return cast(
            "dict[str, Any]",
            self._call(
                "POST",
                f"/v1/projects/{project_id}/datasets",
                json={"name": name, "key_bundle_id": key_bundle_id, "description": description},
            ),
        )

    def list_datasets(self, project_id: str) -> list[dict[str, Any]]:
        return list(self._paginate(f"/v1/projects/{project_id}/datasets"))

    def list_ciphertexts(self, dataset_id: str) -> list[dict[str, Any]]:
        return list(self._paginate(f"/v1/datasets/{dataset_id}/ciphertexts"))

    # ----- ciphertexts -----------------------------------------------------------------------

    def upload_ciphertext(self, dataset_id: str, vector: EncryptedVector, label: str) -> dict[str, Any]:
        """Reserve, upload straight to object storage (presigned POST), confirm."""
        data = vector.to_bytes()
        created = self._call(
            "POST", f"/v1/datasets/{dataset_id}/ciphertexts", json={"label": label, "size_bytes": len(data)}
        )
        upload = created["upload"]
        self._transport.upload_presigned(upload["url"], upload["fields"], data, f"{label}.ccct")
        confirmed: dict[str, Any] = self._call("POST", f"/v1/ciphertexts/{created['ciphertext']['id']}/confirm")
        if confirmed["fingerprint"] != object_fingerprint(data):
            raise IntegrityError("the server recorded a different fingerprint than the bytes this client uploaded")
        self._uploaded[confirmed["id"]] = confirmed["fingerprint"]
        return confirmed

    def encrypt_and_upload(
        self,
        dataset_id: str,
        keys: Keys,
        values: Sequence[float] | np.ndarray,
        *,
        label: str,
        pad_to: int | None = None,
    ) -> dict[str, Any]:
        return self.upload_ciphertext(dataset_id, EncryptedVector.encrypt(keys, values, pad_to=pad_to), label)

    def encrypt_columns_and_upload(
        self, dataset_id: str, keys: Keys, matrix: np.ndarray | Sequence[Sequence[float]], *, labels: Sequence[str]
    ) -> list[dict[str, Any]]:
        """Encrypt a samples x features matrix one *feature column* per ciphertext (batched inference)."""
        arr = np.asarray(matrix, dtype=np.float64)
        if arr.ndim != 2 or arr.shape[1] != len(labels):
            raise ValueError(f"matrix must be samples x {len(labels)} features; got shape {arr.shape}")
        return [self.encrypt_and_upload(dataset_id, keys, arr[:, i], label=label) for i, label in enumerate(labels)]

    # ----- jobs ------------------------------------------------------------------------------

    def submit_job(
        self,
        project_id: str,
        operation: str,
        inputs: Sequence[str],
        args: dict[str, Any] | None = None,
        *,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        """Submit a job. An idempotency key is always sent, so a retried request never runs twice."""
        key = idempotency_key or f"sdk-{uuid.uuid4().hex}"
        return cast(
            "dict[str, Any]",
            self._call(
                "POST",
                f"/v1/projects/{project_id}/jobs",
                json={"operation": operation, "inputs": list(inputs), "args": args or {}},
                headers={"Idempotency-Key": key},
            ),
        )

    def get_job(self, job_id: str) -> dict[str, Any]:
        return cast("dict[str, Any]", self._call("GET", f"/v1/jobs/{job_id}"))

    def list_jobs(self, *, project_id: str | None = None, status: str | None = None) -> list[dict[str, Any]]:
        params = {k: v for k, v in {"project_id": project_id, "status": status}.items() if v}
        return list(self._paginate("/v1/jobs", params))

    def cancel_job(self, job_id: str) -> dict[str, Any]:
        return cast("dict[str, Any]", self._call("POST", f"/v1/jobs/{job_id}/cancel"))

    def wait(self, job_id: str, *, timeout: float = 600.0, poll_interval: float = 1.0) -> dict[str, Any]:
        deadline = time.monotonic() + timeout
        while True:
            job = self.get_job(job_id)
            if job["status"] in TERMINAL:
                if job["status"] != "succeeded":
                    raise JobFailedError(job)
                return job
            if time.monotonic() > deadline:
                raise TimeoutError(f"job {job_id} is still {job['status']} after {timeout:.0f}s")
            time.sleep(poll_interval)

    def events(self, job_id: str) -> Iterator[dict[str, Any]]:
        """Live job updates via Server-Sent Events; yields each ``status`` payload until terminal."""
        with self._transport.stream_lines(f"/v1/jobs/{job_id}/events") as response:
            if response.status_code != 200:
                response.read()
                raise_for_envelope(response)
            event = None
            for line in response.iter_lines():
                if line.startswith("event:"):
                    event = line.split(":", 1)[1].strip()
                elif line.startswith("data:") and event == "status":
                    payload: dict[str, Any] = json.loads(line.split(":", 1)[1])
                    yield payload
                    if payload["status"] in TERMINAL:
                        return

    def download_result(self, job_id: str, keys: Keys | KeyRing) -> EncryptedVector:
        """Download the encrypted result and check it against the fingerprint the worker recorded."""
        result = self._call("GET", f"/v1/jobs/{job_id}/result")
        data = self._transport.download(result["download"]["url"])
        if object_fingerprint(data) != result["result_fingerprint"]:
            raise IntegrityError("downloaded result does not match the recorded fingerprint")
        return EncryptedVector.load(keys, data)

    def decrypt_result(self, job_id: str, ring: KeyRing) -> np.ndarray:
        """Download and decrypt locally — the only place the plaintext result ever exists."""
        return ring.decrypt(self.download_result(job_id, ring))

    def wait_and_decrypt(
        self, job_id: str, ring: KeyRing, *, timeout: float = 600.0, poll_interval: float = 1.0
    ) -> np.ndarray:
        self.wait(job_id, timeout=timeout, poll_interval=poll_interval)
        return self.decrypt_result(job_id, ring)

    def verify_manifest(self, job: dict[str, Any], keys: Keys) -> None:
        """Check the server computed what this client asked for, on the inputs it uploaded."""
        fingerprints = [self._uploaded.get(i) for i in job["input_ids"]]
        if None in fingerprints:
            raise IntegrityError("some inputs were not uploaded by this client; fingerprints unknown")
        expected = manifest_hash(
            job["operation"], job["args"], [str(f) for f in fingerprints], _bundle_of(keys).fingerprint
        )
        if expected != job["manifest_hash"]:
            raise IntegrityError(
                "job manifest does not match the inputs, operation and arguments this client submitted"
            )

    # ----- catalog / audit / usage / keys ----------------------------------------------------

    def operations(self) -> list[dict[str, Any]]:
        return cast("list[dict[str, Any]]", self._call("GET", "/v1/operations"))

    def parameter_sets(self) -> list[dict[str, Any]]:
        return cast("list[dict[str, Any]]", self._call("GET", "/v1/parameter-sets"))

    def advise(
        self, steps: Sequence[tuple[str, dict[str, Any]]], input_lengths: Sequence[int], **options: Any
    ) -> dict[str, Any]:
        body = {
            "steps": [{"operation": op, "args": args} for op, args in steps],
            "input_lengths": list(input_lengths),
            **options,
        }
        return cast("dict[str, Any]", self._call("POST", "/v1/advisor", json=body))

    def audit_events(self, *, action: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
        params: dict[str, Any] = {"limit": limit}
        if action:
            params["action"] = action
        return cast("list[dict[str, Any]]", self._call("GET", "/v1/audit", params=params)["items"])

    def verify_audit_chain(self) -> dict[str, Any]:
        return cast("dict[str, Any]", self._call("GET", "/v1/audit/verify"))

    def usage(self, days: int = 30) -> dict[str, Any]:
        return cast("dict[str, Any]", self._call("GET", "/v1/usage", params={"days": days}))

    def create_api_key(self, name: str, scopes: Sequence[str], expires_in_days: int | None = None) -> dict[str, Any]:
        return cast(
            "dict[str, Any]",
            self._call(
                "POST", "/v1/api-keys", json={"name": name, "scopes": list(scopes), "expires_in_days": expires_in_days}
            ),
        )

    def list_api_keys(self) -> list[dict[str, Any]]:
        return cast("list[dict[str, Any]]", self._call("GET", "/v1/api-keys"))

    def revoke_api_key(self, key_id: str) -> dict[str, Any]:
        return cast("dict[str, Any]", self._call("DELETE", f"/v1/api-keys/{key_id}"))

    # ----- helpers ----------------------------------------------------------------------------

    def _paginate(self, path: str, params: dict[str, Any] | None = None) -> Iterator[dict[str, Any]]:
        query = dict(params or {})
        query.setdefault("limit", 100)
        while True:
            page = self._call("GET", path, params=query)
            yield from page["items"]
            if not page.get("next_cursor"):
                return
            query["before"] = page["next_cursor"]
