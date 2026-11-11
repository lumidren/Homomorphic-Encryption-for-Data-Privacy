"""S3-compatible object storage for ciphertexts, key bundles and results.

Rules enforced here:

* every object key is derived server-side from tenant and resource ids and lives under
  ``org/<organization_id>/``; no caller-supplied path ever reaches the store;
* every write sets server-side encryption; the bucket's default encryption is configured at
  startup as a second gate;
* uploads go straight from the client to the bucket through a presigned POST whose policy
  caps the size, so oversized payloads never transit the API.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import uuid
from dataclasses import dataclass
from datetime import timedelta
from typing import Any, Literal, Protocol

import boto3
from botocore.client import Config
from botocore.exceptions import ClientError
from pydantic import SecretStr

from ..db.base import utcnow
from ..errors import PayloadTooLargeError


class StorageConfig(Protocol):
    """The settings ObjectStore needs; satisfied by the API's and the worker's settings."""

    s3_bucket: str
    s3_region: str
    s3_endpoint_url: str | None
    s3_access_key_id: SecretStr | None
    s3_secret_access_key: SecretStr | None
    s3_sse: Literal["AES256", "aws:kms"]
    s3_kms_key_id: str | None
    s3_force_path_style: bool
    presign_ttl_seconds: int


class TenantKeyViolationError(RuntimeError):
    """An object key outside the caller's tenant prefix was requested. Always a bug."""


@dataclass(frozen=True, slots=True)
class PresignedUpload:
    url: str
    fields: dict[str, str]
    expires_at: str
    max_bytes: int


@dataclass(frozen=True, slots=True)
class ObjectInfo:
    size: int
    etag: str | None
    sse: str | None


class ObjectStore:
    def __init__(self, settings: StorageConfig) -> None:
        self._settings = settings
        self._bucket = settings.s3_bucket
        kwargs: dict[str, Any] = {
            "region_name": settings.s3_region,
            "config": Config(
                signature_version="s3v4",
                s3={"addressing_style": "path" if settings.s3_force_path_style else "auto"},
                retries={"max_attempts": 4, "mode": "standard"},
            ),
        }
        if settings.s3_endpoint_url:
            kwargs["endpoint_url"] = settings.s3_endpoint_url
        if settings.s3_access_key_id and settings.s3_secret_access_key:
            kwargs["aws_access_key_id"] = settings.s3_access_key_id.get_secret_value()
            kwargs["aws_secret_access_key"] = settings.s3_secret_access_key.get_secret_value()
        self._client = boto3.client("s3", **kwargs)

    # ----- keys ---------------------------------------------------------------------------------

    @staticmethod
    def tenant_prefix(organization_id: uuid.UUID) -> str:
        return f"org/{organization_id}/"

    @classmethod
    def key_for_bundle(cls, organization_id: uuid.UUID, project_id: uuid.UUID, bundle_id: uuid.UUID) -> str:
        return f"{cls.tenant_prefix(organization_id)}projects/{project_id}/bundles/{bundle_id}.ccpk"

    @classmethod
    def key_for_ciphertext(
        cls, organization_id: uuid.UUID, project_id: uuid.UUID, dataset_id: uuid.UUID, ciphertext_id: uuid.UUID
    ) -> str:
        return f"{cls.tenant_prefix(organization_id)}projects/{project_id}/datasets/{dataset_id}/{ciphertext_id}.ccct"

    @classmethod
    def key_for_result(cls, organization_id: uuid.UUID, project_id: uuid.UUID, job_id: uuid.UUID) -> str:
        return f"{cls.tenant_prefix(organization_id)}projects/{project_id}/jobs/{job_id}/result.ccct"

    @classmethod
    def assert_tenant_key(cls, key: str, organization_id: uuid.UUID) -> str:
        # [TM:E-4] Presigned URLs and reads are only ever generated for keys under the
        # caller's own prefix.
        if not key.startswith(cls.tenant_prefix(organization_id)) or ".." in key:
            raise TenantKeyViolationError(f"object key is outside the tenant prefix: {key!r}")
        return key

    def _sse(self) -> dict[str, str]:
        # [TM:I-7] Every write is encrypted at rest; KMS when configured, AES-256 otherwise.
        if self._settings.s3_sse == "aws:kms" and self._settings.s3_kms_key_id:
            return {"ServerSideEncryption": "aws:kms", "SSEKMSKeyId": self._settings.s3_kms_key_id}
        return {"ServerSideEncryption": "AES256"}

    # ----- bucket lifecycle -----------------------------------------------------------------------

    async def ensure_bucket(self) -> None:
        def _ensure() -> None:
            try:
                self._client.head_bucket(Bucket=self._bucket)
            except ClientError:
                params: dict[str, Any] = {"Bucket": self._bucket}
                if self._settings.s3_region != "us-east-1" and not self._settings.s3_endpoint_url:
                    params["CreateBucketConfiguration"] = {"LocationConstraint": self._settings.s3_region}
                self._client.create_bucket(**params)
            rule: dict[str, Any] = {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": self._settings.s3_sse}}
            if self._settings.s3_sse == "aws:kms" and self._settings.s3_kms_key_id:
                rule["ApplyServerSideEncryptionByDefault"]["KMSMasterKeyID"] = self._settings.s3_kms_key_id
            # Some S3-compatible stores (older MinIO) reject the call; object-level SSE headers
            # still apply to every write.
            with contextlib.suppress(ClientError):
                self._client.put_bucket_encryption(
                    Bucket=self._bucket, ServerSideEncryptionConfiguration={"Rules": [rule]}
                )

        await asyncio.to_thread(_ensure)

    async def ping(self) -> bool:
        try:
            await asyncio.to_thread(self._client.head_bucket, Bucket=self._bucket)
            return True
        except ClientError:
            return False

    # ----- presigning ------------------------------------------------------------------------------

    async def presign_upload(self, key: str, organization_id: uuid.UUID, *, max_bytes: int) -> PresignedUpload:
        self.assert_tenant_key(key, organization_id)
        ttl = self._settings.presign_ttl_seconds
        sse = self._sse()
        fields = {"x-amz-server-side-encryption": sse["ServerSideEncryption"]}
        conditions: list[Any] = [
            # [TM:D-1] The policy caps the object size; S3/MinIO reject larger bodies outright.
            ["content-length-range", 1, max_bytes],
            {"x-amz-server-side-encryption": sse["ServerSideEncryption"]},
        ]
        if "SSEKMSKeyId" in sse:
            fields["x-amz-server-side-encryption-aws-kms-key-id"] = sse["SSEKMSKeyId"]
            conditions.append({"x-amz-server-side-encryption-aws-kms-key-id": sse["SSEKMSKeyId"]})

        def _presign() -> dict[str, Any]:
            return self._client.generate_presigned_post(  # type: ignore[no-any-return]
                Bucket=self._bucket, Key=key, Fields=fields, Conditions=conditions, ExpiresIn=ttl
            )

        post = await asyncio.to_thread(_presign)
        return PresignedUpload(
            url=post["url"],
            fields=dict(post["fields"]),
            expires_at=(utcnow() + timedelta(seconds=ttl)).isoformat(),
            max_bytes=max_bytes,
        )

    async def presign_download(self, key: str, organization_id: uuid.UUID) -> tuple[str, str]:
        self.assert_tenant_key(key, organization_id)
        ttl = self._settings.presign_ttl_seconds

        def _presign() -> str:
            return self._client.generate_presigned_url(  # type: ignore[no-any-return]
                "get_object", Params={"Bucket": self._bucket, "Key": key}, ExpiresIn=ttl
            )

        url = await asyncio.to_thread(_presign)
        return url, (utcnow() + timedelta(seconds=ttl)).isoformat()

    # ----- direct access (server-side) -----------------------------------------------------------

    async def put_bytes(self, key: str, organization_id: uuid.UUID, data: bytes) -> None:
        self.assert_tenant_key(key, organization_id)
        await asyncio.to_thread(self._client.put_object, Bucket=self._bucket, Key=key, Body=data, **self._sse())

    async def head(self, key: str, organization_id: uuid.UUID) -> ObjectInfo | None:
        self.assert_tenant_key(key, organization_id)
        try:
            meta = await asyncio.to_thread(self._client.head_object, Bucket=self._bucket, Key=key)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") in {"404", "NoSuchKey", "NotFound"}:
                return None
            raise
        return ObjectInfo(size=int(meta["ContentLength"]), etag=meta.get("ETag"), sse=meta.get("ServerSideEncryption"))

    async def get_bytes(self, key: str, organization_id: uuid.UUID, *, max_bytes: int) -> bytes:
        self.assert_tenant_key(key, organization_id)

        def _get() -> bytes:
            obj = self._client.get_object(Bucket=self._bucket, Key=key)
            size = int(obj["ContentLength"])
            if size > max_bytes:
                raise PayloadTooLargeError(
                    f"object is {size} bytes; the limit is {max_bytes}", size=size, limit=max_bytes
                )
            return obj["Body"].read()  # type: ignore[no-any-return]

        return await asyncio.to_thread(_get)

    async def get_range(self, key: str, organization_id: uuid.UUID, start: int, end_inclusive: int) -> bytes:
        self.assert_tenant_key(key, organization_id)

        def _get() -> bytes:
            obj = self._client.get_object(Bucket=self._bucket, Key=key, Range=f"bytes={start}-{end_inclusive}")
            return obj["Body"].read()  # type: ignore[no-any-return]

        return await asyncio.to_thread(_get)

    async def sha256_of(self, key: str, organization_id: uuid.UUID, *, max_bytes: int) -> tuple[str, int]:
        """Stream the object through SHA-256; returns ``("sha256:<hex>", size)``."""
        self.assert_tenant_key(key, organization_id)

        def _digest() -> tuple[str, int]:
            obj = self._client.get_object(Bucket=self._bucket, Key=key)
            size = int(obj["ContentLength"])
            if size > max_bytes:
                raise PayloadTooLargeError(
                    f"object is {size} bytes; the limit is {max_bytes}", size=size, limit=max_bytes
                )
            digest = hashlib.sha256()
            for chunk in obj["Body"].iter_chunks(chunk_size=1024 * 1024):
                digest.update(chunk)
            return "sha256:" + digest.hexdigest(), size

        return await asyncio.to_thread(_digest)

    async def delete(self, key: str, organization_id: uuid.UUID) -> None:
        self.assert_tenant_key(key, organization_id)
        await asyncio.to_thread(self._client.delete_object, Bucket=self._bucket, Key=key)

    async def delete_prefix(self, prefix: str, organization_id: uuid.UUID) -> int:
        """Delete every object under ``prefix`` (which must sit inside the tenant prefix)."""
        self.assert_tenant_key(prefix, organization_id)

        def _delete() -> int:
            removed = 0
            paginator = self._client.get_paginator("list_objects_v2")
            for page in paginator.paginate(Bucket=self._bucket, Prefix=prefix):
                keys = [{"Key": obj["Key"]} for obj in page.get("Contents", [])]
                if keys:
                    self._client.delete_objects(Bucket=self._bucket, Delete={"Objects": keys, "Quiet": True})
                    removed += len(keys)
            return removed

        return await asyncio.to_thread(_delete)

    async def total_bytes(self, prefix: str, organization_id: uuid.UUID) -> int:
        self.assert_tenant_key(prefix, organization_id)

        def _sum() -> int:
            total = 0
            for page in self._client.get_paginator("list_objects_v2").paginate(Bucket=self._bucket, Prefix=prefix):
                total += sum(int(obj["Size"]) for obj in page.get("Contents", []))
            return total

        return await asyncio.to_thread(_sum)
