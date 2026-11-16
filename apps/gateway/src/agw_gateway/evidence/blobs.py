"""Object storage for large payload CIPHERTEXTS (Phase 7, ADR-0029 §3). MinIO / S3 API.

Only ciphertext is ever stored here (the AES-256-GCM output of the payload store), under
``<tenant>/<event_id>``. The bucket is private: on startup the store refuses a bucket that has a
bucket policy (no anonymous/public access, no presigned URLs handed out by the gateway).
Postgres keeps the object key, ciphertext length and SHA-256 so a missing or altered object is
detected on read (availability check), independent of the AEAD tag.

Objects are written BEFORE the event transaction commits (07 §4); a rollback leaves an orphan
that ``RetentionJob.collect_orphans`` deletes. A MinIO outage only affects payloads above the
threshold: their events cannot be written (503, fail closed); small payloads are unaffected.
"""

from __future__ import annotations

import io
from datetime import UTC, datetime
from typing import Protocol

import urllib3
from minio import Minio
from minio.error import S3Error


class BlobUnavailable(Exception):
    pass


class BucketNotPrivate(BlobUnavailable):
    """The payload bucket has a policy (possible public access): refuse to start."""


class BlobStore(Protocol):
    def put(self, key: str, data: bytes) -> None: ...

    def get(self, key: str) -> bytes | None: ...

    def delete(self, key: str) -> None: ...

    def list_objects(self, prefix: str = "") -> list[tuple[str, datetime]]: ...


class S3BlobStore:
    def __init__(
        self,
        *,
        endpoint: str,
        access_key: str,
        secret_key: str,
        bucket: str,
        secure: bool = True,
    ) -> None:
        self._c = Minio(endpoint, access_key=access_key, secret_key=secret_key, secure=secure)
        self.bucket = bucket

    def __repr__(self) -> str:  # never show credentials
        return f"S3BlobStore(bucket={self.bucket!r})"

    def ensure_private_bucket(self) -> None:
        try:
            if not self._c.bucket_exists(self.bucket):
                self._c.make_bucket(self.bucket)
            try:
                policy = self._c.get_bucket_policy(self.bucket)
            except S3Error as exc:
                if exc.code != "NoSuchBucketPolicy":
                    raise
                policy = ""
        except (S3Error, OSError, urllib3.exceptions.HTTPError) as exc:
            raise BlobUnavailable(type(exc).__name__) from None
        if policy:
            raise BucketNotPrivate("bucket has a policy; payload blobs must be private")

    def put(self, key: str, data: bytes) -> None:
        try:
            self._c.put_object(self.bucket, key, io.BytesIO(data), len(data))
        except (S3Error, OSError, urllib3.exceptions.HTTPError) as exc:
            raise BlobUnavailable(type(exc).__name__) from None

    def get(self, key: str) -> bytes | None:
        try:
            resp = self._c.get_object(self.bucket, key)
        except S3Error as exc:
            if exc.code == "NoSuchKey":
                return None
            raise BlobUnavailable(exc.code) from None
        except (OSError, urllib3.exceptions.HTTPError) as exc:
            raise BlobUnavailable(type(exc).__name__) from None
        try:
            return bytes(resp.read())
        finally:
            resp.close()
            resp.release_conn()

    def delete(self, key: str) -> None:
        try:
            self._c.remove_object(self.bucket, key)
        except (S3Error, OSError, urllib3.exceptions.HTTPError) as exc:
            raise BlobUnavailable(type(exc).__name__) from None

    def list_objects(self, prefix: str = "") -> list[tuple[str, datetime]]:
        """(object key, last modified) pairs."""
        try:
            return [
                (str(o.object_name), o.last_modified or datetime.now(UTC))
                for o in self._c.list_objects(self.bucket, prefix=prefix, recursive=True)
            ]
        except (S3Error, OSError, urllib3.exceptions.HTTPError) as exc:
            raise BlobUnavailable(type(exc).__name__) from None
