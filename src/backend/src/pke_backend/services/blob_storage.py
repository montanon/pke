"""BlobStore Protocol + streaming filesystem implementation (HLAM-63).

Per ``context/08_security_assumptions.md`` the backend never decrypts evidence.
This module persists opaque ciphertext blobs only: bytes in, bytes out, never
inspected. The MVP uses a filesystem-backed store keyed by ``snapshot_id``;
the ``BlobStore`` Protocol lets a future S3-backed implementation be swapped
in without touching the endpoint layer.

Streaming I/O uses ``asyncio.to_thread`` because CPython has no native async
file I/O. This consumes default-executor threads on the event loop's default
thread pool (``min(32, os.cpu_count() + 4)``); under heavy concurrent upload
load that pool can become the bottleneck before disk does. Documented here as
a known limit that motivates the S3 migration path.
"""

from __future__ import annotations

import asyncio
import contextlib
import errno
import hashlib
import os
import stat
from collections.abc import AsyncIterator
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Protocol
from uuid import UUID

__all__ = [
    "BLOB_FILENAME",
    "BLOB_TMP_SUFFIX",
    "BlobAlreadyExistsError",
    "BlobNotFoundError",
    "BlobPutResult",
    "BlobStore",
    "BlobStoreError",
    "BlobStoreIOError",
    "FilesystemBlobStore",
]

BLOB_FILENAME: Final[str] = "blob.bin"
BLOB_TMP_SUFFIX: Final[str] = ".tmp"
_CHUNK_SIZE: Final[int] = 64 * 1024
_ROOT_MODE: Final[int] = 0o700
_SNAPSHOT_DIR_MODE: Final[int] = 0o700
_BLOB_FILE_MODE: Final[int] = 0o600


class BlobStoreError(Exception):
    """Base class for blob-storage failures.

    ``reason`` is a short operator-readable string. It must NEVER contain
    ciphertext bytes or other content material.
    """

    __slots__ = ("reason",)

    def __init__(self, reason: str | None = None) -> None:
        super().__init__(reason)
        self.reason = reason

    def __str__(self) -> str:
        if self.reason is None:
            return type(self).__name__
        return f"{type(self).__name__}: {self.reason}"


class BlobNotFoundError(BlobStoreError):
    __slots__ = ()


class BlobAlreadyExistsError(BlobStoreError):
    __slots__ = ()


class BlobStoreIOError(BlobStoreError):
    __slots__ = ()


@dataclass(frozen=True, slots=True)
class BlobPutResult:
    """Result of a successful ``BlobStore.put``.

    * ``path`` — absolute path of the committed blob on disk.
    * ``sha256`` — raw 32-byte digest of the streamed bytes; the endpoint
      cross-checks this against the claimed ``ciphertext_hash``.
    """

    path: Path
    sha256: bytes


class BlobStore(Protocol):
    """Structural Protocol for opaque-blob persistence.

    The endpoint depends on this Protocol, not on ``FilesystemBlobStore``,
    so a future ``S3BlobStore`` can be swapped in transparently.
    """

    async def put(
        self,
        snapshot_id: UUID,
        stream: AsyncIterator[bytes],
        *,
        overwrite: bool = False,
    ) -> BlobPutResult: ...

    def get(self, snapshot_id: UUID) -> AsyncIterator[bytes]: ...

    async def exists(self, snapshot_id: UUID) -> bool: ...


class FilesystemBlobStore:
    """Streaming, atomic, filesystem-backed implementation of ``BlobStore``.

    Layout: ``{root}/{snapshot_id}/blob.bin``. Writes go through a sibling
    ``blob.bin.tmp`` so the final path appears atomically on ``os.replace``.
    The root may be a symlink (operators routinely point it at a mounted
    volume) but per-snapshot subdirectories must be plain directories — a
    symlink there would be a tampering pivot and is rejected.
    """

    __slots__ = ("_root",)

    def __init__(self, root: Path) -> None:
        resolved = root.resolve(strict=False)
        if resolved.exists() and not resolved.is_dir():
            raise BlobStoreIOError(
                reason=f"root path {resolved} exists and is not a directory",
            )
        try:
            resolved.mkdir(mode=_ROOT_MODE, parents=True, exist_ok=True)
            resolved.chmod(_ROOT_MODE)
        except OSError as exc:
            raise BlobStoreIOError(
                reason=f"failed to prepare blob root {resolved}: errno={exc.errno}",
            ) from exc
        self._root = resolved

    @property
    def root(self) -> Path:
        return self._root

    @staticmethod
    def _validate_id(snapshot_id: UUID) -> None:
        if not isinstance(snapshot_id, UUID):
            raise TypeError(
                f"snapshot_id must be uuid.UUID, got {type(snapshot_id).__name__}",
            )

    def _snapshot_dir(self, snapshot_id: UUID) -> Path:
        return self._root / str(snapshot_id)

    def _blob_path(self, snapshot_id: UUID) -> Path:
        return self._snapshot_dir(snapshot_id) / BLOB_FILENAME

    def _tmp_path(self, snapshot_id: UUID) -> Path:
        return self._snapshot_dir(snapshot_id) / (BLOB_FILENAME + BLOB_TMP_SUFFIX)

    async def exists(self, snapshot_id: UUID) -> bool:
        self._validate_id(snapshot_id)
        return await asyncio.to_thread(self._blob_path(snapshot_id).is_file)

    async def put(
        self,
        snapshot_id: UUID,
        stream: AsyncIterator[bytes],
        *,
        overwrite: bool = False,
    ) -> BlobPutResult:
        self._validate_id(snapshot_id)
        snapshot_dir = self._snapshot_dir(snapshot_id)
        blob_path = self._blob_path(snapshot_id)
        tmp_path = self._tmp_path(snapshot_id)

        if not overwrite and await asyncio.to_thread(blob_path.exists):
            raise BlobAlreadyExistsError(
                reason=f"blob already exists for {snapshot_id}",
            )

        try:
            await asyncio.to_thread(
                os.makedirs,
                snapshot_dir,
                _SNAPSHOT_DIR_MODE,
                True,
            )
        except OSError as exc:
            raise BlobStoreIOError(
                reason=f"failed to create snapshot dir for {snapshot_id}: errno={exc.errno}",
            ) from exc

        dir_stat = await asyncio.to_thread(os.lstat, snapshot_dir)
        if stat.S_ISLNK(dir_stat.st_mode):
            raise BlobStoreIOError(
                reason=f"snapshot directory {snapshot_dir} is a symlink",
            )

        try:
            fd = await asyncio.to_thread(
                os.open,
                tmp_path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                _BLOB_FILE_MODE,
            )
        except FileExistsError as exc:
            raise BlobAlreadyExistsError(
                reason=f"a concurrent put is in flight for {snapshot_id}",
            ) from exc
        except OSError as exc:
            raise BlobStoreIOError(
                reason=f"failed to open tmp file for {snapshot_id}: errno={exc.errno}",
            ) from exc

        digest = hashlib.sha256()
        try:
            try:
                async for chunk in stream:
                    digest.update(chunk)
                    await asyncio.to_thread(os.write, fd, chunk)
                await asyncio.to_thread(os.fsync, fd)
            finally:
                await asyncio.to_thread(os.close, fd)

            if not overwrite and await asyncio.to_thread(blob_path.exists):
                raise BlobAlreadyExistsError(
                    reason=f"blob materialised concurrently for {snapshot_id}",
                )
            await asyncio.to_thread(os.replace, tmp_path, blob_path)
            await self._fsync_dir(snapshot_dir)
        except BaseException as exc:
            # Includes OSError (disk full, EIO), the stream raising, and
            # asyncio.CancelledError on consumer cancellation. In every
            # failure path the partial tmp must not survive.
            with contextlib.suppress(FileNotFoundError):
                await asyncio.to_thread(os.unlink, tmp_path)
            if isinstance(exc, OSError) and not isinstance(exc, BlobStoreError):
                raise BlobStoreIOError(
                    reason=f"io error during put for {snapshot_id}: errno={exc.errno} ({errno.errorcode.get(exc.errno or 0, '?')})",
                ) from exc
            raise

        return BlobPutResult(path=blob_path, sha256=digest.digest())

    def get(self, snapshot_id: UUID) -> AsyncIterator[bytes]:
        self._validate_id(snapshot_id)
        return self._read_stream(snapshot_id, self._blob_path(snapshot_id))

    @staticmethod
    async def _fsync_dir(directory: Path) -> None:
        dir_fd = await asyncio.to_thread(os.open, directory, os.O_RDONLY)
        try:
            await asyncio.to_thread(os.fsync, dir_fd)
        except OSError:
            # Some filesystems (e.g. tmpfs on certain platforms) don't
            # support directory fsync. The atomic rename is still durable
            # within its own fs guarantees; we don't fail the put for this.
            pass
        finally:
            await asyncio.to_thread(os.close, dir_fd)

    @staticmethod
    async def _read_stream(
        snapshot_id: UUID,
        blob_path: Path,
    ) -> AsyncIterator[bytes]:
        try:
            fd = await asyncio.to_thread(os.open, blob_path, os.O_RDONLY)
        except FileNotFoundError as exc:
            raise BlobNotFoundError(
                reason=f"no blob for {snapshot_id}",
            ) from exc
        except OSError as exc:
            raise BlobStoreIOError(
                reason=f"failed to open blob for {snapshot_id}: errno={exc.errno}",
            ) from exc
        try:
            while True:
                chunk = await asyncio.to_thread(os.read, fd, _CHUNK_SIZE)
                if not chunk:
                    return
                yield chunk
        finally:
            await asyncio.to_thread(os.close, fd)
