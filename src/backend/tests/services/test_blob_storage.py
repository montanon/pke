from __future__ import annotations

import asyncio
import errno
import hashlib
import os
import stat
import uuid
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any
from uuid import UUID

import pytest

from pke_backend.services import (
    BLOB_FILENAME,
    BLOB_TMP_SUFFIX,
    BlobAlreadyExistsError,
    BlobNotFoundError,
    BlobPutResult,
    BlobStore,
    BlobStoreError,
    BlobStoreIOError,
    FilesystemBlobStore,
)

# --------------------------------------------------------------------------- helpers


async def _aiter(data: bytes, chunk: int = 16 * 1024) -> AsyncIterator[bytes]:
    for i in range(0, len(data), chunk):
        yield data[i : i + chunk]


async def _failing_aiter(
    data: bytes,
    after_chunks: int,
    exc: BaseException,
    chunk: int = 16,
) -> AsyncIterator[bytes]:
    for emitted, i in enumerate(range(0, len(data), chunk)):
        if emitted >= after_chunks:
            raise exc
        yield data[i : i + chunk]
    raise exc


async def _collect(stream: AsyncIterator[bytes]) -> bytes:
    out = bytearray()
    async for chunk in stream:
        out.extend(chunk)
    return bytes(out)


@pytest.fixture
def store(tmp_path: Path) -> FilesystemBlobStore:
    return FilesystemBlobStore(tmp_path / "blobs")


@pytest.fixture
def snapshot_id() -> UUID:
    return uuid.uuid4()


# --------------------------------------------------------------------------- module surface


def test_protocol_is_satisfied_structurally(store: FilesystemBlobStore) -> None:
    s: BlobStore = store
    assert s is store


def test_constants_match_public_layout() -> None:
    assert BLOB_FILENAME == "blob.bin"
    assert BLOB_TMP_SUFFIX == ".tmp"


def test_error_taxonomy() -> None:
    for cls in (BlobNotFoundError, BlobAlreadyExistsError, BlobStoreIOError):
        assert issubclass(cls, BlobStoreError)
        assert cls.__slots__ == ()
    assert BlobStoreError.__slots__ == ("reason",)


def test_error_default_reason_is_none() -> None:
    for cls in (
        BlobStoreError,
        BlobNotFoundError,
        BlobAlreadyExistsError,
        BlobStoreIOError,
    ):
        err = cls()
        assert err.reason is None
        assert str(err) == cls.__name__


def test_error_reason_round_trip() -> None:
    err = BlobStoreIOError(reason="disk full")
    assert err.reason == "disk full"
    assert "BlobStoreIOError" in str(err)
    assert "disk full" in str(err)


def test_blob_put_result_is_frozen() -> None:
    result = BlobPutResult(path=Path("/tmp/x"), sha256=b"\x00" * 32)
    with pytest.raises(AttributeError):
        result.path = Path("/tmp/y")  # type: ignore[misc]


# --------------------------------------------------------------------------- init / root


def test_init_creates_root_with_0o700(tmp_path: Path) -> None:
    target = tmp_path / "fresh"
    assert not target.exists()
    FilesystemBlobStore(target)
    assert target.is_dir()
    assert stat.S_IMODE(target.stat().st_mode) == 0o700


def test_init_chmods_existing_root_to_0o700(tmp_path: Path) -> None:
    target = tmp_path / "loose"
    target.mkdir(mode=0o755)
    assert stat.S_IMODE(target.stat().st_mode) == 0o755
    FilesystemBlobStore(target)
    assert stat.S_IMODE(target.stat().st_mode) == 0o700


def test_init_rejects_root_that_is_a_file(tmp_path: Path) -> None:
    target = tmp_path / "not-a-dir"
    target.write_bytes(b"")
    with pytest.raises(BlobStoreIOError) as exc:
        FilesystemBlobStore(target)
    assert "not a directory" in str(exc.value)


def test_init_resolves_root_symlink(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir(mode=0o700)
    link = tmp_path / "link"
    link.symlink_to(real)
    store = FilesystemBlobStore(link)
    assert store.root == real.resolve()


def test_init_remaps_oserror_on_mkdir(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def boom(self: Path, **_: Any) -> None:
        raise PermissionError(errno.EACCES, "denied")

    monkeypatch.setattr(Path, "mkdir", boom)
    with pytest.raises(BlobStoreIOError) as exc:
        FilesystemBlobStore(tmp_path / "nope")
    assert "failed to prepare blob root" in str(exc.value)


# --------------------------------------------------------------------------- AC #1


async def test_put_writes_streamed_bytes_and_returns_sha256(
    store: FilesystemBlobStore,
    snapshot_id: UUID,
) -> None:
    payload = os.urandom(200 * 1024)
    result = await store.put(snapshot_id, _aiter(payload, chunk=16 * 1024))

    assert isinstance(result, BlobPutResult)
    assert result.path == store.root / str(snapshot_id) / BLOB_FILENAME
    assert result.sha256 == hashlib.sha256(payload).digest()
    assert result.path.read_bytes() == payload


async def test_put_creates_snapshot_dir_with_0o700_and_blob_with_0o600(
    store: FilesystemBlobStore,
    snapshot_id: UUID,
) -> None:
    await store.put(snapshot_id, _aiter(b"hello"))

    snapshot_dir = store.root / str(snapshot_id)
    blob_path = snapshot_dir / BLOB_FILENAME
    assert stat.S_IMODE(snapshot_dir.stat().st_mode) == 0o700
    assert stat.S_IMODE(blob_path.stat().st_mode) == 0o600


async def test_put_no_tmp_file_left_behind_after_success(
    store: FilesystemBlobStore,
    snapshot_id: UUID,
) -> None:
    await store.put(snapshot_id, _aiter(b"payload"))
    tmp = store.root / str(snapshot_id) / (BLOB_FILENAME + BLOB_TMP_SUFFIX)
    assert not tmp.exists()


# --------------------------------------------------------------------------- AC #2


async def test_get_yields_chunks_no_larger_than_64kib(
    store: FilesystemBlobStore,
    snapshot_id: UUID,
) -> None:
    payload = os.urandom(200 * 1024)
    await store.put(snapshot_id, _aiter(payload))

    chunks = [chunk async for chunk in store.get(snapshot_id)]
    assert all(len(c) <= 64 * 1024 for c in chunks)
    assert b"".join(chunks) == payload


# --------------------------------------------------------------------------- AC #3


async def test_get_missing_raises_blob_not_found(
    store: FilesystemBlobStore,
) -> None:
    missing = uuid.uuid4()
    stream = store.get(missing)
    with pytest.raises(BlobNotFoundError) as exc:
        await stream.__anext__()
    assert str(missing) in str(exc.value)


# --------------------------------------------------------------------------- AC #4


async def test_put_existing_raises_already_exists(
    store: FilesystemBlobStore,
    snapshot_id: UUID,
) -> None:
    first = b"first"
    second = b"second"
    await store.put(snapshot_id, _aiter(first))

    with pytest.raises(BlobAlreadyExistsError):
        await store.put(snapshot_id, _aiter(second))

    blob = store.root / str(snapshot_id) / BLOB_FILENAME
    assert blob.read_bytes() == first


async def test_put_overwrite_true_replaces_blob(
    store: FilesystemBlobStore,
    snapshot_id: UUID,
) -> None:
    first = b"first" * 1000
    second = b"second" * 2000
    await store.put(snapshot_id, _aiter(first))

    result = await store.put(snapshot_id, _aiter(second), overwrite=True)
    assert result.sha256 == hashlib.sha256(second).digest()
    assert result.path.read_bytes() == second


# --------------------------------------------------------------------------- AC #5


async def test_exists_true_after_put_false_otherwise(
    store: FilesystemBlobStore,
) -> None:
    present = uuid.uuid4()
    absent = uuid.uuid4()
    await store.put(present, _aiter(b"x"))
    assert await store.exists(present) is True
    assert await store.exists(absent) is False


# --------------------------------------------------------------------------- AC #6


async def test_put_interrupted_midstream_cleans_partial_file(
    store: FilesystemBlobStore,
    snapshot_id: UUID,
) -> None:
    payload = b"a" * 4096
    bomb = RuntimeError("stream blew up")

    with pytest.raises(RuntimeError, match="stream blew up"):
        await store.put(
            snapshot_id,
            _failing_aiter(payload, after_chunks=1, exc=bomb),
        )

    snapshot_dir = store.root / str(snapshot_id)
    assert not (snapshot_dir / BLOB_FILENAME).exists()
    assert not (snapshot_dir / (BLOB_FILENAME + BLOB_TMP_SUFFIX)).exists()
    assert await store.exists(snapshot_id) is False


async def test_put_cancelled_midstream_cleans_partial_file(
    store: FilesystemBlobStore,
    snapshot_id: UUID,
) -> None:
    started = asyncio.Event()
    proceed = asyncio.Event()

    async def slow_stream() -> AsyncIterator[bytes]:
        yield b"first chunk"
        started.set()
        await proceed.wait()
        yield b"never reached"

    task = asyncio.create_task(store.put(snapshot_id, slow_stream()))
    await started.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    snapshot_dir = store.root / str(snapshot_id)
    assert not (snapshot_dir / BLOB_FILENAME).exists()
    assert not (snapshot_dir / (BLOB_FILENAME + BLOB_TMP_SUFFIX)).exists()


# --------------------------------------------------------------------------- edge cases


async def test_put_empty_stream(
    store: FilesystemBlobStore,
    snapshot_id: UUID,
) -> None:
    async def empty() -> AsyncIterator[bytes]:
        if False:
            yield b""

    result = await store.put(snapshot_id, empty())
    assert result.sha256 == hashlib.sha256(b"").digest()
    assert result.path.read_bytes() == b""


async def test_put_handles_tiny_chunks(
    store: FilesystemBlobStore,
    snapshot_id: UUID,
) -> None:
    payload = b"x" * 5000
    result = await store.put(snapshot_id, _aiter(payload, chunk=1))
    assert result.sha256 == hashlib.sha256(payload).digest()
    assert result.path.read_bytes() == payload


async def test_put_disk_full_raises_blob_store_io_error_and_cleans_partial(
    store: FilesystemBlobStore,
    snapshot_id: UUID,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_write = os.write
    calls: list[int] = []

    def fake_write(fd: int, data: bytes) -> int:
        calls.append(len(data))
        if len(calls) > 1:
            raise OSError(errno.ENOSPC, "no space")
        return real_write(fd, data)

    monkeypatch.setattr(os, "write", fake_write)

    with pytest.raises(BlobStoreIOError) as exc:
        await store.put(snapshot_id, _aiter(b"x" * 200_000, chunk=64 * 1024))
    assert "ENOSPC" in str(exc.value)

    snapshot_dir = store.root / str(snapshot_id)
    assert not (snapshot_dir / BLOB_FILENAME).exists()
    assert not (snapshot_dir / (BLOB_FILENAME + BLOB_TMP_SUFFIX)).exists()


@pytest.mark.parametrize(
    "bad",
    [
        "../etc/passwd",
        "not-a-uuid",
        12345,
        None,
        b"\x00" * 16,
    ],
)
async def test_put_rejects_non_uuid_snapshot_id(
    store: FilesystemBlobStore,
    bad: object,
) -> None:
    before = set(store.root.iterdir())
    with pytest.raises(TypeError):
        await store.put(bad, _aiter(b"x"))  # type: ignore[arg-type]
    assert set(store.root.iterdir()) == before


@pytest.mark.parametrize(
    "bad",
    [
        "../etc/passwd",
        "not-a-uuid",
        12345,
        None,
    ],
)
async def test_get_rejects_non_uuid_snapshot_id(
    store: FilesystemBlobStore,
    bad: object,
) -> None:
    with pytest.raises(TypeError):
        store.get(bad)  # type: ignore[arg-type]


async def test_exists_rejects_non_uuid_snapshot_id(
    store: FilesystemBlobStore,
) -> None:
    with pytest.raises(TypeError):
        await store.exists("../etc/passwd")  # type: ignore[arg-type]


async def test_concurrent_put_same_id_one_wins_one_raises(
    store: FilesystemBlobStore,
    snapshot_id: UUID,
) -> None:
    # Use a barrier to maximise interleaving across the open()/replace() race.
    barrier = asyncio.Event()

    async def gated_stream(payload: bytes) -> AsyncIterator[bytes]:
        await barrier.wait()
        for i in range(0, len(payload), 32):
            yield payload[i : i + 32]

    payload_a = b"A" * 4096
    payload_b = b"B" * 4096

    task_a = asyncio.create_task(store.put(snapshot_id, gated_stream(payload_a)))
    task_b = asyncio.create_task(store.put(snapshot_id, gated_stream(payload_b)))
    await asyncio.sleep(0)
    barrier.set()
    results = await asyncio.gather(task_a, task_b, return_exceptions=True)

    wins = [r for r in results if isinstance(r, BlobPutResult)]
    losses = [r for r in results if isinstance(r, BlobAlreadyExistsError)]
    assert len(wins) == 1
    assert len(losses) == 1

    blob = store.root / str(snapshot_id) / BLOB_FILENAME
    assert blob.read_bytes() in (payload_a, payload_b)
    tmp = store.root / str(snapshot_id) / (BLOB_FILENAME + BLOB_TMP_SUFFIX)
    assert not tmp.exists()


async def test_put_rejects_symlinked_snapshot_subdir(
    store: FilesystemBlobStore,
    tmp_path: Path,
    snapshot_id: UUID,
) -> None:
    # Pre-create the snapshot dir as a symlink to a sibling directory.
    target = tmp_path / "elsewhere"
    target.mkdir(mode=0o700)
    snapshot_dir = store.root / str(snapshot_id)
    snapshot_dir.symlink_to(target)

    with pytest.raises(BlobStoreIOError) as exc:
        await store.put(snapshot_id, _aiter(b"x"))
    assert "symlink" in str(exc.value)
    # No write through the symlink target.
    assert not (target / BLOB_FILENAME).exists()


async def test_exists_false_until_put_commits(
    store: FilesystemBlobStore,
    snapshot_id: UUID,
) -> None:
    started = asyncio.Event()
    proceed = asyncio.Event()

    async def gated() -> AsyncIterator[bytes]:
        yield b"chunk-1"
        started.set()
        await proceed.wait()

    task = asyncio.create_task(store.put(snapshot_id, gated()))
    await started.wait()
    assert await store.exists(snapshot_id) is False
    proceed.set()
    await task
    assert await store.exists(snapshot_id) is True


async def test_put_succeeds_after_previous_interrupted_put(
    store: FilesystemBlobStore,
    snapshot_id: UUID,
) -> None:
    bomb = RuntimeError("boom")
    with pytest.raises(RuntimeError):
        await store.put(snapshot_id, _failing_aiter(b"x" * 1024, 1, bomb))

    # The cleanup should leave the snapshot dir usable for a fresh put.
    result = await store.put(snapshot_id, _aiter(b"fresh payload"))
    assert result.path.read_bytes() == b"fresh payload"


async def test_get_after_partial_put_raises_not_found(
    store: FilesystemBlobStore,
    snapshot_id: UUID,
) -> None:
    bomb = RuntimeError("boom")
    with pytest.raises(RuntimeError):
        await store.put(snapshot_id, _failing_aiter(b"x" * 1024, 1, bomb))

    stream = store.get(snapshot_id)
    with pytest.raises(BlobNotFoundError):
        await stream.__anext__()


async def test_get_remaps_unexpected_oserror(
    store: FilesystemBlobStore,
    snapshot_id: UUID,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    await store.put(snapshot_id, _aiter(b"present"))

    real_open = os.open

    def fake_open(path: Any, flags: int, mode: int = 0o777) -> int:
        if isinstance(path, (str, Path)) and str(path).endswith(BLOB_FILENAME):
            raise PermissionError(errno.EACCES, "denied")
        return real_open(path, flags, mode)

    monkeypatch.setattr(os, "open", fake_open)

    stream = store.get(snapshot_id)
    with pytest.raises(BlobStoreIOError) as exc:
        await stream.__anext__()
    assert "failed to open" in str(exc.value)


async def test_put_remaps_unexpected_oserror_on_open_tmp(
    store: FilesystemBlobStore,
    snapshot_id: UUID,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_open = os.open

    def fake_open(path: Any, flags: int, mode: int = 0o777) -> int:
        if isinstance(path, (str, Path)) and str(path).endswith(BLOB_TMP_SUFFIX):
            raise PermissionError(errno.EACCES, "denied")
        return real_open(path, flags, mode)

    monkeypatch.setattr(os, "open", fake_open)

    with pytest.raises(BlobStoreIOError) as exc:
        await store.put(snapshot_id, _aiter(b"x"))
    assert "failed to open tmp file" in str(exc.value)


async def test_concurrent_put_through_tmp_open_path_raises_already_exists(
    store: FilesystemBlobStore,
    snapshot_id: UUID,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Force the tmp open to hit FileExistsError as if a concurrent put got there first.
    real_open = os.open

    def fake_open(path: Any, flags: int, mode: int = 0o777) -> int:
        if isinstance(path, (str, Path)) and str(path).endswith(BLOB_TMP_SUFFIX):
            raise FileExistsError(errno.EEXIST, "already")
        return real_open(path, flags, mode)

    monkeypatch.setattr(os, "open", fake_open)
    with pytest.raises(BlobAlreadyExistsError) as exc:
        await store.put(snapshot_id, _aiter(b"x"))
    assert "concurrent put" in str(exc.value)


async def test_put_remaps_oserror_on_snapshot_dir_create(
    store: FilesystemBlobStore,
    snapshot_id: UUID,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_makedirs = os.makedirs

    def fake_makedirs(path: Any, mode: int = 0o777, exist_ok: bool = False) -> None:
        if str(path).endswith(str(snapshot_id)):
            raise PermissionError(errno.EACCES, "denied")
        real_makedirs(path, mode, exist_ok)

    monkeypatch.setattr(os, "makedirs", fake_makedirs)

    with pytest.raises(BlobStoreIOError) as exc:
        await store.put(snapshot_id, _aiter(b"x"))
    assert "failed to create snapshot dir" in str(exc.value)


async def test_fsync_dir_tolerates_unsupported_filesystems(
    store: FilesystemBlobStore,
    snapshot_id: UUID,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_fsync = os.fsync

    def maybe_fail(fd: int) -> None:
        # Fail only on directory fds (best-effort detection via fstat S_ISDIR).
        st = os.fstat(fd)
        if stat.S_ISDIR(st.st_mode):
            raise OSError(errno.EINVAL, "directory fsync not supported")
        real_fsync(fd)

    monkeypatch.setattr(os, "fsync", maybe_fail)

    result = await store.put(snapshot_id, _aiter(b"resilient"))
    assert result.path.read_bytes() == b"resilient"
