"""Service-layer surfaces — stable imports for endpoint and downstream code."""

from __future__ import annotations

from pke_backend.services.attestations import (
    MAX_RETURNED_ATTESTATIONS,
    compute_attestation_etag,
    list_attestations,
)
from pke_backend.services.blob_storage import (
    BLOB_FILENAME,
    BLOB_TMP_SUFFIX,
    BlobAlreadyExistsError,
    BlobNotFoundError,
    BlobPutResult,
    BlobStore,
    BlobStoreError,
    BlobStoreIOError,
    FilesystemBlobStore,
    get_blob_store,
    reset_blob_store_cache,
)
from pke_backend.services.freezes import list_freezes_for_snapshot
from pke_backend.services.key_grants import (
    MAX_RETURNED_GRANTS,
    compute_grant_list_etag,
    compute_grant_singleton_etag,
    get_grant_or_404,
    list_grants_for_recipient,
)
from pke_backend.services.ledger import (
    LEDGER_LOCK_KEY,
    ChainVerification,
    LedgerCanonicalizationError,
    LedgerError,
    append_entry,
    get_head,
    verify_chain,
)
from pke_backend.services.reports import list_reports_for_snapshot
from pke_backend.services.snapshots import (
    fetch_snapshot_for_response,
    get_snapshot_or_404,
)

__all__ = [
    "BLOB_FILENAME",
    "BLOB_TMP_SUFFIX",
    "LEDGER_LOCK_KEY",
    "MAX_RETURNED_ATTESTATIONS",
    "MAX_RETURNED_GRANTS",
    "BlobAlreadyExistsError",
    "BlobNotFoundError",
    "BlobPutResult",
    "BlobStore",
    "BlobStoreError",
    "BlobStoreIOError",
    "ChainVerification",
    "FilesystemBlobStore",
    "LedgerCanonicalizationError",
    "LedgerError",
    "append_entry",
    "compute_attestation_etag",
    "compute_grant_list_etag",
    "compute_grant_singleton_etag",
    "fetch_snapshot_for_response",
    "get_blob_store",
    "get_grant_or_404",
    "get_head",
    "get_snapshot_or_404",
    "list_attestations",
    "list_freezes_for_snapshot",
    "list_grants_for_recipient",
    "list_reports_for_snapshot",
    "reset_blob_store_cache",
    "verify_chain",
]
