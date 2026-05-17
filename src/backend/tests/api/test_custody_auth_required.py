"""HLAM-122 S8 — bearer auth required on custody POST routers.

The S8 story applies ``Depends(require_user)`` at the router level on the
ledger-mutating endpoints. Only ``POST /reports`` and ``POST /freezes``
exist on dev at the time of writing; the read-only GET surfaces stay
public per the design contract in ``context/05_data_model_public.md``
(``/snapshots/{id}``, ``/snapshots/{id}/blob``, ``/snapshots/{id}/attestations``,
``/key-grants[*]``).

These tests use the dedicated :func:`tests.api.conftest.unauth_client`
fixture so the default authenticated ``client`` does not mask the
negative paths.
"""

from __future__ import annotations

import uuid

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from tests.api.conftest import build_signed_freeze, build_signed_report


@pytest.fixture
def signer() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


# ---------------- POST /reports ----------------


async def test_post_reports_missing_bearer_returns_401(
    unauth_client: httpx.AsyncClient,
    signer: ec.EllipticCurvePrivateKey,
) -> None:
    payload = build_signed_report(snapshot_id=uuid.uuid4(), signer=signer)
    response = await unauth_client.post("/reports", json=payload)
    assert response.status_code == 401
    body = response.json()
    assert body["error"]["code"] == "unauthenticated"
    assert "message" in body["error"]


async def test_post_reports_malformed_bearer_returns_401(
    unauth_client: httpx.AsyncClient,
    signer: ec.EllipticCurvePrivateKey,
) -> None:
    payload = build_signed_report(snapshot_id=uuid.uuid4(), signer=signer)
    response = await unauth_client.post(
        "/reports",
        json=payload,
        headers={"Authorization": "Token abc"},
    )
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "unauthenticated"


async def test_post_reports_unknown_bearer_returns_401(
    unauth_client: httpx.AsyncClient,
    signer: ec.EllipticCurvePrivateKey,
) -> None:
    payload = build_signed_report(snapshot_id=uuid.uuid4(), signer=signer)
    response = await unauth_client.post(
        "/reports",
        json=payload,
        headers={"Authorization": "Bearer not-a-real-token"},
    )
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "unauthenticated"


# ---------------- POST /freezes ----------------


async def test_post_freezes_missing_bearer_returns_401(
    unauth_client: httpx.AsyncClient,
    signer: ec.EllipticCurvePrivateKey,
) -> None:
    payload = build_signed_freeze(
        snapshot_id=uuid.uuid4(),
        triggered_by="report_count_threshold",
        signer=signer,
    )
    response = await unauth_client.post("/freezes", json=payload)
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "unauthenticated"


async def test_post_freezes_unknown_bearer_returns_401(
    unauth_client: httpx.AsyncClient,
    signer: ec.EllipticCurvePrivateKey,
) -> None:
    payload = build_signed_freeze(
        snapshot_id=uuid.uuid4(),
        triggered_by="report_count_threshold",
        signer=signer,
    )
    response = await unauth_client.post(
        "/freezes",
        json=payload,
        headers={"Authorization": "Bearer not-a-real-token"},
    )
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "unauthenticated"
