"""Tests for ``api.errors`` — HTTPError envelope + handler registration (HLAM-79).

Spins up a minimal ``FastAPI`` instance with handlers attached and a couple
of mock endpoints that raise each error type. Asserts status code, envelope
shape, and that raw input bytes never appear in the response body.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest
from fastapi import FastAPI
from pydantic import BaseModel

from pke_backend.api.errors import HTTPError, register_exception_handlers
from pke_backend.crypto.errors import SignatureFormatError, SignatureVerificationError


class _Payload(BaseModel):
    n: int


def _build_app() -> FastAPI:
    app = FastAPI()
    register_exception_handlers(app)

    @app.get("/raise-http-error")
    def _raise_http_error() -> None:
        raise HTTPError(404, "snapshot_not_found", "snapshot abc does not exist")

    @app.get("/raise-sig-format")
    def _raise_sig_format() -> None:
        raise SignatureFormatError(reason="length 63 != 64")

    @app.get("/raise-sig-verify")
    def _raise_sig_verify() -> None:
        raise SignatureVerificationError(reason="signature did not validate")

    @app.post("/typed-body")
    def _typed_body(payload: _Payload) -> dict[str, int]:
        return {"received": payload.n}

    return app


@pytest.fixture
def client() -> httpx.AsyncClient:
    transport = httpx.ASGITransport(app=_build_app())
    return httpx.AsyncClient(transport=transport, base_url="http://test")


def test_http_error_constructor_stores_attributes() -> None:
    exc = HTTPError(409, "snapshot_already_frozen", "...")
    assert exc.status_code == 409
    assert exc.error == "snapshot_already_frozen"
    assert exc.detail == "..."
    assert "409" in str(exc)
    assert "snapshot_already_frozen" in str(exc)


@pytest.mark.asyncio
async def test_http_error_maps_to_envelope(client: httpx.AsyncClient) -> None:
    async with client:
        response = await client.get("/raise-http-error")
    assert response.status_code == 404
    body: dict[str, Any] = response.json()
    assert body == {"error": "snapshot_not_found", "detail": "snapshot abc does not exist"}


@pytest.mark.asyncio
async def test_signature_format_error_maps_to_401(client: httpx.AsyncClient) -> None:
    async with client:
        response = await client.get("/raise-sig-format")
    assert response.status_code == 401
    body: dict[str, Any] = response.json()
    assert body["error"] == "signature_invalid"
    # The handler must NOT leak the validator's ``reason`` (which could
    # include lengths / coordinate hints) into the response.
    assert "63" not in body["detail"]


@pytest.mark.asyncio
async def test_signature_verification_error_maps_to_401(client: httpx.AsyncClient) -> None:
    async with client:
        response = await client.get("/raise-sig-verify")
    assert response.status_code == 401
    body: dict[str, Any] = response.json()
    assert body["error"] == "signature_invalid"
    assert "did not validate" not in body["detail"]


@pytest.mark.asyncio
async def test_request_validation_error_maps_to_422(client: httpx.AsyncClient) -> None:
    async with client:
        response = await client.post("/typed-body", json={"n": "not-an-int"})
    assert response.status_code == 422
    body: dict[str, Any] = response.json()
    assert body["error"] == "invalid_payload"
    assert isinstance(body["detail"], str)
    assert body["detail"]


@pytest.mark.asyncio
async def test_validation_detail_is_truncated_for_very_large_inputs(
    client: httpx.AsyncClient,
) -> None:
    big_string = "x" * 5000
    async with client:
        response = await client.post("/typed-body", json={"n": big_string})
    assert response.status_code == 422
    body: dict[str, Any] = response.json()
    # Cap is 512 + the truncation marker; allow generous slack.
    assert len(body["detail"]) < 1024
