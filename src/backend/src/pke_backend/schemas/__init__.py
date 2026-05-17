"""HTTP request/response models for the FastAPI surface.

Distinct from `pke_backend.protocol`, which holds the on-the-wire protocol payload
models (the 5 JSON-Schema-mirrored types) — those flow through canonicalize + sign
and must not be confused with the API contract models that live here.
"""
