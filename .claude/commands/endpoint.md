Scaffold a new API endpoint for the pke backend.

Before writing any code:
1. Read the existing route files in `src/backend/src/pke_backend/` to understand current patterns (router structure, dependency injection, response models)
2. Read the data model at `/context/05_data_model_public.md` for schema reference
3. Read the protocol overview at `/context/04_protocol_overview.md` for domain context

Then create the endpoint for: $ARGUMENTS

Follow these conventions:
- FastAPI router in its own module or grouped with related routes
- Pydantic models for request/response schemas
- Async SQLAlchemy for database access
- Proper HTTP status codes and error responses
- Type annotations on all function signatures
- Security: validate auth, sanitize inputs, never expose key material

After scaffolding, run `make ci` to verify the new code passes all checks.
