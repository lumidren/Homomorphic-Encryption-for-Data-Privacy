# ciphercompute-api

FastAPI service for CipherCompute. It authenticates users and API keys, enforces tenant
isolation and RBAC, accepts public key bundles (rejecting any that contain a secret key),
issues presigned uploads for ciphertexts, refuses jobs that would exhaust the multiplicative
depth of their parameters, enqueues the rest for the worker, and keeps a hash-chained audit log.

```bash
export CC_JWT_SECRET=$(python -c "import secrets; print(secrets.token_urlsafe(48))")
alembic -c services/api/alembic.ini upgrade head
gunicorn 'ciphercompute_api.app:create_app()' -k uvicorn.workers.UvicornWorker -b 0.0.0.0:8000
```

Interactive API reference: `http://localhost:8000/docs` (OpenAPI 3.1 at `/openapi.json`).
Every variable is documented in the repository's `.env.example`.
