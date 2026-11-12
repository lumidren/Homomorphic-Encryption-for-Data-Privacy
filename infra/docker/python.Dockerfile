# syntax=docker/dockerfile:1.7
#
# One image definition for both Python services; SERVICE selects the entrypoint.
#   docker build -f infra/docker/python.Dockerfile --build-arg SERVICE=api    -t ciphercompute-api .
#   docker build -f infra/docker/python.Dockerfile --build-arg SERVICE=worker -t ciphercompute-worker .
#
# Stage 1 builds wheels (TenSEAL ships manylinux wheels; no compiler is needed at runtime).
# Stage 2 is a slim runtime: non-root user, no build tools, no package manager cache.

ARG PYTHON_VERSION=3.12

FROM python:${PYTHON_VERSION}-slim-bookworm AS build
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_CACHE_DIR=1
WORKDIR /src
COPY packages/core packages/core
COPY services/api services/api
COPY services/worker services/worker
RUN python -m pip wheel --wheel-dir /wheels ./packages/core ./services/api ./services/worker

FROM python:${PYTHON_VERSION}-slim-bookworm AS runtime
ARG SERVICE=api
ARG VERSION=0.1.0
LABEL org.opencontainers.image.title="ciphercompute-${SERVICE}" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.source="https://github.com/lumidren/Homomorphic-Encryption-for-Data-Privacy" \
      org.opencontainers.image.licenses="MIT"
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_CACHE_DIR=1 \
    SERVICE=${SERVICE} CC_VERSION=${VERSION}
RUN groupadd --system --gid 10001 app && useradd --system --uid 10001 --gid app --home-dir /app --shell /usr/sbin/nologin app
COPY --from=build /wheels /wheels
RUN python -m pip install --no-index --find-links=/wheels ciphercompute-api ciphercompute-worker && rm -rf /wheels
WORKDIR /app
COPY --chown=app:app services/api/alembic.ini /app/alembic.ini
COPY --chown=app:app services/api/alembic /app/alembic
COPY --chown=app:app infra/docker/entrypoint.sh /app/entrypoint.sh
RUN chmod 0555 /app/entrypoint.sh
USER 10001:10001
EXPOSE 8000 9100
HEALTHCHECK --interval=15s --timeout=3s --start-period=20s --retries=3 \
  CMD python -c "import os,urllib.request,sys; port='8000' if os.environ.get('SERVICE')=='api' else '9100'; path='/healthz' if port=='8000' else '/metrics'; sys.exit(0 if urllib.request.urlopen(f'http://127.0.0.1:{port}{path}', timeout=2).status==200 else 1)"
ENTRYPOINT ["/app/entrypoint.sh"]
