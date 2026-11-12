#!/bin/sh
# Entrypoint for the Python services. exec replaces the shell so SIGTERM reaches the server
# directly (graceful shutdown: gunicorn drains requests, Celery finishes the current job).
set -eu

case "${SERVICE:-api}" in
  api)
    if [ "${CC_RUN_MIGRATIONS:-0}" = "1" ]; then
      alembic -c /app/alembic.ini upgrade head
    fi
    exec gunicorn 'ciphercompute_api.app:create_app()' \
      --worker-class uvicorn.workers.UvicornWorker \
      --bind "0.0.0.0:${PORT:-8000}" \
      --workers "${WEB_CONCURRENCY:-2}" \
      --graceful-timeout "${GRACEFUL_TIMEOUT:-30}" \
      --timeout "${REQUEST_TIMEOUT:-120}" \
      --keep-alive 5 \
      --forwarded-allow-ips "${FORWARDED_ALLOW_IPS:-127.0.0.1}" \
      --access-logfile - \
      --error-logfile -
    ;;
  migrate)
    exec alembic -c /app/alembic.ini upgrade head
    ;;
  worker)
    exec celery -A ciphercompute_worker.celery_app worker \
      --loglevel "${LOG_LEVEL:-INFO}" \
      --concurrency 1 \
      --prefetch-multiplier 1 \
      --without-gossip --without-mingle
    ;;
  *)
    echo "unknown SERVICE=${SERVICE}" >&2
    exit 64
    ;;
esac
