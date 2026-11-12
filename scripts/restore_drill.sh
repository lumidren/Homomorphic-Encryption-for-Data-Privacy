#!/usr/bin/env bash
# Backup / restore drill (run in CI on every push, and monthly against staging per RUNBOOK).
#
#   1. migrate a fresh database and seed it through the real API code path
#   2. back up PostgreSQL (pg_dump, custom format) and the object store (bucket mirror)
#   3. destroy both
#   4. restore both from the backups
#   5. verify: row counts match, every object's SHA-256 matches its recorded fingerprint,
#      and the audit hash chain still verifies from genesis
#
# Requires: psql/pg_dump/pg_restore, aws CLI, a Postgres at $PGHOST (default 127.0.0.1) and an
# S3 endpoint at $S3_ENDPOINT (default http://127.0.0.1:9000).
set -euo pipefail

PGHOST="${PGHOST:-127.0.0.1}"
PGUSER="${PGUSER:-ciphercompute}"
PGDATABASE="${PGDATABASE:-ciphercompute}"
S3_ENDPOINT="${S3_ENDPOINT:-http://127.0.0.1:9000}"
BUCKET="${BUCKET:-cc-drill}"
WORK="$(mktemp -d)"
export PGHOST PGUSER PGDATABASE
export CC_DATABASE_URL="postgresql+asyncpg://${PGUSER}:${PGPASSWORD}@${PGHOST}:5432/${PGDATABASE}"
export CC_JWT_SECRET="drill-only-jwt-secret-with-at-least-32-bytes"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
s3() { aws --endpoint-url "$S3_ENDPOINT" s3 "$@"; }

echo "== 1. migrate + seed"
(cd "$ROOT/services/api" && alembic -c alembic.ini upgrade head)
python "$ROOT/scripts/drill_seed.py" seed --bucket "$BUCKET" --endpoint "$S3_ENDPOINT" > "$WORK/before.json"
cat "$WORK/before.json"

echo "== 2. back up"
pg_dump --format=custom --no-owner --file "$WORK/db.dump"
s3 sync "s3://$BUCKET" "$WORK/objects" --only-show-errors
echo "database dump: $(du -h "$WORK/db.dump" | cut -f1); objects: $(find "$WORK/objects" -type f | wc -l)"

echo "== 3. destroy"
psql -v ON_ERROR_STOP=1 -c "DROP SCHEMA public CASCADE; CREATE SCHEMA public;"
s3 rm "s3://$BUCKET" --recursive --only-show-errors

echo "== 4. restore"
pg_restore --no-owner --exit-on-error --dbname "$PGDATABASE" "$WORK/db.dump"
s3 sync "$WORK/objects" "s3://$BUCKET" --only-show-errors

echo "== 5. verify"
python "$ROOT/scripts/drill_seed.py" verify --bucket "$BUCKET" --endpoint "$S3_ENDPOINT" --expect "$WORK/before.json"
echo "restore drill passed"
rm -rf "$WORK"
