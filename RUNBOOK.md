# CipherCompute — On-call Runbook

Every alert in `infra/observability/prometheus/alerts.yml` links to a section here (CI checks
the links). Each section: **what it means → how to confirm → what to do → when to escalate.**

Golden rule: the service never holds secret keys or plaintext. No incident procedure ever
requires, or may ask a customer for, a secret key or decrypted data.

Quick references

```bash
kubectl -n ciphercompute get pods -o wide
kubectl -n ciphercompute logs deploy/ciphercompute-api --since=15m | jq 'select(.level=="error")'
kubectl -n ciphercompute logs deploy/ciphercompute-worker --since=15m | jq 'select(.event|test("job_"))'
helm -n ciphercompute history ciphercompute
```

Dashboards: Grafana → *CipherCompute — service overview*. Traces: Jaeger, search by
`request_id` (every API response carries `X-Request-ID`; every log line has it too).

---

## API high error rate

**Means:** more than 2% of API responses are 5xx for 5 minutes.

1. Grafana *HTTP requests by status* + *HTTP latency p95 by route*: is it one route or all?
2. `GET /readyz` on a pod shows which dependency is down (`database`, `redis`, `object_storage`, `queue`).
3. Logs: `event == "unhandled_error"` with `request_id`; open the trace in Jaeger.
4. Started right after a deploy? → [Roll back a release](#roll-back-a-release).
5. A dependency is down → RDS / ElastiCache / S3 status in the AWS console; CloudWatch alarms
   `*-rds-cpu`, `*-redis-memory`.

Escalate if the error rate is above 10% for 15 minutes or any data-integrity error appears.

## API latency high

**Means:** p95 above 1 s (uploads and event streams excluded) for 10 minutes.

1. Slow database? RDS Performance Insights; `log_min_duration_statement` captures queries > 500 ms.
2. CPU-bound pods? `kubectl top pods`; the HPA should be adding replicas — check
   `kubectl -n ciphercompute describe hpa ciphercompute-api`.
3. Key bundle uploads are parsed in the API (the secret-key gate). Many concurrent N=16384/32768
   bundle uploads raise CPU; they are bounded by `CC_RATE_LIMIT_PER_MINUTE` and the ingress body limit.

## API down

**Means:** Prometheus cannot scrape an API instance for 2 minutes.

1. `kubectl get pods`: CrashLoopBackOff → `kubectl logs --previous`. A common cause is a
   missing/short `CC_JWT_SECRET` (the process refuses to start with < 32 bytes) after a secret edit.
2. Pending pods → node capacity; check the cluster autoscaler.
3. If all replicas are down, roll back: [Roll back a release](#roll-back-a-release).

## Audit chain broken

**Means:** `GET /v1/audit/verify` reported a broken hash chain for an organization. **Treat as a
security incident** — either someone with database access modified history or there is a bug.

1. Do not "fix" the data. Snapshot the database immediately (AWS Backup on-demand).
2. `GET /v1/audit/verify` for the organization → `first_broken_seq` and `reason`.
3. The PostgreSQL trigger blocks `UPDATE`/`DELETE`/`TRUNCATE` on `audit_events`; a break means
   the trigger was disabled or the rows were written outside the API. Check RDS logs and
   CloudTrail for `ALTER TABLE … DISABLE TRIGGER`, superuser sessions, and snapshot restores.
4. Notify the security lead and the affected organization's owner (SECURITY.md process).

## Queue depth high

**Means:** more than 200 jobs queued for 10 minutes.

1. Are workers scaling? `kubectl describe hpa ciphercompute-worker` (external metric
   `ciphercompute_queue_depth`). If the metric is missing, check the Prometheus Adapter.
2. Are workers busy (Grafana *Busy workers*) but slow? Look at *Job compute latency* by
   `poly_modulus_degree` — N=32768 jobs take minutes each.
3. Node group at max? Raise `max_size` of the `fhe` node group in Terraform.
4. One tenant flooding? *Per-tenant throughput* + [Tenant throttled](#tenant-throttled).

## Worker starvation

**Means:** jobs are queued but no worker has been busy for 5 minutes, or no worker is scraped.

1. `kubectl get pods -l app.kubernetes.io/component=worker` — running?
2. Logs for `worker_process_started`. Broker reachable? `redis-cli -h <elasticache> --tls ping`.
3. Visibility timeout too short makes Redis redeliver long jobs repeatedly; it is set to twice the
   hard time limit in `celery_app.py` — confirm the deployed version.
4. Stuck `running` jobs from a crashed worker are reclaimed automatically after
   `job_hard_time_limit + 60 s`; nothing to do unless that also fails.

## Job failures

**Means:** more than 10% of jobs failed over 15 minutes. Read the `error.code` of failed jobs:

| code | meaning | action |
|---|---|---|
| `input_integrity` / `bundle_integrity` | stored bytes no longer match the fingerprint recorded at upload | **Security**: possible storage tampering. Snapshot the bucket (versioning keeps the prior object), follow the [Audit chain broken](#audit-chain-broken) steps. |
| `depth_mismatch` | ciphertext consumed more levels than planned (forged header or library change) | Check TenSEAL version drift between API and worker images. |
| `bundle_revoked`, `input_missing` | user revoked/deleted while queued | none |
| `retries_exhausted` | storage/DB/broker unavailable across 5 attempts | fix the dependency; users can resubmit (idempotency key protects duplicates) |
| `time_limit_exceeded` | job above the 600 s soft limit | the user should split the job or use a smaller ring |
| `starved` | waited longer than `max_queue_wait_seconds` for a tenant slot | see [Tenant throttled](#tenant-throttled) |
| `execution_error` | unexpected exception | trace by `job_id` in logs; file a bug |

## Tenant throttled

**Means:** an organization keeps hitting its concurrency limit (`CC_TENANT_MAX_CONCURRENT_JOBS`;
N=16384 jobs weigh 2, N=32768 weigh 4). This protects other tenants. Raise the limit only for a
paying plan that justifies it, then roll the worker deployment so the setting takes effect.

---

## Roll back a release

Deploys use `helm upgrade --atomic`, so a failed rollout rolls back by itself, and the deploy job
rolls back when post-deploy health checks fail. Manual rollback:

```bash
helm -n ciphercompute history ciphercompute
helm -n ciphercompute rollback ciphercompute <REVISION> --wait
```

Migrations are expand/contract (backward compatible with the previous release), so rolling back
the application never requires rolling back the schema.

## Restore from backup

Backups: AWS Backup daily + continuous (point-in-time) for RDS and the data bucket, retained
`backup_retention_days` (35); RDS automated backups; S3 versioning. The procedure below is the
one `scripts/restore_drill.sh` exercises in CI on every push.

1. Declare the incident; stop writes: `kubectl -n ciphercompute scale deploy --all --replicas=0`.
2. **Database:** AWS Backup → recovery point (or RDS point-in-time restore) → restore to a *new*
   instance `ciphercompute-<env>-restored`. Never overwrite the original until verified.
3. **Objects:** AWS Backup → S3 recovery point → restore into the same bucket (versioned) or a new
   bucket; for single objects, restore a previous version.
4. Point the application secret's `CC_DATABASE_URL` at the restored instance, start the API only
   (`--replicas=1`), then verify:
   - `GET /v1/audit/verify` is valid for every organization;
   - a sample of ciphertexts: object SHA-256 == `ciphertexts.fingerprint`
     (`scripts/drill_seed.py verify` automates both).
5. Scale everything back up; keep the original instance for 7 days, then delete.

RPO: ~5 minutes (continuous backups). RTO: under 1 hour for the database at current sizes.

## Key rotation

**Customer CKKS keys** (the customer acts; we never see the secret key):

1. `ciphercompute keys generate ./keys-new` and upload the new public bundle to the project.
2. Re-encrypt datasets locally under the new ring and upload them to new datasets.
3. Revoke the old bundle (`POST /v1/key-bundles/{id}/revoke`): no new jobs can run under it.
4. Delete the old datasets once nothing needs them.

**API keys:** create the replacement, deploy it to the consumer, revoke the old key. Every use
is in the audit log (`api_key` actor).

## Rotate JWT secret

1. In Secrets Manager / Vault set `CC_JWT_PREVIOUS_SECRET` = current `CC_JWT_SECRET` and
   `CC_JWT_PREVIOUS_KID` = current `CC_JWT_KID`; set a new random `CC_JWT_SECRET` and a new kid.
2. Wait for External Secrets to sync (`refreshInterval`), then `kubectl rollout restart deploy/ciphercompute-api`.
3. After the access-token lifetime (15 min) remove `CC_JWT_PREVIOUS_SECRET`.
   If the old secret leaked, skip step 3's grace period: remove it immediately (all sessions re-login).

## Bootstrap secrets

For a new environment, after `terraform apply`:

1. Read the RDS master secret ARN (`terraform output db_master_secret_arn`) and create an
   application database role with least privilege (no `TRUNCATE`/`DELETE` on `audit_events`).
2. Fill the application secret (`terraform output app_secret_arn`) with `CC_JWT_SECRET`
   (≥ 32 random bytes), `CC_DATABASE_URL`, `CC_REDIS_URL` (the ElastiCache auth token from
   Terraform state, TLS: `rediss://`) and `CC_S3_KMS_KEY_ID`.
3. Install the External Secrets Operator with a `ClusterSecretStore` named as in `values.yaml`.
