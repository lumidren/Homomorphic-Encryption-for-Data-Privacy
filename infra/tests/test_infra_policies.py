"""Static policy checks over the deployment configuration (no cluster or cloud needed).

These pin the security properties the threat model relies on (TM:S-4, TM:T-4, TM:E-3, TM:I-7)
so a careless edit to a template or config fails CI.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
INFRA = ROOT / "infra"
HELM = INFRA / "helm" / "ciphercompute"


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


# ----- edge / TLS ----------------------------------------------------------------------------------


def test_nginx_tls13_only_and_metrics_blocked() -> None:
    conf = read(INFRA / "nginx" / "nginx.conf")
    protocols = re.findall(r"ssl_protocols\s+([^;]+);", conf)
    assert protocols == ["TLSv1.3"], protocols
    assert "Strict-Transport-Security" in conf
    assert "location = /metrics { return 404; }" in conf
    assert "server_tokens off" in conf
    assert "ssl_verify_client optional" in conf
    # the only plaintext listener redirects
    plain = re.search(r"listen 8080;\s*return 308 https://", conf)
    assert plain is not None


def test_mtls_policies() -> None:
    assert '"^FAILED"' in read(INFRA / "nginx" / "conf.d" / "mtls-policy.conf")
    assert '!= "SUCCESS"' in read(INFRA / "nginx" / "conf.d" / "mtls-required.conf")


def test_ingress_and_alb_enforce_tls13() -> None:
    assert 'nginx.ingress.kubernetes.io/ssl-protocols: "TLSv1.3"' in read(HELM / "templates" / "ingress.yaml")
    assert "cert-manager.io/cluster-issuer" in read(HELM / "templates" / "ingress.yaml")
    assert 'ssl_policy      = "ELBSecurityPolicy-TLS13-1-3-2021-06"' in read(INFRA / "terraform" / "alb_waf.tf")


# ----- workloads -------------------------------------------------------------------------------------


def test_every_workload_is_hardened() -> None:
    helpers = read(HELM / "templates" / "_helpers.tpl")
    for needle in (
        "runAsNonRoot: true",
        "type: RuntimeDefault",
        "allowPrivilegeEscalation: false",
        "readOnlyRootFilesystem: true",
        'drop: ["ALL"]',
    ):
        assert needle in helpers, needle
    for name in ("api.yaml", "worker.yaml", "dashboard.yaml", "migrations.yaml"):
        text = read(HELM / "templates" / name)
        assert 'include "cc.podSecurityContext"' in text, name
        assert 'include "cc.containerSecurityContext"' in text, name


def test_zero_downtime_rollouts_and_disruption_budgets() -> None:
    for name in ("api.yaml", "worker.yaml", "dashboard.yaml"):
        text = read(HELM / "templates" / name)
        assert "maxUnavailable: 0" in text, name
        assert "kind: PodDisruptionBudget" in text, name
        assert "kind: HorizontalPodAutoscaler" in text, name
    api = read(HELM / "templates" / "api.yaml")
    assert "readinessProbe" in api and "/readyz" in api and "livenessProbe" in api and "preStop" in api
    assert "type: External" in read(HELM / "templates" / "worker.yaml")


def test_network_policy_default_deny_and_dashboard_isolation() -> None:
    text = read(HELM / "templates" / "networkpolicy.yaml")
    assert "default-deny" in text and "policyTypes: [Ingress, Egress]" in text
    dashboard = text.split("-dashboard\n", 1)[1].split("---", 1)[0]
    assert "5432" not in dashboard and "6379" not in dashboard, "the dashboard must not reach the database or Redis"


def test_no_secrets_in_values_or_compose() -> None:
    for path in (
        HELM / "values.yaml",
        HELM / "values-prod.yaml",
        HELM / "values-staging.yaml",
        ROOT / "docker-compose.yml",
    ):
        text = read(path)
        assert not re.search(r"(?i)(password|secret|token)\s*:\s*['\"]?[A-Za-z0-9+/=_-]{12,}", text), path
    compose = yaml.safe_load(read(ROOT / "docker-compose.yml"))
    for name in ("api", "worker", "migrate", "dashboard"):
        svc = compose["services"][name]
        assert svc["read_only"] is True and svc["cap_drop"] == ["ALL"], name


def test_prometheus_rules_cover_required_alerts_and_chart_copy_is_identical() -> None:
    source = read(INFRA / "observability" / "prometheus" / "alerts.yml")
    assert source == read(HELM / "files" / "alerts.yml"), (
        "run: cp infra/observability/prometheus/alerts.yml infra/helm/ciphercompute/files/"
    )
    rules = {r["alert"] for g in yaml.safe_load(source)["groups"] for r in g["rules"]}
    assert {"ApiHighErrorRate", "QueueDepthHigh", "WorkerStarvation"} <= rules
    # every alert links to a runbook section that exists (GitHub heading slugs)
    headings = re.findall(r"^#{1,6}\s+(.+?)\s*$", read(ROOT / "RUNBOOK.md"), re.M)
    slugs = {re.sub(r"[^a-z0-9 -]", "", h.lower()).strip().replace(" ", "-") for h in headings}
    for group in yaml.safe_load(source)["groups"]:
        for rule in group["rules"]:
            anchor = rule["annotations"]["runbook"].split("#", 1)[1]
            assert anchor in slugs, f"{rule['alert']} links to missing RUNBOOK section #{anchor}"


# ----- cloud ------------------------------------------------------------------------------------------


def test_storage_encryption_and_transport_rules() -> None:
    s3 = read(INFRA / "terraform" / "s3.tf")
    assert 'sse_algorithm     = "aws:kms"' in s3
    assert "DenyInsecureTransport" in s3 and "DenyUnencryptedUploads" in s3
    assert "block_public_policy     = true" in s3
    rds = read(INFRA / "terraform" / "rds.tf")
    assert "storage_encrypted     = true" in rds and "manage_master_user_password   = true" in rds
    assert '"rds.force_ssl"' in rds
    redis = read(INFRA / "terraform" / "elasticache.tf")
    assert "transit_encryption_enabled = true" in redis and "at_rest_encryption_enabled = true" in redis


def test_backups_cover_database_and_objects() -> None:
    tf = read(INFRA / "terraform" / "observability_backup.tf")
    assert "aws_db_instance.main.arn" in tf and "aws_s3_bucket.data.arn" in tf
    assert "enable_continuous_backup = true" in tf


def test_waf_and_alarm_coverage() -> None:
    waf = read(INFRA / "terraform" / "alb_waf.tf")
    for group in (
        "AWSManagedRulesCommonRuleSet",
        "AWSManagedRulesKnownBadInputsRuleSet",
        "AWSManagedRulesAmazonIpReputationList",
    ):
        assert group in waf
    assert "rate_based_statement" in waf
    alarms = read(INFRA / "terraform" / "observability_backup.tf")
    for alarm in ("alb-5xx", "rds-cpu", "rds-free-storage", "redis-memory"):
        assert alarm in alarms


def test_dockerfiles_run_as_non_root() -> None:
    for name in ("python.Dockerfile", "dashboard.Dockerfile"):
        text = read(INFRA / "docker" / name)
        assert "USER 10001:10001" in text, name
        assert text.count("FROM ") >= 2, f"{name} must be multi-stage"
        assert "HEALTHCHECK" in text, name
