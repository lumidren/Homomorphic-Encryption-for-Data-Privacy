#!/usr/bin/env python3
"""Generate infra/observability/grafana/dashboards/ciphercompute.json.

The dashboard is code: edit the panel list here, run the script, commit both files. CI runs it
with ``--check`` so the committed JSON can never drift from this source.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

OUT = Path(__file__).resolve().parents[1] / "infra" / "observability" / "grafana" / "dashboards" / "ciphercompute.json"
DS = {"type": "prometheus", "uid": "prometheus"}


def panel(
    title: str,
    exprs: list[tuple[str, str]],
    *,
    unit: str = "short",
    kind: str = "timeseries",
    w: int = 12,
    h: int = 8,
    description: str = "",
) -> dict[str, Any]:
    return {
        "type": kind,
        "title": title,
        "description": description,
        "datasource": DS,
        "gridPos": {"w": w, "h": h},
        "fieldConfig": {"defaults": {"unit": unit}, "overrides": []},
        "options": {"legend": {"displayMode": "list", "placement": "bottom"}} if kind == "timeseries" else {},
        "targets": [
            {"datasource": DS, "expr": expr, "legendFormat": legend, "refId": chr(65 + i)}
            for i, (expr, legend) in enumerate(exprs)
        ],
    }


def quantiles(metric: str, by: str = "") -> list[tuple[str, str]]:
    grouping = f"le{', ' + by if by else ''}"
    suffix = f" {{{{{by}}}}}" if by else ""
    return [
        (f"histogram_quantile({q}, sum by ({grouping}) (rate({metric}_bucket[5m])))", f"p{int(q * 100)}{suffix}")
        for q in (0.5, 0.95, 0.99)
    ]


def build() -> dict[str, Any]:
    panels = [
        panel(
            "Job compute latency (p50 / p95 / p99)",
            quantiles("ciphercompute_job_compute_seconds"),
            unit="s",
            description="Download, integrity checks, homomorphic evaluation and upload, per job.",
        ),
        panel(
            "Job end-to-end latency (p50 / p95 / p99)",
            quantiles("ciphercompute_job_end_to_end_seconds"),
            unit="s",
            description="Submission to completion, including queue wait.",
        ),
        panel("Queue depth", [("ciphercompute_queue_depth", "queued jobs")], w=8),
        panel("Busy workers", [("sum(ciphercompute_worker_busy)", "busy")], w=8),
        panel(
            "Queue wait (p95)",
            [("histogram_quantile(0.95, sum by (le) (rate(ciphercompute_job_queue_wait_seconds_bucket[5m])))", "p95")],
            unit="s",
            w=8,
        ),
        panel(
            "Jobs finished by status",
            [("sum by (status) (rate(ciphercompute_jobs_finished_total[5m]))", "{{status}}")],
            unit="ops",
        ),
        panel(
            "Per-tenant throughput",
            [
                (
                    'topk(10, sum by (organization) (rate(ciphercompute_jobs_finished_total{status="succeeded"}[5m])))',
                    "{{organization}}",
                )
            ],
            unit="ops",
            description="Top 10 organizations by successful jobs per second.",
        ),
        panel(
            "Noise-budget usage: share of multiplicative depth consumed (p50 / p95)",
            [
                (
                    f"histogram_quantile({q}, sum by (le, operation) "
                    "(rate(ciphercompute_job_levels_consumed_ratio_bucket[15m])))",
                    f"p{int(q * 100)} {{{{operation}}}}",
                )
                for q in (0.5, 0.95)
            ],
            unit="percentunit",
            description="1.0 means a job used every level of its parameter set's modulus chain.",
        ),
        panel(
            "Ciphertext sizes (p50 / p95)",
            [
                (
                    "histogram_quantile(0.5, sum by (le) (rate(ciphercompute_ciphertext_input_bytes_bucket[15m])))",
                    "input p50",
                ),
                (
                    "histogram_quantile(0.95, sum by (le) (rate(ciphercompute_ciphertext_input_bytes_bucket[15m])))",
                    "input p95",
                ),
                (
                    "histogram_quantile(0.95, sum by (le) (rate(ciphercompute_result_ciphertext_bytes_bucket[15m])))",
                    "result p95",
                ),
            ],
            unit="bytes",
        ),
        panel(
            "Jobs refused before enqueue",
            [("sum by (reason) (rate(ciphercompute_jobs_refused_total[15m]))", "{{reason}}")],
            unit="ops",
            description="depth_exhausted means clients chose parameters too shallow for the computation.",
        ),
        panel(
            "HTTP requests by status",
            [("sum by (status) (rate(ciphercompute_http_requests_total[5m]))", "{{status}}")],
            unit="reqps",
        ),
        panel(
            "HTTP latency p95 by route",
            quantiles("ciphercompute_http_request_duration_seconds", by="route")[1:2],
            unit="s",
        ),
        panel(
            "Retries by reason",
            [("sum by (reason) (rate(ciphercompute_job_retries_total[15m]))", "{{reason}}")],
            unit="ops",
            w=8,
        ),
        panel(
            "Tenants throttled",
            [("sum by (organization) (rate(ciphercompute_tenant_throttled_total[15m]))", "{{organization}}")],
            unit="ops",
            w=8,
        ),
        panel("Audit chain valid", [("min(ciphercompute_audit_chain_valid)", "valid")], kind="stat", w=8),
    ]
    x = y = 0
    for i, p in enumerate(panels, start=1):
        width, height = p["gridPos"]["w"], p["gridPos"]["h"]
        if x + width > 24:
            x, y = 0, y + height
        p["id"] = i
        p["gridPos"].update(x=x, y=y)
        x += width
    return {
        "uid": "ciphercompute-overview",
        "title": "CipherCompute — service overview",
        "tags": ["ciphercompute"],
        "timezone": "utc",
        "schemaVersion": 39,
        "version": 1,
        "editable": False,
        "refresh": "30s",
        "time": {"from": "now-6h", "to": "now"},
        "panels": panels,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="fail if the committed JSON is stale")
    args = parser.parse_args()
    rendered = json.dumps(build(), indent=2, ensure_ascii=False) + "\n"
    if args.check:
        if not OUT.exists() or OUT.read_text(encoding="utf-8") != rendered:
            print(f"{OUT} is stale; run scripts/build_grafana_dashboard.py", file=sys.stderr)
            return 1
        return 0
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(rendered, encoding="utf-8")
    print(f"wrote {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
