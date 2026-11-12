"""CipherCompute load test (Locust) — 128-bit security, poly_modulus_degree = 8192.

Setup (once per run, through the SDK): register an organization, generate an N=8192 / 128-bit
balanced key ring, upload its public bundle, upload ``CC_LT_CIPHERTEXTS`` full-width ciphertexts
(4,096 values each) and mint an API key. Simulated clients then submit statistics jobs over those
ciphertexts and poll them to completion. Each user keeps at most ``CC_LT_MAX_IN_FLIGHT`` jobs
outstanding (a closed loop, like a real analyst or pipeline). Job latency is reported as the
custom request type ``JOB`` using the server's own timestamps (``created_at`` -> ``finished_at``),
so it measures queueing plus execution and not how often the simulated client happened to poll.

    locust -f loadtest/locustfile.py --host http://127.0.0.1:8000 --headless -u 20 -r 5 -t 5m \
        --csv loadtest/results/run --html loadtest/results/run.html
"""

from __future__ import annotations

import os
import random
import threading
import time
import uuid
from datetime import datetime
from typing import Any

import numpy as np
from locust import HttpUser, between, events, task

from ciphercompute_client import CipherComputeClient, TransportConfig
from ciphercompute_core import KeyRing, standard_params

SHARED: dict[str, Any] = {}
MAX_IN_FLIGHT = int(os.environ.get("CC_LT_MAX_IN_FLIGHT", "4"))
_lock = threading.Lock()


@events.test_start.add_listener
def setup(environment, **_: Any) -> None:  # type: ignore[no-untyped-def]
    host = environment.host
    client = CipherComputeClient(host, transport_config=TransportConfig(allow_insecure_http=host.startswith("http://")))
    client.register(f"loadtest-{uuid.uuid4().hex[:8]}@example.com", uuid.uuid4().hex + "A!", "Load Test Org")
    ring = KeyRing.generate(standard_params(8192, 128))
    project = client.create_project("loadtest")
    bundle = client.upload_key_bundle(project["id"], ring)
    dataset = client.create_dataset(project["id"], "load", bundle["id"])
    rng = np.random.default_rng(1)
    count = int(os.environ.get("CC_LT_CIPHERTEXTS", "8"))
    cts = [
        client.encrypt_and_upload(dataset["id"], ring, rng.uniform(-10, 10, 4096), label=f"x{i}")["id"]
        for i in range(count)
    ]
    key = client.create_api_key("loadtest", ["jobs:read", "jobs:write", "datasets:read", "projects:read"])["secret"]
    SHARED.update(project=project["id"], ciphertexts=cts, api_key=key)
    print(f"load test ready: project {project['id']}, {len(cts)} ciphertexts of 4096 slots, N=8192/128-bit")


class Analyst(HttpUser):
    wait_time = between(0.2, 1.0)

    def on_start(self) -> None:
        self.client.headers.update({"Authorization": f"Bearer {SHARED['api_key']}"})
        self.pending: dict[str, float] = {}

    def _submit(self, operation: str, inputs: list[str], args: dict[str, Any] | None = None) -> None:
        if len(self.pending) >= MAX_IN_FLIGHT:
            self.poll()
            return
        body = {"operation": operation, "inputs": inputs, "args": args or {}}
        with self.client.post(
            f"/v1/projects/{SHARED['project']}/jobs",
            json=body,
            headers={"Idempotency-Key": f"lt-{uuid.uuid4().hex}"},
            name=f"POST /jobs ({operation})",
            catch_response=True,
        ) as response:
            if response.status_code == 202:
                self.pending[response.json()["id"]] = time.perf_counter()
                response.success()
            else:
                response.failure(f"{response.status_code} {response.text[:120]}")

    @task(4)
    def mean(self) -> None:
        self._submit("mean", [random.choice(SHARED["ciphertexts"])])

    @task(2)
    def dot_product(self) -> None:
        self._submit("dot_product", random.sample(SHARED["ciphertexts"], 2))

    @task(1)
    def variance(self) -> None:
        self._submit("variance", [random.choice(SHARED["ciphertexts"])])

    @task(6)
    def poll(self) -> None:
        if not self.pending:
            return
        job_id, submitted = next(iter(self.pending.items()))
        response = self.client.get(f"/v1/jobs/{job_id}", name="GET /jobs/{id}")
        if response.status_code != 200:
            return
        job = response.json()
        status = job["status"]
        if status in ("succeeded", "failed", "cancelled"):
            del self.pending[job_id]
            if job.get("created_at") and job.get("finished_at"):
                elapsed = datetime.fromisoformat(job["finished_at"]) - datetime.fromisoformat(job["created_at"])
                latency_ms = elapsed.total_seconds() * 1000
            else:  # cancelled before it ran: fall back to what the client observed
                latency_ms = (time.perf_counter() - submitted) * 1000
            events.request.fire(
                request_type="JOB",
                name="end-to-end (accepted -> succeeded)" if status == "succeeded" else f"end-to-end ({status})",
                response_time=latency_ms,
                response_length=0,
                exception=None if status == "succeeded" else RuntimeError(status),
                context={},
            )

    @task(1)
    def list_jobs(self) -> None:
        self.client.get("/v1/jobs", params={"limit": 20}, name="GET /jobs")
