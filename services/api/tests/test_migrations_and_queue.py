"""The Alembic migration matches the models; the Celery hand-off sends the right message."""

from __future__ import annotations

import os
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.exc import DBAPIError

from ciphercompute_api.config import Settings
from ciphercompute_api.queue import CeleryQueue, MemoryQueue, make_queue

API_DIR = Path(__file__).resolve().parents[1]


def _alembic(db: Path, *args: str) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "CC_DATABASE_URL": f"sqlite+aiosqlite:///{db.as_posix()}", "CC_JWT_SECRET": "m" * 40}
    return subprocess.run(  # noqa: S603 - fixed argv, test-only
        [sys.executable, "-m", "alembic", "-c", str(API_DIR / "alembic.ini"), *args],
        cwd=API_DIR,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


def test_migration_upgrade_check_downgrade(tmp_path: Path) -> None:
    db = tmp_path / "mig.db"
    up = _alembic(db, "upgrade", "head")
    assert up.returncode == 0, up.stderr
    check = _alembic(db, "check")
    assert check.returncode == 0 and "No new upgrade operations" in (check.stdout + check.stderr), check.stderr
    engine = create_engine(f"sqlite:///{db.as_posix()}")
    tables = set(inspect(engine).get_table_names())
    assert {
        "organizations",
        "users",
        "memberships",
        "projects",
        "key_bundles",
        "datasets",
        "ciphertexts",
        "jobs",
        "audit_events",
    } <= tables
    with engine.begin() as conn:
        org = uuid.uuid4().hex
        conn.execute(
            text("INSERT INTO organizations (id, name, slug, created_at) VALUES (:id, 'o', 's', '2026-01-01')"),
            {"id": org},
        )
        conn.execute(
            text(
                "INSERT INTO audit_events (id, organization_id, occurred_at, actor_type, action, resource_type, details, prev_hash, hash) "
                "VALUES (:id, :org, '2026-01-01', 'system', 'x', 'y', '{}', 'p', 'h')"
            ),
            {"id": uuid.uuid4().hex, "org": org},
        )
    with engine.connect() as conn, pytest.raises(DBAPIError, match="append-only"):
        conn.execute(text("UPDATE audit_events SET action = 'z'"))
    engine.dispose()
    down = _alembic(db, "downgrade", "base")
    assert down.returncode == 0, down.stderr


def test_offline_sql_targets_postgres_triggers(tmp_path: Path) -> None:
    env_url = "postgresql+asyncpg://u:p@localhost:5432/x"
    result = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "alembic", "-c", str(API_DIR / "alembic.ini"), "upgrade", "head", "--sql"],
        cwd=API_DIR,
        env={**os.environ, "CC_DATABASE_URL": env_url, "CC_JWT_SECRET": "m" * 40},
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    sql = result.stdout
    assert "CREATE TABLE audit_events" in sql
    assert "RAISE EXCEPTION 'audit_events is append-only'" in sql
    assert "BEFORE TRUNCATE ON audit_events" in sql


class _FakeCelery:
    def __init__(self) -> None:
        self.sent: list[tuple[str, dict[str, Any]]] = []
        self.conf = self

    def update(self, **_: Any) -> None:
        return None

    def send_task(self, name: str, **kwargs: Any) -> None:
        self.sent.append((name, kwargs))


async def test_celery_queue_sends_task_by_name() -> None:
    settings = Settings(jwt_secret="q" * 40, queue_backend="celery", redis_url="redis://localhost:6399/0")
    queue = make_queue(settings)
    assert isinstance(queue, CeleryQueue)
    fake = _FakeCelery()
    queue._app = fake  # type: ignore[assignment]
    job, org = uuid.uuid4(), uuid.uuid4()
    await queue.enqueue(job, org)
    assert fake.sent == [
        (
            "ciphercompute_worker.tasks.execute_job",
            {"args": [str(job)], "kwargs": {"organization_id": str(org)}, "task_id": str(job)},
        )
    ]
    # no broker listening on 6399: ping reports unhealthy instead of raising
    assert await CeleryQueue(settings).ping() is False


def test_memory_queue_selected_for_tests() -> None:
    assert isinstance(make_queue(Settings(jwt_secret="q" * 40, queue_backend="memory")), MemoryQueue)
