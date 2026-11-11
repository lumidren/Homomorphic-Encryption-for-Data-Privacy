"""Alembic environment: async engine, URL from ``CC_DATABASE_URL``."""

from __future__ import annotations

import asyncio
import os

from alembic import context
from sqlalchemy.engine import Connection

from ciphercompute_api.db import models  # noqa: F401 - registers every table on the metadata
from ciphercompute_api.db.base import Base, make_engine

config = context.config
target_metadata = Base.metadata


def _url() -> str:
    url = os.environ.get("CC_DATABASE_URL") or config.get_main_option("sqlalchemy.url")
    if not url:
        raise RuntimeError("set CC_DATABASE_URL, e.g. postgresql+asyncpg://user:pass@host:5432/ciphercompute")
    return url


def run_migrations_offline() -> None:
    context.configure(url=_url(), target_metadata=target_metadata, literal_binds=True, compare_type=True)
    with context.begin_transaction():
        context.run_migrations()


def _run(connection: Connection) -> None:
    context.configure(connection=connection, target_metadata=target_metadata, compare_type=True, render_as_batch=True)
    with context.begin_transaction():
        context.run_migrations()


async def run_migrations_online() -> None:
    engine = make_engine(_url())
    async with engine.connect() as connection:
        await connection.run_sync(_run)
    await engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    asyncio.run(run_migrations_online())
