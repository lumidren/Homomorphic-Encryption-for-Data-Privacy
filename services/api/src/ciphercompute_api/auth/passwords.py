"""Argon2id password hashing (RFC 9106 second recommended parameter set by default)."""

from __future__ import annotations

from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from ..config import Settings


class PasswordService:
    def __init__(self, settings: Settings) -> None:
        # [TM:S-1] Argon2id, 64 MiB memory, 3 iterations, 4 lanes: slow enough to make offline
        # guessing expensive, fast enough for interactive login.
        self._hasher = PasswordHasher(
            time_cost=settings.argon2_time_cost,
            memory_cost=settings.argon2_memory_kib,
            parallelism=settings.argon2_parallelism,
            hash_len=32,
            salt_len=16,
            type=Type.ID,
        )

    def hash(self, password: str) -> str:
        return self._hasher.hash(password)

    def verify(self, password: str, password_hash: str) -> bool:
        try:
            return self._hasher.verify(password_hash, password)
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            return False

    def needs_rehash(self, password_hash: str) -> bool:
        return self._hasher.check_needs_rehash(password_hash)

    @property
    def parameters(self) -> dict[str, int | str]:
        return {
            "type": "argon2id",
            "time_cost": self._hasher.time_cost,
            "memory_kib": self._hasher.memory_cost,
            "parallelism": self._hasher.parallelism,
        }
