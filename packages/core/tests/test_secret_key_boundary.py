"""The server must have no code path that accepts, stores or uses a secret key.

Two layers: (1) the only loader for key material refuses private contexts; (2) the server and
worker source trees are scanned for any symbol that could touch secret material.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from ciphercompute_core import EncryptedVector, KeyRing, PublicKeyBundle
from ciphercompute_core.envelope import MAGIC_BUNDLE, pack
from ciphercompute_core.errors import SecretKeyLeakError
from ciphercompute_core.keys import BUNDLE_KIND

REPO_ROOT = Path(__file__).resolve().parents[3]
SERVICES = REPO_ROOT / "services"

FORBIDDEN_TOKENS = (
    "decrypt(",
    ".secret_key",
    "secret_key()",
    "save_secret_key=True",
    "KeyRing",
    "from_secret_bytes",
    "to_secret_bytes",
    "MAGIC_SECRET",
    "import tenseal",
    "from tenseal",
    "ts.context(",
)


def test_private_context_cannot_become_a_bundle(small_ring: KeyRing) -> None:
    raw = small_ring.context().serialize(
        save_public_key=True, save_secret_key=True, save_galois_keys=True, save_relin_keys=True
    )
    header = {"kind": BUNDLE_KIND, "ring_id": small_ring.ring_id, "params": small_ring.params.to_dict()}
    with pytest.raises(SecretKeyLeakError):
        PublicKeyBundle.load(pack(MAGIC_BUNDLE, header, raw))


def test_public_types_expose_no_decryption_surface() -> None:
    for cls in (PublicKeyBundle, EncryptedVector):
        names = {n for n in dir(cls) if not n.startswith("__")}
        assert "decrypt" not in names, cls
        assert not any("secret" in n for n in names), cls


def test_services_tree_has_no_secret_key_paths() -> None:
    if not SERVICES.exists():
        pytest.skip("services/ is not part of this checkout")
    offenders: list[str] = []
    for path in SERVICES.glob("*/src/**/*.py"):
        text = path.read_text(encoding="utf-8")
        for token in FORBIDDEN_TOKENS:
            if token in text:
                line = next(i for i, text_line in enumerate(text.splitlines(), 1) if token in text_line)
                offenders.append(f"{path.relative_to(REPO_ROOT)}:{line}: {token}")
    assert not offenders, "secret-key material must never reach the server:\n" + "\n".join(offenders)
