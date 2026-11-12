from __future__ import annotations

from ciphercompute_core.manifest import manifest_hash, object_fingerprint


def test_manifest_is_canonical_and_binding() -> None:
    base = manifest_hash("mean", {"count": 3}, ["sha256:a"], "sha256:b")
    assert len(base) == 64
    # key order does not matter; every committed field does
    assert manifest_hash(
        "mean", dict(reversed(list({"count": 3, "x": 1}.items()))), ["sha256:a"], "sha256:b"
    ) == manifest_hash("mean", {"count": 3, "x": 1}, ["sha256:a"], "sha256:b")
    for changed in (
        manifest_hash("sum", {"count": 3}, ["sha256:a"], "sha256:b"),
        manifest_hash("mean", {"count": 4}, ["sha256:a"], "sha256:b"),
        manifest_hash("mean", {"count": 3}, ["sha256:c"], "sha256:b"),
        manifest_hash("mean", {"count": 3}, ["sha256:a"], None),
    ):
        assert changed != base


def test_object_fingerprint() -> None:
    assert object_fingerprint(b"") == "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
