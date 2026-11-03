"""Shared fixtures.

``ring`` is a *session-scoped, parametrised* fixture: pytest groups every test that uses it by
parameter set, so each key ring is generated once and torn down before the next one (a 16384
bundle is several hundred MB). N=32768 sets are marked ``heavy`` and only run with
``CC_TEST_HEAVY=1``.
"""

from __future__ import annotations

import os

import pytest

from ciphercompute_core import KeyRing, all_presets
from ciphercompute_core.params import CKKSParams

HEAVY_ENABLED = os.environ.get("CC_TEST_HEAVY") == "1"


def _preset_params() -> list[object]:
    out = []
    for profile, params in all_presets():
        marks = [pytest.mark.heavy] if params.poly_modulus_degree == 32768 else []
        ident = f"N{params.poly_modulus_degree}-{int(params.security_level)}-{profile}"
        out.append(pytest.param(params, id=ident, marks=marks))
    return out


@pytest.fixture(scope="session", params=_preset_params())
def params(request: pytest.FixtureRequest) -> CKKSParams:
    p: CKKSParams = request.param
    if p.poly_modulus_degree == 32768 and not HEAVY_ENABLED:
        pytest.skip("N=32768 presets need CC_TEST_HEAVY=1 (several GB of RAM)")
    return p


@pytest.fixture(scope="session")
def ring(params: CKKSParams) -> KeyRing:
    return KeyRing.generate(params)


@pytest.fixture(scope="session")
def bundle(ring: KeyRing):
    return ring.public_bundle()


@pytest.fixture(scope="session")
def small_ring() -> KeyRing:
    """A single cheap ring for tests that do not need every parameter set."""
    from ciphercompute_core import standard_params

    return KeyRing.generate(standard_params(8192, 128))


@pytest.fixture(scope="session")
def small_bundle(small_ring: KeyRing):
    return small_ring.public_bundle()
