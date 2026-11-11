"""Parameter validation: every insecure combination must be refused at construction time."""

from __future__ import annotations

import pytest

from ciphercompute_core.errors import InsecureParametersError
from ciphercompute_core.params import (
    DEEP_PARAMS,
    MAX_COEFF_MODULUS_BITS,
    STANDARD_PARAMS,
    CKKSParams,
    PolyModulusDegree,
    SecurityLevel,
    all_presets,
    max_coeff_modulus_bits,
    standard_params,
)


@pytest.mark.parametrize(("profile", "params"), all_presets())
def test_every_preset_is_within_standard_bounds(profile: str, params: CKKSParams) -> None:
    assert params.total_coeff_modulus_bits <= params.max_coeff_modulus_bits
    assert params.depth >= 2
    assert params.achieved_security_level() >= params.security_level
    assert all(20 <= b <= 60 for b in params.coeff_mod_bit_sizes)
    assert params.scale_bits <= min(params.coeff_mod_bit_sizes[1:-1])
    assert params.slots == params.poly_modulus_degree // 2
    assert params.integer_headroom_bits >= 11
    # the special (last) prime must be at least as large as every working prime
    assert params.coeff_mod_bit_sizes[-1] >= max(params.coeff_mod_bit_sizes[1:-1])
    assert params.describe()


def test_deep_profile_has_more_levels_than_balanced() -> None:
    assert len(DEEP_PARAMS) == len(STANDARD_PARAMS) - 1
    for key, deep in DEEP_PARAMS.items():
        assert deep.depth > STANDARD_PARAMS[key].depth


def test_no_deep_profile_at_8192_256() -> None:
    assert (PolyModulusDegree.N_8192, SecurityLevel.BITS_256) not in DEEP_PARAMS
    with pytest.raises(InsecureParametersError, match="no 'deep' profile exists") as excinfo:
        standard_params(8192, 256, "deep")
    assert excinfo.value.details["profile"] == "deep"
    assert sum(1 for profile, _ in all_presets() if profile == "deep") == 8


def test_special_prime_must_dominate() -> None:
    with pytest.raises(InsecureParametersError, match="special \\(last\\) prime"):
        CKKSParams(8192, (60, 40, 40, 50), 40)
    with pytest.raises(InsecureParametersError, match="special \\(last\\) prime"):
        CKKSParams(8192, (32, 21, 21, 21, 23), 21, SecurityLevel.BITS_256)
    # equal is fine
    assert CKKSParams(8192, (40, 40, 40, 40), 40).depth == 2


@pytest.mark.parametrize(
    ("degree", "level", "bits"),
    [
        (8192, 128, (60, 60, 60, 60)),  # 240 > 218
        (8192, 192, (60, 40, 40, 60)),  # 200 > 152: the 128-bit set is NOT 192-bit secure
        (8192, 256, (45, 30, 30, 45)),  # 150 > 118
        (16384, 256, (60, 40, 40, 40, 40, 40, 40, 60)),  # 360 > 237
        (32768, 256, (60,) + (40,) * 10 + (60,)),  # 520 > 476
    ],
)
def test_insecure_combos_rejected(degree: int, level: int, bits: tuple[int, ...]) -> None:
    with pytest.raises(InsecureParametersError) as excinfo:
        CKKSParams(degree, bits, 30, SecurityLevel(level))
    err = excinfo.value
    assert err.code == "insecure_parameters"
    assert err.details["max_bits"] == MAX_COEFF_MODULUS_BITS[(degree, level)]
    assert err.details["total_bits"] == sum(bits)
    assert "HE Security Standard" in str(err)


def test_error_message_names_next_degree() -> None:
    with pytest.raises(InsecureParametersError, match="16384"):
        CKKSParams(8192, (60, 60, 60, 60), 40)
    with pytest.raises(InsecureParametersError, match="drop a prime"):
        CKKSParams(32768, (60,) * 16, 40)


@pytest.mark.parametrize(
    ("degree", "bits", "scale", "fragment"),
    [
        (4096, (40, 30, 40), 30, "not supported"),
        (8192, (60, 60), 40, "at least 3 primes"),
        (8192, (60, 61, 60), 40, "between 20 and 60"),
        (8192, (60, 19, 60), 19, "between 20 and 60"),
        (8192, (60, 40, 40, 60), 0, "scale_bits must be"),
        (8192, (60, 40, 40, 60), 41, "exceeds a working prime"),
        (8192, (30, 40, 40, 60), 40, "first prime"),
    ],
)
def test_structural_rejections(degree: int, bits: tuple[int, ...], scale: int, fragment: str) -> None:
    with pytest.raises(InsecureParametersError, match=fragment):
        CKKSParams(degree, bits, scale)


def test_unsupported_degree_in_bound_lookup() -> None:
    with pytest.raises(InsecureParametersError, match="not a supported ring dimension"):
        max_coeff_modulus_bits(1234, SecurityLevel.BITS_128)


def test_round_trip_dict() -> None:
    p = standard_params(16384, 192, "deep")
    assert CKKSParams.from_dict(p.to_dict()) == p
    assert hash(CKKSParams.from_dict(p.to_dict())) == hash(p)


def test_from_dict_malformed() -> None:
    with pytest.raises(InsecureParametersError, match="malformed"):
        CKKSParams.from_dict({"poly_modulus_degree": 8192})
    with pytest.raises(InsecureParametersError, match="malformed"):
        CKKSParams.from_dict({"poly_modulus_degree": "x", "coeff_mod_bit_sizes": [1], "scale_bits": 1})
    # an insecure-but-well-formed dict must surface the security error, not "malformed"
    with pytest.raises(InsecureParametersError, match="HE Security Standard"):
        CKKSParams.from_dict({"poly_modulus_degree": 8192, "coeff_mod_bit_sizes": [60, 60, 60, 60], "scale_bits": 40})


def test_with_security_level_revalidates() -> None:
    p = standard_params(8192, 128)
    with pytest.raises(InsecureParametersError):
        p.with_security_level(SecurityLevel.BITS_256)
    assert standard_params(8192, 256).with_security_level(SecurityLevel.BITS_128).security_level == 128


def test_achieved_level_is_the_strongest_satisfied() -> None:
    assert standard_params(8192, 256).achieved_security_level() == SecurityLevel.BITS_256
    assert standard_params(8192, 128).achieved_security_level() == SecurityLevel.BITS_128
    # 440 bits at N=32768 sits under the 256-bit bound (476), so the set is stronger than labelled
    assert standard_params(32768, 128).achieved_security_level() == SecurityLevel.BITS_256
    assert standard_params(16384, 192).achieved_security_level() == SecurityLevel.BITS_192


def test_standard_params_accepts_ints_and_enums() -> None:
    assert standard_params(8192, 128) is standard_params(PolyModulusDegree.N_8192, SecurityLevel.BITS_128)
    assert standard_params(8192, 128, "deep") is DEEP_PARAMS[(PolyModulusDegree.N_8192, SecurityLevel.BITS_128)]


def test_error_envelope() -> None:
    with pytest.raises(InsecureParametersError) as excinfo:
        CKKSParams(8192, (60, 60, 60, 60), 40)
    d = excinfo.value.to_dict()
    assert d["code"] == "insecure_parameters"
    assert d["details"]["total_bits"] == 240
    assert d["message"] == excinfo.value.message


def test_frozen() -> None:
    p = standard_params(8192, 128)
    with pytest.raises(AttributeError):
        p.scale_bits = 10  # type: ignore[misc]
    assert p.max_abs_value == 2.0**20
