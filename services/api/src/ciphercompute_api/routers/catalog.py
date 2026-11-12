"""Operation catalog, standard parameter sets and the parameter advisor. No tenant data."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends

from ciphercompute_core import advise, all_presets, list_operations
from ciphercompute_core.precision import PRECISION_CLASSES, precision_bits
from ciphercompute_core.sigmoid import SIGMOID_DOMAIN, SIGMOID_MAX_ABS_ERROR

from ..deps import Principal, get_principal
from ..schemas import AdvisorRequest

router = APIRouter(prefix="/v1", tags=["catalog"])


@router.get("/operations")
async def operations(_: Principal = Depends(get_principal)) -> list[dict[str, Any]]:
    out = []
    for spec in list_operations():
        item = spec.describe()
        if spec.name == "logistic_regression":
            item["sigmoid"] = {
                "domain": list(SIGMOID_DOMAIN),
                "max_abs_error": {str(k): v for k, v in SIGMOID_MAX_ABS_ERROR.items()},
            }
        out.append(item)
    return out


@router.get("/parameter-sets")
async def parameter_sets(_: Principal = Depends(get_principal)) -> list[dict[str, Any]]:
    out = []
    for profile, params in all_presets():
        out.append(
            {
                "profile": profile,
                **params.to_dict(),
                "depth": params.depth,
                "slots": params.slots,
                "integer_headroom_bits": params.integer_headroom_bits,
                "precision_bits_by_level": {
                    cls: {str(lvl): precision_bits(params, lvl, cls)[0] for lvl in range(params.depth + 1)}
                    for cls in PRECISION_CLASSES
                },
                "precision_measured": precision_bits(params, 0)[1],
            }
        )
    return out


@router.post("/advisor")
async def advisor(body: AdvisorRequest, _: Principal = Depends(get_principal)) -> dict[str, Any]:
    """Recommend the smallest standard parameter set that carries the given operation chain."""
    result = advise(
        [(s.operation, s.args) for s in body.steps],
        input_lengths=body.input_lengths,
        security_level=body.security_level,
        min_poly_modulus_degree=body.min_poly_modulus_degree,
        prefer=body.prefer,
        min_precision_bits=body.min_precision_bits,
    )
    return result.to_dict()
