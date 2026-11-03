"""Registry of homomorphic operations.

Every operation declares the multiplicative depth it consumes so that :mod:`budget` can
refuse a job before execution, and ships a plaintext ``reference`` implementation used by the
property-based tests to prove ``decrypt(op(enc(x))) ≈ op(x)``.

All operations take :class:`EncryptedVector` inputs and *plaintext* arguments. The server can
read the plaintext arguments (scalars, weights, matrices) — see THREAT_MODEL.md, residual
risk 4 — but never the inputs or outputs.
"""

from __future__ import annotations

import math
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final

import numpy as np

from .ciphertext import EncryptedVector
from .errors import InvalidArgumentError, KeyMismatchError, UnsupportedOperationError
from .keys import PublicKeyBundle
from .sigmoid import SUPPORTED_DEGREES, polyval_depth, sigmoid_coefficients, sigmoid_poly

Args = dict[str, Any]
Normalize = Callable[[Sequence[int], Mapping[str, Any]], Args]
DepthCost = Callable[[Args], int]
OutputLength = Callable[[Sequence[int], Args], int]
Apply = Callable[[PublicKeyBundle, Sequence[EncryptedVector], Args], EncryptedVector]
Reference = Callable[[Sequence[np.ndarray], Args], np.ndarray]


@dataclass(frozen=True, slots=True)
class OperationSpec:
    name: str
    summary: str
    min_inputs: int
    max_inputs: int | None
    normalize: Normalize
    depth_cost: DepthCost
    output_length: OutputLength
    apply: Apply
    reference: Reference
    reveals: tuple[str, ...]
    """Plaintext argument names the server can see."""

    def describe(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "summary": self.summary,
            "min_inputs": self.min_inputs,
            "max_inputs": self.max_inputs,
            "reveals": list(self.reveals),
        }


OPERATIONS: dict[str, OperationSpec] = {}


def _register(spec: OperationSpec) -> OperationSpec:
    OPERATIONS[spec.name] = spec
    return spec


def get_operation(name: str) -> OperationSpec:
    try:
        return OPERATIONS[name]
    except KeyError:
        raise UnsupportedOperationError(
            f"unknown operation {name!r}; supported: {sorted(OPERATIONS)}", operation=name
        ) from None


def list_operations() -> list[OperationSpec]:
    return [OPERATIONS[k] for k in sorted(OPERATIONS)]


# ----- argument helpers ------------------------------------------------------------------------


def _same_length(lengths: Sequence[int], op: str) -> int:
    if len(set(lengths)) != 1:
        raise InvalidArgumentError(f"{op} requires inputs of equal length; got {list(lengths)}", lengths=list(lengths))
    return int(lengths[0])


def _float(value: Any, name: str) -> float:
    try:
        f = float(value)
    except (TypeError, ValueError):
        raise InvalidArgumentError(f"{name} must be a number", **{name: value}) from None
    if not math.isfinite(f):
        raise InvalidArgumentError(f"{name} must be finite", **{name: value})
    return f


def _float_list(value: Any, name: str, length: int | None = None) -> list[float]:
    try:
        arr = np.asarray(value, dtype=np.float64)
    except (TypeError, ValueError):
        raise InvalidArgumentError(f"{name} must be a list of numbers") from None
    if arr.ndim != 1 or arr.size == 0:
        raise InvalidArgumentError(f"{name} must be a non-empty 1-D list of numbers", shape=list(arr.shape))
    if not np.all(np.isfinite(arr)):
        raise InvalidArgumentError(f"{name} must contain only finite numbers")
    if length is not None and arr.size != length:
        raise InvalidArgumentError(
            f"{name} has {arr.size} entries but the input vector has {length}", expected=length, got=int(arr.size)
        )
    return [float(v) for v in arr]


def _matrix(value: Any, name: str, columns: int) -> list[list[float]]:
    try:
        arr = np.asarray(value, dtype=np.float64)
    except (TypeError, ValueError):
        raise InvalidArgumentError(f"{name} must be a 2-D list of numbers") from None
    if arr.ndim != 2 or arr.size == 0:
        raise InvalidArgumentError(f"{name} must be a non-empty 2-D matrix", shape=list(arr.shape))
    if not np.all(np.isfinite(arr)):
        raise InvalidArgumentError(f"{name} must contain only finite numbers")
    if arr.shape[1] != columns:
        raise InvalidArgumentError(
            f"{name} has {arr.shape[1]} columns but the input vector has {columns} entries",
            expected=columns,
            got=int(arr.shape[1]),
        )
    return [[float(v) for v in row] for row in arr]


def _count(value: Any, length: int) -> int:
    if value is None:
        return length
    if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= length:
        raise InvalidArgumentError(f"count must be an integer between 1 and the vector length {length}", count=value)
    return value


def _no_extra(args: Mapping[str, Any], allowed: set[str], op: str) -> None:
    extra = set(args) - allowed
    if extra:
        raise InvalidArgumentError(f"{op} does not accept arguments {sorted(extra)}", unexpected=sorted(extra))


def _require_nonzero(values: Sequence[float], name: str) -> None:
    # SEAL refuses to multiply by an all-zero plaintext ("transparent ciphertext"); refusing it
    # here turns a worker crash into a precise 4xx.
    if not any(v != 0.0 for v in values):
        raise InvalidArgumentError(f"{name} must contain at least one non-zero entry")


# ----- vector_add ----------------------------------------------------------------------------


def _add_normalize(lengths: Sequence[int], args: Mapping[str, Any]) -> Args:
    _no_extra(args, set(), "vector_add")
    _same_length(lengths, "vector_add")
    return {}


def _add_apply(bundle: PublicKeyBundle, inputs: Sequence[EncryptedVector], args: Args) -> EncryptedVector:
    acc = inputs[0].raw()
    for ev in inputs[1:]:
        acc = acc + ev.raw()
    return inputs[0].spawn(acc, inputs[0].length)


_register(
    OperationSpec(
        name="vector_add",
        summary="Element-wise sum of two or more encrypted vectors.",
        min_inputs=2,
        max_inputs=None,
        normalize=_add_normalize,
        depth_cost=lambda a: 0,
        output_length=lambda lengths, a: int(lengths[0]),
        apply=_add_apply,
        reference=lambda xs, a: np.sum(np.stack(xs), axis=0),
        reveals=(),
    )
)

# ----- scalar_multiply ------------------------------------------------------------------------


def _scalar_normalize(lengths: Sequence[int], args: Mapping[str, Any]) -> Args:
    _no_extra(args, {"scalar"}, "scalar_multiply")
    if "scalar" not in args:
        raise InvalidArgumentError("scalar_multiply requires a 'scalar' argument")
    scalar = _float(args["scalar"], "scalar")
    if scalar == 0.0:
        raise InvalidArgumentError("scalar must be non-zero (multiplying by zero is not a homomorphic operation)")
    return {"scalar": scalar}


_register(
    OperationSpec(
        name="scalar_multiply",
        summary="Multiply every element by a plaintext scalar.",
        min_inputs=1,
        max_inputs=1,
        normalize=_scalar_normalize,
        depth_cost=lambda a: 1,
        output_length=lambda lengths, a: int(lengths[0]),
        apply=lambda b, inputs, a: inputs[0].spawn(inputs[0].raw() * a["scalar"], inputs[0].length),
        reference=lambda xs, a: xs[0] * a["scalar"],
        reveals=("scalar",),
    )
)

# ----- elementwise_multiply -------------------------------------------------------------------


def _ewmul_normalize(lengths: Sequence[int], args: Mapping[str, Any]) -> Args:
    _no_extra(args, set(), "elementwise_multiply")
    _same_length(lengths, "elementwise_multiply")
    return {}


_register(
    OperationSpec(
        name="elementwise_multiply",
        summary="Hadamard product of two encrypted vectors.",
        min_inputs=2,
        max_inputs=2,
        normalize=_ewmul_normalize,
        depth_cost=lambda a: 1,
        output_length=lambda lengths, a: int(lengths[0]),
        apply=lambda b, inputs, a: inputs[0].spawn(inputs[0].raw() * inputs[1].raw(), inputs[0].length),
        reference=lambda xs, a: xs[0] * xs[1],
        reveals=(),
    )
)

# ----- dot_product -----------------------------------------------------------------------------


def _dot_normalize(lengths: Sequence[int], args: Mapping[str, Any]) -> Args:
    _no_extra(args, set(), "dot_product")
    _same_length(lengths, "dot_product")
    return {}


_register(
    OperationSpec(
        name="dot_product",
        summary="Inner product of two encrypted vectors.",
        min_inputs=2,
        max_inputs=2,
        normalize=_dot_normalize,
        depth_cost=lambda a: 1,
        output_length=lambda lengths, a: 1,
        apply=lambda b, inputs, a: inputs[0].spawn(inputs[0].raw().dot(inputs[1].raw()), 1),
        reference=lambda xs, a: np.array([float(np.dot(xs[0], xs[1]))]),
        reveals=(),
    )
)

# ----- sum / mean / variance ------------------------------------------------------------------


def _sum_normalize(lengths: Sequence[int], args: Mapping[str, Any]) -> Args:
    _no_extra(args, set(), "sum")
    return {}


_register(
    OperationSpec(
        name="sum",
        summary="Sum of all elements.",
        min_inputs=1,
        max_inputs=1,
        normalize=_sum_normalize,
        depth_cost=lambda a: 0,
        output_length=lambda lengths, a: 1,
        apply=lambda b, inputs, a: inputs[0].spawn(inputs[0].raw().sum(), 1),
        reference=lambda xs, a: np.array([float(np.sum(xs[0]))]),
        reveals=(),
    )
)


def _mean_normalize(lengths: Sequence[int], args: Mapping[str, Any]) -> Args:
    _no_extra(args, {"count"}, "mean")
    return {"count": _count(args.get("count"), int(lengths[0]))}


_register(
    OperationSpec(
        name="mean",
        summary="Arithmetic mean. 'count' overrides the divisor for padded vectors.",
        min_inputs=1,
        max_inputs=1,
        normalize=_mean_normalize,
        depth_cost=lambda a: 1,
        output_length=lambda lengths, a: 1,
        apply=lambda b, inputs, a: inputs[0].spawn(inputs[0].raw().sum() * (1.0 / a["count"]), 1),
        reference=lambda xs, a: np.array([float(np.sum(xs[0]) / a["count"])]),
        reveals=("count",),
    )
)


def _var_normalize(lengths: Sequence[int], args: Mapping[str, Any]) -> Args:
    _no_extra(args, {"count", "ddof"}, "variance")
    count = _count(args.get("count"), int(lengths[0]))
    ddof = args.get("ddof", 0)
    if ddof not in (0, 1) or isinstance(ddof, bool):
        raise InvalidArgumentError("ddof must be 0 (population) or 1 (sample)", ddof=ddof)
    if count - ddof < 1:
        raise InvalidArgumentError("sample variance needs at least two values", count=count, ddof=ddof)
    return {"count": count, "ddof": int(ddof)}


def _var_apply(bundle: PublicKeyBundle, inputs: Sequence[EncryptedVector], args: Args) -> EncryptedVector:
    # var = E[x^2] - E[x]^2, each branch exactly two levels deep so they line up for the subtraction.
    x = inputs[0].raw()
    n, ddof = args["count"], args["ddof"]
    denom = n - ddof
    mean_sq = (x * x).sum() * (1.0 / denom)
    # fold n/(n-ddof) into the mean before squaring so no third level is needed
    scaled_mean = x.sum() * (math.sqrt(n / denom) / n)
    return inputs[0].spawn(mean_sq - scaled_mean * scaled_mean, 1)


def _var_reference(xs: Sequence[np.ndarray], args: Args) -> np.ndarray:
    x = xs[0]
    n, ddof = args["count"], args["ddof"]
    denom = n - ddof
    return np.array([float(np.sum(x * x) / denom - (n / denom) * (np.sum(x) / n) ** 2)])


_register(
    OperationSpec(
        name="variance",
        summary="Population (ddof=0) or sample (ddof=1) variance.",
        min_inputs=1,
        max_inputs=1,
        normalize=_var_normalize,
        depth_cost=lambda a: 2,
        output_length=lambda lengths, a: 1,
        apply=_var_apply,
        reference=_var_reference,
        reveals=("count", "ddof"),
    )
)

# ----- weighted_average -----------------------------------------------------------------------


def _wavg_normalize(lengths: Sequence[int], args: Mapping[str, Any]) -> Args:
    _no_extra(args, {"weights"}, "weighted_average")
    if "weights" not in args:
        raise InvalidArgumentError("weighted_average requires a 'weights' argument")
    weights = _float_list(args["weights"], "weights", int(lengths[0]))
    total = float(sum(weights))
    if total == 0.0:
        raise InvalidArgumentError("weights must not sum to zero")
    return {"weights": weights}


def _wavg_apply(bundle: PublicKeyBundle, inputs: Sequence[EncryptedVector], args: Args) -> EncryptedVector:
    w = np.asarray(args["weights"])
    normalized = (w / w.sum()).tolist()
    return inputs[0].spawn(inputs[0].raw().dot(normalized), 1)


_register(
    OperationSpec(
        name="weighted_average",
        summary="Weighted mean with plaintext weights (normalised client-side of the ciphertext).",
        min_inputs=1,
        max_inputs=1,
        normalize=_wavg_normalize,
        depth_cost=lambda a: 1,
        output_length=lambda lengths, a: 1,
        apply=_wavg_apply,
        reference=lambda xs, a: np.array([float(np.dot(xs[0], a["weights"]) / np.sum(a["weights"]))]),
        reveals=("weights",),
    )
)

# ----- linear / logistic regression -----------------------------------------------------------

_LAYOUTS: Final = ("sample", "columns")


def _regression_normalize(op: str, lengths: Sequence[int], args: Mapping[str, Any], extra: set[str]) -> Args:
    _no_extra(args, {"weights", "intercept", "layout"} | extra, op)
    if "weights" not in args:
        raise InvalidArgumentError(f"{op} requires a 'weights' argument")
    layout = args.get("layout", "sample")
    if layout not in _LAYOUTS:
        raise InvalidArgumentError(f"layout must be one of {list(_LAYOUTS)}", layout=layout)
    if layout == "sample":
        if len(lengths) != 1:
            raise InvalidArgumentError(
                f"{op} with layout='sample' takes exactly one input (the feature vector)", inputs=len(lengths)
            )
        weights = _float_list(args["weights"], "weights", int(lengths[0]))
    else:
        _same_length(lengths, f"{op} (layout='columns')")
        weights = _float_list(args["weights"], "weights", len(lengths))
    _require_nonzero(weights, "weights")
    return {"weights": weights, "intercept": _float(args.get("intercept", 0.0), "intercept"), "layout": layout}


def _linear_raw(inputs: Sequence[EncryptedVector], args: Args) -> Any:
    weights, intercept, layout = args["weights"], args["intercept"], args["layout"]
    if layout == "sample":
        z = inputs[0].raw().dot(weights)
    else:
        z = None
        for ev, w in zip(inputs, weights, strict=True):
            if w == 0.0:
                continue
            term = ev.raw() * w
            z = term if z is None else z + term
    return z if intercept == 0.0 else z + intercept


def _linear_reference(xs: Sequence[np.ndarray], args: Args) -> np.ndarray:
    weights, intercept, layout = np.asarray(args["weights"]), args["intercept"], args["layout"]
    if layout == "sample":
        return np.array([float(np.dot(xs[0], weights) + intercept)])
    return np.asarray(np.sum(np.stack(xs) * weights[:, None], axis=0) + intercept, dtype=np.float64)


def _regression_output_length(lengths: Sequence[int], args: Args) -> int:
    return 1 if args["layout"] == "sample" else int(lengths[0])


_register(
    OperationSpec(
        name="linear_regression",
        summary="Apply pre-trained plaintext weights and intercept to encrypted features. "
        "layout='sample': one input vector of features; layout='columns': one input per feature, "
        "each holding that feature for many samples (batched inference).",
        min_inputs=1,
        max_inputs=None,
        normalize=lambda lengths, args: _regression_normalize("linear_regression", lengths, args, set()),
        depth_cost=lambda a: 1,
        output_length=_regression_output_length,
        apply=lambda b, inputs, a: inputs[0].spawn(
            _linear_raw(inputs, a), _regression_output_length([ev.length for ev in inputs], a)
        ),
        reference=_linear_reference,
        reveals=("weights", "intercept", "layout"),
    )
)


def _logistic_normalize(lengths: Sequence[int], args: Mapping[str, Any]) -> Args:
    out = _regression_normalize("logistic_regression", lengths, args, {"degree"})
    degree = args.get("degree", 3)
    if isinstance(degree, bool) or degree not in SUPPORTED_DEGREES:
        raise InvalidArgumentError(f"degree must be one of {list(SUPPORTED_DEGREES)}", degree=degree)
    out["degree"] = int(degree)
    return out


def _logistic_apply(bundle: PublicKeyBundle, inputs: Sequence[EncryptedVector], args: Args) -> EncryptedVector:
    z = _linear_raw(inputs, args)
    probs = z.polyval(list(sigmoid_coefficients(args["degree"])))
    return inputs[0].spawn(probs, _regression_output_length([ev.length for ev in inputs], args))


_register(
    OperationSpec(
        name="logistic_regression",
        summary="Linear regression followed by a degree-3 or degree-5 polynomial sigmoid "
        "(valid for logits in [-8, 8]).",
        min_inputs=1,
        max_inputs=None,
        normalize=_logistic_normalize,
        depth_cost=lambda a: 1 + polyval_depth(a["degree"]),
        output_length=_regression_output_length,
        apply=_logistic_apply,
        reference=lambda xs, a: sigmoid_poly(_linear_reference(xs, a), a["degree"]),
        reveals=("weights", "intercept", "layout", "degree"),
    )
)

# ----- matvec_multiply ------------------------------------------------------------------------


def _matvec_normalize(lengths: Sequence[int], args: Mapping[str, Any]) -> Args:
    _no_extra(args, {"matrix"}, "matvec_multiply")
    if "matrix" not in args:
        raise InvalidArgumentError("matvec_multiply requires a 'matrix' argument (rows x len(vector))")
    matrix = _matrix(args["matrix"], "matrix", int(lengths[0]))
    _require_nonzero([v for row in matrix for v in row], "matrix")
    return {"matrix": matrix}


def _matvec_apply(bundle: PublicKeyBundle, inputs: Sequence[EncryptedVector], args: Args) -> EncryptedVector:
    matrix = np.asarray(args["matrix"])
    rows = int(matrix.shape[0])
    if rows > inputs[0].params.slots:
        raise InvalidArgumentError(
            f"matrix has {rows} rows but the parameter set offers {inputs[0].params.slots} slots"
        )
    # TenSEAL computes (row vector) x (matrix); A x == x^T A^T.
    out = inputs[0].raw().matmul(matrix.T.tolist())
    return inputs[0].spawn(out, rows)


_register(
    OperationSpec(
        name="matvec_multiply",
        summary="Multiply a plaintext matrix (rows x n) by an encrypted vector of length n.",
        min_inputs=1,
        max_inputs=1,
        normalize=_matvec_normalize,
        depth_cost=lambda a: 1,
        output_length=lambda lengths, a: len(a["matrix"]),
        apply=_matvec_apply,
        reference=lambda xs, a: np.asarray(a["matrix"]) @ xs[0],
        reveals=("matrix",),
    )
)


# ----- entry point ------------------------------------------------------------------------------


def apply_operation(
    name: str,
    bundle: PublicKeyBundle,
    inputs: Sequence[EncryptedVector],
    args: Mapping[str, Any] | None = None,
) -> EncryptedVector:
    """Validate and run ``name`` on ``inputs`` under ``bundle``.

    Raises ``InvalidArgumentError``, ``KeyMismatchError`` or ``UnsupportedOperationError``
    before touching any ciphertext; depth is *not* checked here — call :func:`budget.plan`
    first (the API does) if you need the refusal rather than a SEAL failure.
    """
    spec = get_operation(name)
    if len(inputs) < spec.min_inputs or (spec.max_inputs is not None and len(inputs) > spec.max_inputs):
        bound = (
            f"exactly {spec.min_inputs}"
            if spec.min_inputs == spec.max_inputs
            else f"between {spec.min_inputs} and {spec.max_inputs or 'any number of'}"
        )
        raise InvalidArgumentError(f"{name} takes {bound} input(s); got {len(inputs)}", inputs=len(inputs))
    for ev in inputs:
        if ev.ring_id != bundle.ring_id:
            raise KeyMismatchError(
                "input ciphertext belongs to a different key ring than the bundle",
                expected_ring_id=bundle.ring_id,
                got_ring_id=ev.ring_id,
            )
    normalized = spec.normalize([ev.length for ev in inputs], dict(args or {}))
    # TenSEAL mod-switches the *higher-level* operand in place when two operands sit at
    # different levels. Copy those inputs so a caller's ciphertexts are never degraded as a
    # side effect of an operation.
    deepest = max(ev.levels_consumed for ev in inputs)
    protected = [ev.copy() if ev.levels_consumed < deepest else ev for ev in inputs]
    return spec.apply(bundle, protected, normalized)
