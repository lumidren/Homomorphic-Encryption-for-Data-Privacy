# Contributing

## Prerequisites

* **Python 3.12, 64-bit.** TenSEAL ships no 32-bit wheels. If your system interpreter is
  32-bit (common on Windows installs), use [uv](https://docs.astral.sh/uv/) to fetch a managed one:

  ```bash
  pip install uv
  uv python install cpython-3.12-windows-x86_64-none   # or just 3.12 on Linux/macOS
  uv venv .venv --python 3.12
  ```

* Node 20+ for the dashboard, Docker for the local stack, `kubectl`/`helm`/`terraform` for infra work.

## Setting up

```bash
uv pip install --python .venv -e packages/core[test] -e packages/client[test] -e services/api[test] -e services/worker[test]
uv pip install --python .venv ruff mypy bandit pip-audit
```

## Running the tests

```bash
cd packages/core && pytest                       # all 8192 and 16384 presets (~5 min)
CC_TEST_HEAVY=1 pytest -m heavy                  # N=32768 presets: several GB of RAM
CC_PROPERTY_EXAMPLES=50 pytest tests/test_properties.py   # more Hypothesis examples
pytest --cov --cov-report=term-missing           # crypto modules must stay at 100%
```

The property tests take their tolerances from `data/precision_table.json`. If you change a
parameter preset or an operation's implementation, re-run the calibration and commit the table:

```bash
python packages/core/scripts/calibrate_precision.py            # 8192 + 16384
python packages/core/scripts/calibrate_precision.py --heavy    # adds 32768
```

## Lint and types

```bash
ruff format . && ruff check .
mypy packages/core/src packages/client/src services/api/src services/worker/src
```

CI runs `ruff`, `mypy --strict`, `bandit`, `semgrep` (OWASP rules), `pip-audit`, `npm audit`,
`tsc`, `eslint` and Trivy. A HIGH/CRITICAL finding fails the build.

## Threat-model markers

Every row in `THREAT_MODEL.md` points at the code that enforces it. Put a marker comment at the
enforcement site:

```python
# [TM:S-2] Keys are compared with hmac.compare_digest.
```

then run `python scripts/resolve_threat_refs.py` to rewrite the `file:line` references.
`--check` is run in CI and fails on stale references, missing markers or markers with no row.

## Rules that are not negotiable

1. Nothing under `services/` may import `KeyRing`, call `decrypt(`, touch a secret key or
   construct a TenSEAL context directly. `packages/core/tests/test_secret_key_boundary.py`
   enforces this.
2. Secrets are compared with `hmac.compare_digest` and never logged.
3. No mock encryption, no placeholders, no TODOs in `main`. If something is not implemented,
   say so in the pull request and in `CHANGELOG.md`.

## Commits and pull requests

* Small, focused commits with conventional prefixes: `feat(core):`, `fix(api):`, `docs:`, `test:`,
  `ci:`, `infra:`.
* Every pull request updates `CHANGELOG.md` under *Unreleased*.
* Security-relevant changes reference the threat-model row they affect (`TM:I-1`).
