#!/usr/bin/env python3
"""Run the full crypto-core suite with each large parameter set in its own process.

SEAL's memory pool never returns memory to the operating system, so one pytest process that
generates key rings for every N=16384 parameter set grows until an allocation fails. The suite is
therefore split: unit tests and the N=8192 sets in one process, then one process per N=16384 (and,
with ``--heavy``, N=32768) parameter set. Coverage is appended across processes and the 100%
gate is applied to the combined result.

    python scripts/run_suite.py            # N=8192 + N=16384
    python scripts/run_suite.py --heavy    # adds N=32768 (needs several GB per process)
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
PROFILES = [f"N16384-{level}-{profile}" for level in (128, 192, 256) for profile in ("balanced", "deep")]
HEAVY = [f"N32768-{level}-{profile}" for level in (128, 192, 256) for profile in ("balanced", "deep")]


def run(argv: list[str]) -> int:
    print("$", " ".join(argv), flush=True)
    return subprocess.run(argv, cwd=HERE, check=False).returncode


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--heavy", action="store_true")
    parser.add_argument("pytest_args", nargs="*", help="extra arguments passed to every pytest run")
    ns = parser.parse_args()
    python = sys.executable
    run([python, "-m", "coverage", "erase"])
    groups = ["not N16384 and not N32768", *PROFILES]
    if ns.heavy:
        groups += HEAVY
    failures = []
    for expr in groups:
        argv = [
            python,
            "-m",
            "pytest",
            "-q",
            "-p",
            "no:cacheprovider",
            "-k",
            expr,
            "--cov=ciphercompute_core",
            "--cov-append",
            "--cov-report=",
            "--cov-fail-under=0",
            *ns.pytest_args,
        ]
        if ns.heavy and expr in HEAVY:
            argv += ["-m", "heavy"]
        code = run(argv)
        if code not in (0, 5):  # 5 = no tests collected (e.g. a heavy group without CC_TEST_HEAVY)
            failures.append(expr)
    coverage = run([python, "-m", "coverage", "report", "--fail-under=100", "--show-missing"])
    if failures:
        print(f"failing groups: {failures}", file=sys.stderr)
        return 1
    return coverage


if __name__ == "__main__":
    sys.exit(main())
