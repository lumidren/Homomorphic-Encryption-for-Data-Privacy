#!/usr/bin/env python3
"""Keep THREAT_MODEL.md's ``file:line`` mitigation references exact.

Mitigation sites in the code carry a marker comment such as ``# [TM:S-1]``. Each row of the
threat register names its marker as ``(TM:S-1)`` right after the backticked reference(s).
This script locates every marker and rewrites the references to the real ``path:line``.

    python scripts/resolve_threat_refs.py          # update THREAT_MODEL.md in place
    python scripts/resolve_threat_refs.py --check  # CI: fail if stale or a marker is missing
"""

from __future__ import annotations

import argparse
import re
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT / "THREAT_MODEL.md"
SCAN_DIRS = ("packages", "services", "infra", "dashboard", "scripts", "showcase")
SKIP_PARTS = {
    "node_modules",
    ".next",
    ".venv",
    "__pycache__",
    ".git",
    ".terraform",
    ".mypy_cache",
    ".ruff_cache",
    ".pytest_cache",
    ".hypothesis",
    "tests",
    "dist",
    "build",
}
EXTENSIONS = {".py", ".ts", ".tsx", ".yaml", ".yml", ".tf", ".conf", ".toml", ".sh", ".Dockerfile", ".json", ".sql"}

MARKER_RE = re.compile(r"\[TM:([A-Z]-\d+)\]")
# `path[:line]`[, `path[:line]`...] followed by either the raw marker form or the resolved form.
REF_RE = re.compile(
    r"(?P<refs>`[^`\n]+`(?:,\s*`[^`\n]+`)*)\s*(?:`# \[TM:(?P<id1>[A-Z]-\d+)\]`|\(TM:(?P<id2>[A-Z]-\d+)\))"
)


def find_markers() -> dict[str, list[tuple[str, int]]]:
    found: dict[str, list[tuple[str, int]]] = defaultdict(list)
    for base in SCAN_DIRS:
        root = ROOT / base
        if not root.exists():
            continue
        for path in root.rglob("*"):
            if not path.is_file() or (path.suffix not in EXTENSIONS and path.name != "Dockerfile"):
                continue
            if path.resolve() == Path(__file__).resolve():
                continue  # this file documents the marker syntax; it enforces nothing
            if SKIP_PARTS & set(path.relative_to(ROOT).parts):
                continue
            try:
                lines = path.read_text(encoding="utf-8").splitlines()
            except UnicodeDecodeError:
                continue
            for number, line in enumerate(lines, 1):
                for match in MARKER_RE.finditer(line):
                    found[match.group(1)].append((path.relative_to(ROOT).as_posix(), number))
    return found


def resolve(text: str, markers: dict[str, list[tuple[str, int]]]) -> tuple[str, list[str], int]:
    missing: list[str] = []
    changed = 0

    def replace(match: re.Match[str]) -> str:
        nonlocal changed
        marker_id = match.group("id1") or match.group("id2")
        sites = markers.get(marker_id)
        if not sites:
            missing.append(marker_id)
            return match.group(0)
        refs = ", ".join(f"`{path}:{line}`" for path, line in sites)
        new = f"{refs} (TM:{marker_id})"
        if new != match.group(0):
            changed += 1
        return new

    return REF_RE.sub(replace, text), missing, changed


ROW_RE = re.compile(r"^\| [A-Z]-\d+ \|")
TEST_REF_RE = re.compile(r"`([^`\s]*test_[^`\s]*)`")


def _test_files(name: str) -> list[Path]:
    skip = SKIP_PARTS - {"tests"}
    return [p for p in ROOT.rglob(name) if not skip & set(p.relative_to(ROOT).parts)]


def missing_tests(text: str) -> list[str]:
    """Every test named in a register row's last column must exist, so evidence cannot rot.

    Accepted forms: ``path/to/test_x.py``, ``path/to/test_x.py::test_y``, a bare ``test_x.py``
    (unique file name), and ``::test_y`` (same file as the previous reference in the row).
    """
    problems: list[str] = []
    for line in text.splitlines():
        if not ROW_RE.match(line):
            continue
        row_id = line.split("|")[1].strip()
        evidence = line.rstrip().rstrip("|").rsplit("|", 1)[-1]
        current: list[Path] = []
        for ref in TEST_REF_RE.findall(evidence):
            file_part, _, func = ref.partition("::")
            if file_part:
                path = ROOT / file_part
                current = [path] if "/" in file_part and path.is_file() else _test_files(Path(file_part).name)
                if not current:
                    problems.append(f"{row_id}: test file `{file_part}` does not exist")
                    continue
            if func and not any(
                re.search(rf"^\s*(?:async\s+)?def {re.escape(func)}\(", f.read_text(encoding="utf-8"), re.M)
                for f in current
            ):
                problems.append(
                    f"{row_id}: test `{func}` not found in {[c.relative_to(ROOT).as_posix() for c in current]}"
                )
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check", action="store_true", help="exit non-zero instead of rewriting")
    args = parser.parse_args()

    markers = find_markers()
    text = DOC.read_text(encoding="utf-8")
    new_text, missing, changed = resolve(text, markers)
    referenced = {m.group("id1") or m.group("id2") for m in REF_RE.finditer(text)}
    orphans = sorted(set(markers) - referenced)

    for marker_id in sorted(set(missing)):
        print(f"MISSING  {marker_id}: no `[TM:{marker_id}]` marker found in the code", file=sys.stderr)
    for marker_id in orphans:
        print(f"ORPHAN   {marker_id}: marker in code but no row in THREAT_MODEL.md", file=sys.stderr)

    bad_tests = missing_tests(text)
    for problem in bad_tests:
        print(f"NO TEST  {problem}", file=sys.stderr)

    if args.check:
        if missing or orphans or bad_tests or new_text != text:
            print(
                f"THREAT_MODEL.md is stale ({changed} reference(s) differ); run scripts/resolve_threat_refs.py",
                file=sys.stderr,
            )
            return 1
        print(f"THREAT_MODEL.md references are exact ({len(referenced)} markers).")
        return 0

    if new_text != text:
        DOC.write_text(new_text, encoding="utf-8")
    print(f"resolved {len(referenced) - len(set(missing))}/{len(referenced)} markers, {changed} reference(s) updated")
    return 1 if orphans else 0


if __name__ == "__main__":
    sys.exit(main())
