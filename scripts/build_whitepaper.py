#!/usr/bin/env python3
"""Build docs/whitepaper.md and docs/whitepaper.pdf from the template and measured results.

Inputs (all produced by scripts in this repository, never typed by hand):
  * packages/core/src/ciphercompute_core/data/precision_table.json   (calibrate_precision.py)
  * benchmarks/results/results.md                                      (benchmarks/benchmark.py)
  * loadtest/REPORT.md, section "Summary"                               (load test run)

    python scripts/build_whitepaper.py            # writes the .md and the .pdf
    python scripts/build_whitepaper.py --check    # CI: fail if the committed .md is stale
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / "docs" / "whitepaper.template.md"
OUT_MD = ROOT / "docs" / "whitepaper.md"
OUT_PDF = ROOT / "docs" / "whitepaper.pdf"
TABLE = ROOT / "packages" / "core" / "src" / "ciphercompute_core" / "data" / "precision_table.json"
BENCH = ROOT / "benchmarks" / "results" / "results.md"
LOADTEST = ROOT / "loadtest" / "REPORT.md"


def precision_table() -> str:
    sys.path.insert(0, str(ROOT / "packages" / "core" / "src"))
    from ciphercompute_core.params import all_presets
    from ciphercompute_core.precision import bits_from_worst_error, table_key

    table = json.loads(TABLE.read_text(encoding="utf-8"))
    rows = ["| N | security | profile | primes | levels | bits after 0, 1, 2, … levels | key rings |", "|---|---|---|---|---|---|---|"]
    for profile, params in all_presets():
        entry = table.get(table_key(params))
        if entry is None:
            continue
        worst = entry["worst_normalized_error"]
        bits = " · ".join(str(bits_from_worst_error(float(worst[k]))) for k in sorted(worst, key=int))
        rows.append(
            f"| {params.poly_modulus_degree} | {int(params.security_level)} | {profile} | {list(params.coeff_mod_bit_sizes)} | "
            f"{params.depth} | {bits} | {entry.get('key_rings', 1)} |"
        )
    return "\n".join(rows)


def loadtest_summary() -> str:
    text = LOADTEST.read_text(encoding="utf-8")
    match = re.search(r"## Summary\n(.*?)(?=\n## |\Z)", text, re.S)
    if not match:
        raise SystemExit("loadtest/REPORT.md has no '## Summary' section")
    return match.group(1).strip() + "\n\nFull report: `loadtest/REPORT.md`."


def render() -> str:
    out = TEMPLATE.read_text(encoding="utf-8")
    out = out.replace("{{PRECISION_TABLE}}", precision_table())
    out = out.replace("{{BENCHMARK_TABLE}}", BENCH.read_text(encoding="utf-8").strip())
    out = out.replace("{{LOADTEST_SUMMARY}}", loadtest_summary())
    leftover = re.findall(r"\{\{[A-Z_]+\}\}", out)
    if leftover:
        raise SystemExit(f"unfilled placeholders: {leftover}")
    return out


def write_pdf(markdown: str) -> None:
    from markdown_pdf import MarkdownPdf, Section

    body = re.sub(r"\A---\n.*?\n---\n", "", markdown, flags=re.S)  # drop the YAML front matter
    css = (
        "body { font-family: serif; font-size: 10.5pt; line-height: 1.35; }"
        "h1 { font-size: 18pt; } h2 { font-size: 14pt; margin-top: 14pt; } h3 { font-size: 11.5pt; }"
        "table { border-collapse: collapse; font-size: 8pt; } th, td { border: 0.5pt solid #888; padding: 2pt 4pt; }"
        "code { font-family: monospace; font-size: 9pt; }"
    )
    pdf = MarkdownPdf(toc_level=2, optimize=True)
    pdf.meta["title"] = "CipherCompute: Statistics and Inference on Encrypted Data with CKKS"
    pdf.meta["author"] = "lumidren"
    pdf.add_section(Section(body, paper_size="A4"), user_css=css)
    pdf.save(str(OUT_PDF))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check", action="store_true")
    ns = parser.parse_args()
    markdown = render()
    if ns.check:
        if not OUT_MD.exists() or OUT_MD.read_text(encoding="utf-8") != markdown:
            print("docs/whitepaper.md is stale; run scripts/build_whitepaper.py", file=sys.stderr)
            return 1
        return 0
    OUT_MD.write_text(markdown, encoding="utf-8")
    write_pdf(markdown)
    print(f"wrote {OUT_MD} and {OUT_PDF}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
