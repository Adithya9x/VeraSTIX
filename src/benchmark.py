"""
VeraSTIX — Step 7: Benchmarking

Runs the full pipeline (extract -> enrich -> validate) across multiple
reports and computes aggregate metrics, compared honestly against the
paper's baseline (25-31% indicator/technique recall, up to 46%
unsupported relationships).

IMPORTANT HONESTY NOTE, stated explicitly in output: our "ground truth"
here is CAPE's own automated `ttps` field, not independent human-verified
ground truth. This measures recall RELATIVE TO CAPE's automated tagging,
not absolute ground-truth recall like the paper likely used. This is a
narrower, more defensible claim — state it exactly this way in writeups,
never as unqualified "recall."

Unsupported-claim rate is trivially near-0% for VeraSTIX BY CONSTRUCTION,
since claims are rule-generated with evidence attached, not freely
asserted by an LLM. This is worth explaining, not just reporting as a win:
it's the structural difference (decomposed+cited pipeline vs single-shot
LLM generation) that the paper's own future-work section pointed at.
"""

import json
import glob
import os

from extract_v2 import extract_all_evidence, load_report
from enrich import enrich, compare_to_cape_claims
from validate import validate_all


def run_pipeline_on_report(report_path):
    report = load_report(report_path)
    evidence = extract_all_evidence(report)
    claims = enrich(evidence)
    results = validate_all(claims, evidence)

    valid_claims = [r.claim for r in results if r.status in ("VALID", "WARNING")]
    rejected_claims = [r.claim for r in results if r.status == "REJECTED"]

    comparison = compare_to_cape_claims(valid_claims, evidence)

    cape_total = len(comparison["cape_claimed"])
    matched = len(comparison["matched_exact"]) + len(comparison["matched_via_parent_technique"])
    recall = (matched / cape_total) if cape_total > 0 else None

    total_claims_attempted = len(claims)
    unsupported_rate = (len(rejected_claims) / total_claims_attempted) if total_claims_attempted > 0 else 0.0

    return {
        "report": os.path.basename(report_path),
        "cape_claimed_count": cape_total,
        "we_matched_count": matched,
        "recall_vs_cape": round(recall, 3) if recall is not None else None,
        "claims_attempted": total_claims_attempted,
        "claims_rejected_by_validator": len(rejected_claims),
        "unsupported_rate": round(unsupported_rate, 3),
        "we_found_cape_missed": comparison["we_found_cape_missed"],
    }


def run_benchmark(report_paths):
    per_report = []
    for path in report_paths:
        try:
            result = run_pipeline_on_report(path)
            per_report.append(result)
        except Exception as e:
            per_report.append({"report": os.path.basename(path), "error": str(e)})

    valid_results = [r for r in per_report if "recall_vs_cape" in r and r["recall_vs_cape"] is not None]
    avg_recall = sum(r["recall_vs_cape"] for r in valid_results) / len(valid_results) if valid_results else None
    avg_unsupported = sum(r["unsupported_rate"] for r in per_report if "unsupported_rate" in r) / len(per_report) if per_report else None

    return {
        "n_reports": len(report_paths),
        "avg_recall_vs_cape": round(avg_recall, 3) if avg_recall is not None else None,
        "avg_unsupported_rate": round(avg_unsupported, 3) if avg_unsupported is not None else None,
        "per_report": per_report,
    }


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        report_paths = sys.argv[1:]
    else:
        report_paths = glob.glob("../data/raw_reports/*.json")
        if not report_paths:
            report_paths = glob.glob("*.json")

    print(f"Running benchmark across {len(report_paths)} report(s)...\n")
    results = run_benchmark(report_paths)

    print("=== Per-report results ===")
    for r in results["per_report"]:
        print(json.dumps(r, indent=2))
        print()

    print("=== AGGREGATE ===")
    print(f"n = {results['n_reports']} report(s)")
    print(f"Average recall vs CAPE's own tagging: {results['avg_recall_vs_cape']}")
    print(f"Average unsupported-claim rate: {results['avg_unsupported_rate']}")
    print()
    print("HONEST FRAMING for writeup:")
    print("- This measures recall RELATIVE TO CAPE's own automated ttps field,")
    print("  not independent human-verified ground truth like the paper likely used.")
    print("- Unsupported rate is near-0 BY CONSTRUCTION (rule-based + citation-validated")
    print("  pipeline, not free-form LLM generation) — this demonstrates the structural")
    print("  fix works, not that we 'beat' the paper's number in the same regime.")
    if results["n_reports"] < 10:
        print(f"- n={results['n_reports']} is TOO SMALL for a statistically meaningful claim.")
        print("  Treat this as a proof-of-concept result, not a publishable benchmark,")
        print("  until run across 15-20+ samples.")

    with open("benchmark_results.json", "w") as f:
        json.dump(results, f, indent=2)
