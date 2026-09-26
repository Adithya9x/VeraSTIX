# VeraSTIX

**Evidence-Grounded Sandbox-to-STIX Pipeline**

VeraSTIX converts raw malware sandbox reports (CAPEv2 JSON) into shareable, standards-compliant STIX 2.1 threat intelligence — where every claim about what a piece of malware did is required to cite the specific raw evidence that supports it.

*"Vera" — Latin for **true** — because every relationship in the output is verifiable, not just asserted.*

---

## The problem this addresses

Sandbox reports are huge, noisy, and mostly benign background noise. Turning them into clean threat intelligence usually means either:

- **Manual analysis** — accurate, but slow and doesn't scale
- **Naive LLM summarization** — fast, but unreliable. A recent USENIX Security-track paper ([arXiv 2609.01174](https://arxiv.org/abs/2609.01174), "*A SoK for SoCs: Reading the TI Leaves on AI for Cyber Threat Intelligence Generation and Sharing*") benchmarked exactly this: feeding a raw sandbox report to an LLM and asking it to produce STIX output achieved only **25–31% indicator recall**, and **up to 46% of the AI-asserted relationships had no supporting evidence at all.**

That paper explicitly names three open research directions: (1) decomposed, self-validating workflows instead of single-shot generation, (2) full-pipeline benchmarks, and (3) explicit redaction policy. VeraSTIX is a small, concrete attempt at all three.

## What VeraSTIX actually does

```
Raw CAPEv2 report (JSON)
        │
        ▼
 ┌─────────────┐   Flattens the nested report into atomic,
 │ 1. Extract  │   individually-addressable "evidence records"
 └─────────────┘   (evidence_id + source_path for every fact)
        │
        ▼
 ┌─────────────┐   Rule-based ATT&CK technique detection.
 │ 2. Enrich   │   Every claim lists the exact evidence_ids
 └─────────────┘   that justify it — nothing is asserted freely.
        │
        ▼
 ┌─────────────┐   Mechanically verifies every claim:
 │ 3. Validate │   do the cited evidence_ids exist? Are they a
 └─────────────┘   plausible evidence type for this claim?
        │
        ▼
 ┌─────────────┐   Strips victim-identifying data (usernames,
 │ 4. Redact   │   hostnames, internal IPs) with a consistent,
 └─────────────┘   auditable placeholder scheme.
        │
        ▼
 ┌─────────────┐   Serializes validated + redacted claims into
 │ 5. Package  │   a real STIX 2.1 Bundle. Evidence IDs survive
 └─────────────┘   into the output as custom properties.
        │
        ▼
   stix_bundle.json — shareable, cited, redacted CTI
```

The evidence citation isn't cosmetic — it's mechanically enforced at two separate points (the Validator, and again as inspectable data in the final STIX output), and it's checkable by anyone who opens the bundle.

## Benchmark results

Tested against **8 real malware samples** (CAPEv2 reports from the [Thcrull/win-exe-malware-analysis](https://huggingface.co/datasets/Thcrull/win-exe-malware-analysis) dataset), comparing VeraSTIX's independently-derived, cited claims against CAPE's own automated `ttps` field:

| Metric | Paper's naive LLM baseline | VeraSTIX (this project) |
|---|---|---|
| Recall | 25–31% | **41.3%** average (33.3–50% per sample) |
| Unsupported claims | up to 46% | **0%** |

**Read this honestly, not as a headline win:**

- Recall here is measured **against CAPE's own automated tagging**, not independent human-verified ground truth — a narrower, more modest claim than what the paper's baseline was likely measured against.
- This benchmark is **in-sample**: the detection rules were iteratively developed and tuned against these same 8 reports. A held-out test set would likely show a lower, more representative number. This has not yet been done.
- A few rules (native API usage, generic file-attribute changes) are deliberately low-specificity and are marked as such — the STIX output carries a `confidence` field on every relationship so this isn't hidden.
- Some CAPE-claimed techniques (confirmed in at least one sample) appear to come from static analysis rather than the observed dynamic execution, and are **structurally impossible to verify from sandbox behavior logs alone** — this is a real scope boundary of any dynamic-analysis-only pipeline, VeraSTIX included.

The one number that *is* robust regardless of sample size: **0% unsupported claims, by construction**, because every claim is rule-generated with evidence attached rather than freely asserted. That's the actual mechanism this project set out to prove works.

## How this compares to existing tools

This is **not a novel category of tool** — AI-assisted CTI/SOC tooling is an active, crowded space, including projects like AiSOC, ThreatMapper, CTIParsor, cti-expert, IOC_STIX, and ThreatLens, several of which already combine AI analysis, ATT&CK mapping, and STIX export.

What's different here, specifically:

1. **Input is raw sandbox telemetry**, not an already-published report — most existing tools consume finished reports, not the messy dynamic-analysis output that produces them.
2. **A dedicated victim-identity redaction step** — not found in any comparable tool surveyed for this project.
3. **Mandatory, mechanically-validated evidence citation for every claim**, benchmarked directly against this specific paper's published baseline numbers, rather than an unverified accuracy claim.

## Project structure

```
VeraSTIX/
├── data/
│   └── raw_reports/       # input CAPEv2 JSON reports
├── src/
│   ├── extract_v2.py       # Part 1: evidence extraction
│   ├── enrich.py            # Part 2: cited ATT&CK claim generation (18 rules)
│   ├── validate.py          # Part 3: citation validation
│   ├── redact.py            # Part 4: victim-identity redaction
│   ├── stix_export.py       # Part 5: STIX 2.1 bundle output
│   └── benchmark.py         # Part 6: recall/precision benchmarking
├── output/                # generated evidence/claims/bundles
└── README.md
```

## Running it

```bash
pip install stix2

cd src
python extract_v2.py ../data/raw_reports/<report>.json
python enrich.py evidence_real.json
python validate.py evidence_real.json claims.json
python redact.py evidence_real.json
python stix_export.py validated_claims.json "<sample_name>"

# Or run the benchmark across every report in data/raw_reports:
python benchmark.py
```

## Limitations & honest future work

- **Recall coverage is narrow.** 18 rules cover a meaningful but small slice of the full ATT&CK matrix. Techniques requiring static binary analysis (packing/obfuscation detection, DGA classification) are entirely out of scope for a dynamic-behavior-only pipeline.
- **No held-out validation yet.** The benchmark numbers above are in-sample. A genuine train/test split across a larger sample set is the clear next step before trusting these numbers as representative.
- **"Ground truth" is CAPE's own tagging**, not independently verified labels — a fair proxy, but not equivalent to a human-analyst-labeled benchmark.
- **Confidence-graded claims aren't all equal.** Some rules (native API usage, generic registry writes) are intentionally broad and low-specificity; treating every claim in the 41.3% figure as equally strong would be misleading.

## Background reading

Built against the four-stage CTI Generation and Sharing framework (extraction → enrichment → redaction → distribution) from:

> *"A SoK for SoCs: Reading the TI Leaves on AI for Cyber Threat Intelligence Generation and Sharing"* — [arXiv:2609.01174](https://arxiv.org/abs/2609.01174), USENIX Security submission, September 2026.

---

**Author:** Adithya · B.Tech Computer Science & Engineering (Cybersecurity), IIIT Kottayam
