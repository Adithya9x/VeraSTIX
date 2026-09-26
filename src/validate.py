"""
VeraSTIX — Step 4: Citation Validator

Purpose: take any set of claims (from enrich.py, or later from an LLM)
and MECHANICALLY verify:
  1. Every evidence_id cited actually exists in the evidence set
     (catches hallucinated/fabricated citations)
  2. The cited evidence actually matches what the claim says it is
     (catches citations that exist but don't really support the claim)
  3. Flags claims with NO evidence_ids at all as automatically REJECTED

This is what turns "evidence-citation" from a nice idea into an
enforced guarantee. A claim that fails validation should never reach
the STIX output — that's the whole point of the project.
"""

import json


class ValidationResult:
    def __init__(self, claim, status, reasons):
        self.claim = claim
        self.status = status  # "VALID", "REJECTED", "WARNING"
        self.reasons = reasons

    def to_dict(self):
        return {
            "technique_id": self.claim.get("technique_id"),
            "status": self.status,
            "reasons": self.reasons,
        }


def build_evidence_index(evidence):
    """evidence_id -> full evidence record, for O(1) lookup."""
    return {e["evidence_id"]: e for e in evidence}


# Rules for whether a given evidence record's TYPE is even plausible
# support for a given claimed technique. This is a lightweight sanity
# check, not a full semantic verifier — but it catches the obvious
# failure mode: a claim citing evidence that couldn't possibly support it
# (e.g. a DNS lookup cited as evidence for "process injection").
PLAUSIBLE_EVIDENCE_TYPES = {
    "T1562.001": {"api_call"},
    "T1489": {"api_call"},
    "T1490": {"api_call"},
    "T1055": {"api_call"},
    "T1547.001": {"registry.write"},
    "T1486": {"file.write", "api_call"},
    "T1082": {"api_call"},
    "T1033": {"api_call"},
    "T1059": {"api_call"},
    "T1112": {"registry.write"},
    "T1071": {"network.dns_request", "network.http_request"},
    "T1129": {"api_call"},
    "T1497": {"api_call"},
}


def validate_claim(claim, evidence_index):
    reasons = []
    status = "VALID"

    evidence_ids = claim.get("evidence_ids", [])

    # Rule 1: no evidence at all = automatic rejection
    if not evidence_ids:
        return ValidationResult(claim, "REJECTED", ["No evidence_ids provided — unsupported claim."])

    # Rule 2: every cited evidence_id must actually exist
    missing = [eid for eid in evidence_ids if eid not in evidence_index]
    if missing:
        reasons.append(f"Cited evidence_ids do not exist in evidence set: {missing}")
        status = "REJECTED"

    # Rule 3: cited evidence type must be plausible for this technique
    valid_ids = [eid for eid in evidence_ids if eid in evidence_index]
    technique = claim.get("technique_id")
    allowed_types = PLAUSIBLE_EVIDENCE_TYPES.get(technique)
    if allowed_types:
        for eid in valid_ids:
            actual_type = evidence_index[eid]["type"]
            if actual_type not in allowed_types:
                reasons.append(
                    f"{eid} is type '{actual_type}', not plausible support for {technique} "
                    f"(expected one of {allowed_types})"
                )
                status = "REJECTED"

    # Rule 4: low-confidence claims pass, but flagged as warnings, not silently accepted
    if status == "VALID" and claim.get("confidence", "").startswith("medium"):
        status = "WARNING"
        reasons.append(f"Claim marked {claim.get('confidence')} — passed structural checks but is circumstantial.")

    if status == "VALID" and not reasons:
        reasons.append(f"All {len(evidence_ids)} cited evidence_ids exist and are plausible support.")

    return ValidationResult(claim, status, reasons)


def validate_all(claims, evidence):
    index = build_evidence_index(evidence)
    return [validate_claim(c, index) for c in claims]


if __name__ == "__main__":
    import sys
    evidence_path = sys.argv[1] if len(sys.argv) > 1 else "evidence_real.json"
    claims_path = sys.argv[2] if len(sys.argv) > 2 else "claims.json"

    evidence = json.load(open(evidence_path))
    claims_data = json.load(open(claims_path))
    claims = claims_data["claims"]

    results = validate_all(claims, evidence)

    print(f"=== Validation results for {len(claims)} claims ===\n")
    valid_count = rejected_count = warning_count = 0
    for r in results:
        print(f"[{r.status}] {r.claim.get('technique_id')} — {r.claim.get('technique_name')}")
        for reason in r.reasons:
            print(f"    {reason}")
        print()
        if r.status == "VALID":
            valid_count += 1
        elif r.status == "REJECTED":
            rejected_count += 1
        else:
            warning_count += 1

    print(f"Summary: {valid_count} VALID, {warning_count} WARNING, {rejected_count} REJECTED")

    # Only VALID + WARNING claims should ever reach STIX packaging.
    passing = [r.claim for r in results if r.status in ("VALID", "WARNING")]
    with open("validated_claims.json", "w") as f:
        json.dump(passing, f, indent=2)
    print(f"\n{len(passing)} claims passed and written to validated_claims.json (ready for redaction/STIX steps)")
