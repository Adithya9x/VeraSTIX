"""
VeraSTIX — Step 1: Extraction (v2, built against a REAL CAPEv2 report)

Real reports differ from a naive mock in a few important ways we learned
by inspecting actual data:
  - it's "process_id", not "pid"
  - "arguments" is a LIST of {"name":..., "value":...} dicts, not a plain dict
  - registry activity lives under behavior.summary (read_keys/write_keys/delete_keys),
    not attached to individual calls
  - network section has domains/dns/http/tcp/udp/etc, and a domain being present
    does NOT mean it's malicious (e.g. Windows' own connectivity-check domain)
  - CAPE's own "ttps" field maps SIGNATURE NAMES to ATT&CK IDs, with NO evidence
    attached — this is the exact gap VeraSTIX's evidence-citation is meant to close
"""

import json


def load_report(path):
    # Explicit UTF-8 (Windows defaults to cp1252 otherwise, which breaks
    # on real malware data). errors="replace" tolerates malformed bytes
    # instead of crashing — sandbox reports can contain raw strings pulled
    # from the malware sample itself, which aren't guaranteed to be clean text.
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return json.load(f)


def args_list_to_dict(arg_list):
    """Real arguments are [{"name": X, "value": Y}, ...] — flatten for readability."""
    return {a.get("name"): a.get("value") for a in (arg_list or [])}


def extract_process_events(report, evidence, api_allowlist=None):
    """
    Walk real process/call data. Because a single process can have 700+ calls
    (we saw this firsthand), we optionally filter to a smaller set of
    "interesting" APIs — otherwise evidence.json balloons with noise like
    NtTestAlert / RtlUserThreadStart that rarely matter for CTI purposes.
    """
    processes = report.get("behavior", {}).get("processes", [])
    for p_idx, process in enumerate(processes):
        proc_name = process.get("process_name")
        proc_id = process.get("process_id")
        for c_idx, call in enumerate(process.get("calls", [])):
            api = call.get("api")
            if api_allowlist and api not in api_allowlist:
                continue
            evidence.append({
                "evidence_id": f"EVT-{len(evidence)+1:04d}",
                "type": "api_call",
                "process": f"{proc_name} (PID {proc_id})",
                "api": api,
                "timestamp": call.get("timestamp"),
                "arguments": args_list_to_dict(call.get("arguments")),
                "source_path": f"behavior.processes[{p_idx}].calls[{c_idx}]",
            })


def extract_network_events(report, evidence):
    net = report.get("network", {})

    for idx, dns in enumerate(net.get("dns", [])):
        evidence.append({
            "evidence_id": f"EVT-{len(evidence)+1:04d}",
            "type": "network.dns_request",
            "domain": dns.get("request"),
            "answers": dns.get("answers"),
            "timestamp": dns.get("first_seen"),
            "source_path": f"network.dns[{idx}]",
        })

    for idx, http in enumerate(net.get("http", [])):
        evidence.append({
            "evidence_id": f"EVT-{len(evidence)+1:04d}",
            "type": "network.http_request",
            "uri": http.get("uri"),
            "host": http.get("host"),
            "method": http.get("method"),
            "user_agent": http.get("user-agent"),
            "timestamp": http.get("first_seen"),
            "source_path": f"network.http[{idx}]",
        })


def extract_registry_events(report, evidence):
    """
    Real registry activity lives at behavior.summary level, aggregated
    across the whole run — not per-call like our mock assumed.
    """
    summary = report.get("behavior", {}).get("summary", {})
    for idx, key in enumerate(summary.get("write_keys", [])):
        evidence.append({
            "evidence_id": f"EVT-{len(evidence)+1:04d}",
            "type": "registry.write",
            "key": key,
            "source_path": f"behavior.summary.write_keys[{idx}]",
        })


def extract_file_events(report, evidence):
    """
    File writes, from behavior.summary — same aggregation level as registry.
    Important for catching ransomware artifacts (ransom notes, mass writes)
    that may NOT show up as documented crypto API calls, since malware
    often implements its own encryption to dodge API-based detection.
    """
    summary = report.get("behavior", {}).get("summary", {})
    for idx, path in enumerate(summary.get("write_files", [])):
        evidence.append({
            "evidence_id": f"EVT-{len(evidence)+1:04d}",
            "type": "file.write",
            "path": path,
            "source_path": f"behavior.summary.write_files[{idx}]",
        })


def extract_signatures_and_ttps(report, evidence):
    """
    CAPE's signatures + its own ttps mapping. IMPORTANT: these are CAPE's
    CONCLUSIONS, not raw evidence. We tag them distinctly (type starting
    with "cape_") so a later validation step knows these need to be
    checked against real evidence, not treated as evidence themselves.
    """
    for idx, sig in enumerate(report.get("signatures", [])):
        evidence.append({
            "evidence_id": f"EVT-{len(evidence)+1:04d}",
            "type": "cape_signature",
            "name": sig.get("name"),
            "description": sig.get("description"),
            "severity": sig.get("severity"),
            "source_path": f"signatures[{idx}]",
        })

    for idx, ttp in enumerate(report.get("ttps", [])):
        evidence.append({
            "evidence_id": f"EVT-{len(evidence)+1:04d}",
            "type": "cape_ttp_claim",
            "linked_signature": ttp.get("signature"),
            "attack_ids": ttp.get("ttps"),
            "mbc_ids": ttp.get("mbcs"),
            "source_path": f"ttps[{idx}]",
            "note": "UNVERIFIED — asserted by CAPE, no evidence line attached",
        })


def extract_all_evidence(report, api_allowlist=None):
    evidence = []
    extract_process_events(report, evidence, api_allowlist)
    extract_network_events(report, evidence)
    extract_registry_events(report, evidence)
    extract_file_events(report, evidence)
    extract_signatures_and_ttps(report, evidence)
    return evidence


if __name__ == "__main__":
    import sys
    path = sys.argv[1] if len(sys.argv) > 1 else "sample_report.json"
    report = load_report(path)

    # Filter noisy low-value APIs for a first readable pass.
    # (Not a final design decision — just for a first look.)
    interesting_apis = None  # None = no filter, take everything

    evidence = extract_all_evidence(report, api_allowlist=interesting_apis)

    counts = {}
    for e in evidence:
        counts[e["type"]] = counts.get(e["type"], 0) + 1

    print(f"Extracted {len(evidence)} total evidence records:")
    for t, c in counts.items():
        print(f"  {t}: {c}")

    with open("evidence_real.json", "w") as f:
        json.dump(evidence, f, indent=2)
    print("\nFull evidence records written to evidence_real.json")
