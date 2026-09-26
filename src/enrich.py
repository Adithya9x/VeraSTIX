"""
VeraSTIX — Step 3: Enrichment

Takes the flat evidence list from extraction and produces ATT&CK technique
CLAIMS, where every claim lists the exact evidence_ids that justify it.

Design: a small rule engine. Each rule is a function that scans the
evidence list and returns zero or more claims. Rules are independent
and additive — this makes it easy to add more later without touching
existing ones.

This is deliberately built WITHOUT looking at CAPE's own `ttps` field,
so we can compare our independently-derived, cited claims against
CAPE's uncited ones afterward.
"""

import json


def rule_security_service_disruption(evidence):
    """
    T1562.001 (Impair Defenses: Disable/Modify Tools) +
    T1489 (Service Stop)

    Pattern: OpenServiceW -> ControlService/DeleteService, where the
    targeted service name matches known AV/EDR/security services.
    """
    security_services = {
        "windefend", "wdboot", "wdfilter", "wdnisdrv", "wdnissvc",
        "wscsvc", "sense", "securityhealthservice", "mbamservice",
        "webroot", "sav", "savservice",
    }
    claims = []
    hit_ids = []
    hit_services = set()
    for e in evidence:
        if e["type"] != "api_call":
            continue
        if e["api"] in ("OpenServiceW", "ControlService", "DeleteService"):
            svc = (e["arguments"].get("ServiceName") or "").lower()
            if svc in security_services:
                hit_ids.append(e["evidence_id"])
                hit_services.add(svc)
    if hit_ids:
        claims.append({
            "technique_id": "T1562.001",
            "technique_name": "Impair Defenses: Disable or Modify Tools",
            "evidence_ids": hit_ids,
            "justification": f"Service-manipulation APIs targeted known security services: {sorted(hit_services)}",
        })
        claims.append({
            "technique_id": "T1489",
            "technique_name": "Service Stop",
            "evidence_ids": hit_ids,
            "justification": f"Security services were stopped/deleted via ControlService/DeleteService: {sorted(hit_services)}",
        })
    return claims


def rule_recovery_inhibition(evidence):
    """
    T1490 (Inhibit System Recovery)
    Pattern: service manipulation targeting VSS (Volume Shadow Copy).
    """
    vss_names = {"vss", "vmicvss", "swprv"}
    hit_ids = []
    for e in evidence:
        if e["type"] != "api_call":
            continue
        if e["api"] in ("OpenServiceW", "ControlService", "DeleteService"):
            svc = (e["arguments"].get("ServiceName") or "").lower()
            if svc in vss_names:
                hit_ids.append(e["evidence_id"])
    if hit_ids:
        return [{
            "technique_id": "T1490",
            "technique_name": "Inhibit System Recovery",
            "evidence_ids": hit_ids,
            "justification": "Volume Shadow Copy Service was manipulated (stopped/deleted), removing recovery points.",
        }]
    return []


def rule_process_injection(evidence):
    """
    T1055 (Process Injection)
    Pattern: VirtualAllocEx/NtAllocateVirtualMemory -> WriteProcessMemory
    -> CreateRemoteThread/NtCreateThreadEx, on the SAME target process,
    close together. (Simplified: same process, all three APIs present.)
    """
    alloc_apis = {"VirtualAllocEx", "NtAllocateVirtualMemory"}
    write_apis = {"WriteProcessMemory", "NtWriteVirtualMemory"}
    thread_apis = {"CreateRemoteThread", "NtCreateThreadEx"}

    by_process = {}
    for e in evidence:
        if e["type"] != "api_call":
            continue
        proc = e["process"]
        by_process.setdefault(proc, {"alloc": [], "write": [], "thread": []})
        if e["api"] in alloc_apis:
            by_process[proc]["alloc"].append(e["evidence_id"])
        elif e["api"] in write_apis:
            by_process[proc]["write"].append(e["evidence_id"])
        elif e["api"] in thread_apis:
            by_process[proc]["thread"].append(e["evidence_id"])

    claims = []
    for proc, hits in by_process.items():
        if hits["alloc"] and hits["write"] and hits["thread"]:
            claims.append({
                "technique_id": "T1055",
                "technique_name": "Process Injection",
                "evidence_ids": hits["alloc"] + hits["write"] + hits["thread"],
                "justification": f"Memory allocation, write, and remote thread creation observed together in {proc}.",
            })
    return claims


def rule_registry_persistence(evidence):
    """
    T1547.001 (Registry Run Keys / Startup Folder)
    Pattern: registry.write event with a key path containing a known
    autorun location.
    """
    autorun_markers = ["\\run", "\\runonce"]
    hit_ids = []
    hit_keys = []
    for e in evidence:
        if e["type"] != "registry.write":
            continue
        key = (e.get("key") or "").lower()
        if any(marker in key for marker in autorun_markers):
            hit_ids.append(e["evidence_id"])
            hit_keys.append(e.get("key"))
    if hit_ids:
        return [{
            "technique_id": "T1547.001",
            "technique_name": "Boot or Logon Autostart Execution: Registry Run Keys",
            "evidence_ids": hit_ids,
            "justification": f"Registry write to autorun key(s): {hit_keys}",
        }]
    return []


def rule_ransomware_indicators(evidence):
    """
    T1486 (Data Encrypted for Impact)

    IMPORTANT LIMITATION, stated honestly: this rule does NOT confirm
    encryption occurred. It flags file-artifact patterns consistent with
    ransomware (ransom-note-style filenames), because encryption itself
    is often invisible to API-level monitoring when malware implements
    its own crypto routine instead of calling documented Windows APIs.
    This claim should be treated as WEAKER / circumstantial evidence
    compared to a directly-observed API call chain.
    """
    note_markers = ["readme", "decrypt", "how_to", "recover", "restore", "ransom"]
    hit_ids = []
    hit_files = []
    for e in evidence:
        if e["type"] != "file.write":
            continue
        path = (e.get("path") or "").lower()
        if any(marker in path for marker in note_markers):
            hit_ids.append(e["evidence_id"])
            hit_files.append(e.get("path"))
    if hit_ids:
        return [{
            "technique_id": "T1486",
            "technique_name": "Data Encrypted for Impact",
            "evidence_ids": hit_ids,
            "justification": f"Ransom-note-style file(s) dropped: {hit_files}. NOTE: circumstantial — no direct encryption API call observed, consistent with malware using custom (non-API) encryption to evade detection.",
            "confidence": "medium — file-artifact pattern only, not a directly observed encryption call",
        }]
    return []


def rule_process_injection_section_based(evidence):
    """
    T1055 (Process Injection) — VARIANT 2: section-mapping + APC injection
    (commonly called "process hollowing" style, or "Atom Bombing"-adjacent).

    Pattern: NtCreateSection -> NtMapViewOfSection -> NtQueueApcThread/
    NtCreateThreadEx/CreateRemoteThreadEx, in the same process. This is
    a DIFFERENT mechanism from the classic Alloc/Write/CreateRemoteThread
    chain in rule_process_injection — no WriteProcessMemory call occurs,
    so that rule alone misses this. Real malware uses many injection
    variants specifically to evade single-pattern detection.
    """
    section_apis = {"NtCreateSection"}
    map_apis = {"NtMapViewOfSection"}
    trigger_apis = {"NtQueueApcThread", "NtCreateThreadEx", "CreateRemoteThreadEx", "NtResumeThread"}

    by_process = {}
    for e in evidence:
        if e["type"] != "api_call":
            continue
        proc = e["process"]
        by_process.setdefault(proc, {"section": [], "map": [], "trigger": []})
        if e["api"] in section_apis:
            by_process[proc]["section"].append(e["evidence_id"])
        elif e["api"] in map_apis:
            by_process[proc]["map"].append(e["evidence_id"])
        elif e["api"] in trigger_apis:
            by_process[proc]["trigger"].append(e["evidence_id"])

    claims = []
    for proc, hits in by_process.items():
        if hits["section"] and hits["map"] and hits["trigger"]:
            claims.append({
                "technique_id": "T1055",
                "technique_name": "Process Injection (section-mapping/APC variant)",
                "evidence_ids": hits["section"] + hits["map"] + hits["trigger"],
                "justification": f"Section creation, mapping, and thread/APC triggering observed together in {proc} — process hollowing / APC injection pattern.",
            })
    return claims


def rule_system_discovery(evidence):
    """
    T1082 (System Information Discovery)
    Pattern: calls that enumerate system/hardware info.
    """
    discovery_apis = {"GetSystemInfo", "GetVersionExW", "GetNativeSystemInfo", "GetSystemMetrics", "GetSystemDirectoryW", "GetVolumeInformationW"}
    hit_ids = [e["evidence_id"] for e in evidence if e["type"] == "api_call" and e["api"] in discovery_apis]
    if hit_ids:
        return [{
            "technique_id": "T1082",
            "technique_name": "System Information Discovery",
            "evidence_ids": hit_ids,
            "justification": f"System/hardware info enumeration APIs called ({len(hit_ids)} call(s)).",
        }]
    return []


def rule_owner_discovery(evidence):
    """
    T1033 (System Owner/User Discovery)
    Pattern: calls that identify the logged-in user or machine identity.
    """
    owner_apis = {"GetComputerNameW", "GetUserNameW", "LookupAccountSidW"}
    hit_ids = [e["evidence_id"] for e in evidence if e["type"] == "api_call" and e["api"] in owner_apis]
    if hit_ids:
        return [{
            "technique_id": "T1033",
            "technique_name": "System Owner/User Discovery",
            "evidence_ids": hit_ids,
            "justification": f"Computer name / username identification APIs called ({len(hit_ids)} call(s)).",
        }]
    return []


def rule_command_execution(evidence):
    """
    T1059 (Command and Scripting Interpreter)
    Pattern: process-creation APIs whose command line invokes a known
    interpreter (cmd.exe, powershell.exe, wscript.exe, cscript.exe).
    """
    process_apis = {"CreateProcessInternalW", "CreateProcessW", "CreateProcessA", "ShellExecuteW", "WinExec"}
    interpreters = ["cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe"]
    hit_ids = []
    for e in evidence:
        if e["type"] != "api_call" or e["api"] not in process_apis:
            continue
        args_text = json.dumps(e.get("arguments", {})).lower()
        if any(interp in args_text for interp in interpreters):
            hit_ids.append(e["evidence_id"])
    if hit_ids:
        return [{
            "technique_id": "T1059",
            "technique_name": "Command and Scripting Interpreter",
            "evidence_ids": hit_ids,
            "justification": f"Process creation invoking a known script/command interpreter ({len(hit_ids)} call(s)).",
        }]
    return []


def rule_registry_modification_generic(evidence):
    """
    T1112 (Modify Registry) — broader catch-all than the autorun-specific
    T1547.001 rule. Deliberately excludes keys already claimed by that
    rule, so we don't double-cite the same evidence under two techniques
    without reason.
    """
    autorun_markers = ["\\run", "\\runonce"]
    hit_ids = []
    for e in evidence:
        if e["type"] != "registry.write":
            continue
        key = (e.get("key") or "").lower()
        if not any(marker in key for marker in autorun_markers):
            hit_ids.append(e["evidence_id"])
    if hit_ids:
        return [{
            "technique_id": "T1112",
            "technique_name": "Modify Registry",
            "evidence_ids": hit_ids,
            "justification": f"Registry key(s) written outside known autorun locations ({len(hit_ids)} write(s)).",
        }]
    return []


def rule_c2_communication(evidence):
    """
    T1071 (Application Layer Protocol / C2 communication)

    Pattern: outbound DNS/HTTP to a domain NOT on a small known-benign
    allowlist (OS/infrastructure connectivity checks, etc).

    IMPORTANT LIMITATION, stated honestly: this does NOT perform real
    domain-reputation lookups. A domain simply being unfamiliar/external
    is weak evidence of C2 on its own (see the msftconnecttest.com false
    positive we found earlier) — so this is deliberately marked as
    medium confidence unless the domain contains an explicit strong
    marker (e.g. "c2." subdomain), which is rare in real-world evasive
    C2 infrastructure but appears in this dataset.
    """
    benign_allowlist = {
        "www.msftconnecttest.com", "ctldl.windowsupdate.com",
        "www.microsoft.com", "login.live.com",
    }
    strong_markers = ["c2.", "malware.", "cnc."]

    hit_ids = []
    domains_seen = []
    strong_signal = False
    for e in evidence:
        if e["type"] not in ("network.dns_request", "network.http_request"):
            continue
        domain = (e.get("domain") or e.get("host") or "").lower()
        if not domain or domain in benign_allowlist:
            continue
        hit_ids.append(e["evidence_id"])
        domains_seen.append(domain)
        if any(marker in domain for marker in strong_markers):
            strong_signal = True

    if hit_ids:
        confidence = "high (explicit C2-labeled subdomain observed)" if strong_signal else \
            "medium — external network communication observed; domain reputation not independently verified, could be a false positive"
        return [{
            "technique_id": "T1071",
            "technique_name": "Application Layer Protocol (C2 communication)",
            "evidence_ids": hit_ids,
            "justification": f"Outbound communication to non-allowlisted domain(s): {sorted(set(domains_seen))}",
            "confidence": confidence,
        }]
    return []


def rule_shared_modules(evidence):
    """T1129 (Shared Modules) — DLL loading via LoadLibrary family."""
    dll_apis = {"LoadLibraryW", "LoadLibraryA", "LoadLibraryExW", "LoadLibraryExA"}
    hit_ids = [e["evidence_id"] for e in evidence if e["type"] == "api_call" and e["api"] in dll_apis]
    if hit_ids:
        return [{
            "technique_id": "T1129",
            "technique_name": "Shared Modules",
            "evidence_ids": hit_ids,
            "justification": f"DLL loaded via LoadLibrary API ({len(hit_ids)} call(s)).",
        }]
    return []


def rule_sandbox_evasion(evidence):
    """
    T1497 (Virtualization/Sandbox Evasion)
    Pattern: anti-debug/anti-VM checks. IsDebuggerPresent alone is common
    in legitimate software too (weak signal) — GetSystemMetrics combined
    with IsDebuggerPresent is a more specific evasion-check pattern.
    Marked medium confidence since IsDebuggerPresent alone isn't definitive.
    """
    evasion_apis = {"IsDebuggerPresent", "GetSystemMetrics", "CheckRemoteDebuggerPresent"}
    hit_ids = [e["evidence_id"] for e in evidence if e["type"] == "api_call" and e["api"] in evasion_apis]
    if hit_ids:
        return [{
            "technique_id": "T1497",
            "technique_name": "Virtualization/Sandbox Evasion",
            "evidence_ids": hit_ids,
            "justification": f"Anti-debug/anti-VM check API(s) called ({len(hit_ids)} call(s)).",
            "confidence": "medium — these APIs are sometimes used by legitimate software too, not exclusively malicious",
        }]
    return []


RULES = [
    rule_security_service_disruption,
    rule_recovery_inhibition,
    rule_process_injection,
    rule_process_injection_section_based,
    rule_registry_persistence,
    rule_ransomware_indicators,
    rule_system_discovery,
    rule_owner_discovery,
    rule_command_execution,
    rule_registry_modification_generic,
    rule_c2_communication,
    rule_shared_modules,
    rule_sandbox_evasion,
]


def enrich(evidence):
    claims = []
    for rule in RULES:
        claims.extend(rule(evidence))
    return claims


def compare_to_cape_claims(our_claims, evidence):
    """
    Pull CAPE's own uncited ttp claims from the evidence list and
    compare technique IDs against what we independently derived.
    """
    cape_technique_ids = set()
    for e in evidence:
        if e["type"] == "cape_ttp_claim":
            cape_technique_ids.update(e.get("attack_ids") or [])

    our_technique_ids = {c["technique_id"] for c in our_claims}
    # normalize sub-technique to parent for comparison (T1562.001 -> T1562 also counts)
    our_parents = {t.split(".")[0] for t in our_technique_ids}

    only_ours = our_technique_ids - cape_technique_ids - our_parents.intersection(cape_technique_ids)
    matched = our_technique_ids & cape_technique_ids
    matched_via_parent = {t for t in our_technique_ids if t.split(".")[0] in cape_technique_ids} - matched

    return {
        "cape_claimed": sorted(cape_technique_ids),
        "we_claimed": sorted(our_technique_ids),
        "matched_exact": sorted(matched),
        "matched_via_parent_technique": sorted(matched_via_parent),
        "we_found_cape_missed": sorted(our_technique_ids - cape_technique_ids - matched_via_parent),
    }


if __name__ == "__main__":
    import sys
    path = sys.argv[1] if len(sys.argv) > 1 else "evidence_real.json"
    evidence = json.load(open(path))

    claims = enrich(evidence)

    print(f"=== {len(claims)} cited ATT&CK claims derived independently ===\n")
    for c in claims:
        print(f"{c['technique_id']}  {c['technique_name']}")
        print(f"  evidence: {c['evidence_ids']}")
        print(f"  why: {c['justification']}\n")

    comparison = compare_to_cape_claims(claims, evidence)
    print("=== Comparison vs CAPE's own (uncited) ttps field ===")
    print(json.dumps(comparison, indent=2))

    with open("claims.json", "w") as f:
        json.dump({"claims": claims, "comparison_vs_cape": comparison}, f, indent=2)
