"""
VeraSTIX — Step 5: Redaction

Strips victim-identifying information (usernames, hostnames, internal IPs)
from evidence/claims before anything is packaged for sharing.

Design principles:
  - CONSISTENT placeholders: the same real value always maps to the same
    placeholder within one report, so relationships between events stay
    visible (e.g. "same host did X and Y") without revealing WHO that host is.
  - AUDITABLE, not silent: a manifest records exactly what was redacted
    and where, kept as a LOCAL-ONLY file — never shipped with the
    redacted output. This lets an analyst verify redaction actually
    happened and reverse it internally if legitimately needed, while the
    shared STIX bundle never contains victim identity.
"""

import json
import re


# Windows path username: C:\Users\<name>\...
USERNAME_PATTERN = re.compile(r"(C:\\Users\\)([^\\\"]+)(\\)")

# Private/internal IP ranges (RFC1918)
PRIVATE_IP_PATTERN = re.compile(
    r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b"
)


class Redactor:
    def __init__(self):
        self.manifest = []  # audit trail — local only, never shared
        self._username_map = {}
        self._ip_map = {}
        self._username_counter = 0
        self._ip_counter = 0

    def _get_username_placeholder(self, real_value):
        if real_value not in self._username_map:
            self._username_counter += 1
            self._username_map[real_value] = f"VICTIM_USER_{self._username_counter}"
        return self._username_map[real_value]

    def _get_ip_placeholder(self, real_value):
        if real_value not in self._ip_map:
            self._ip_counter += 1
            self._ip_map[real_value] = f"INTERNAL_IP_{self._ip_counter}"
        return self._ip_map[real_value]

    def redact_string(self, text, evidence_id="unknown"):
        if not isinstance(text, str):
            return text

        original = text

        def sub_username(m):
            real = m.group(2)
            placeholder = self._get_username_placeholder(real)
            return f"{m.group(1)}{placeholder}{m.group(3)}"

        text = USERNAME_PATTERN.sub(sub_username, text)

        def sub_ip(m):
            real = m.group(0)
            return self._get_ip_placeholder(real)

        text = PRIVATE_IP_PATTERN.sub(sub_ip, text)

        if text != original:
            self.manifest.append({
                "evidence_id": evidence_id,
                "original_contained": original,
                "redacted_to": text,
            })
        return text

    def redact_value(self, value, evidence_id="unknown"):
        """Recursively redact strings inside dicts/lists, leave other types alone."""
        if isinstance(value, str):
            return self.redact_string(value, evidence_id)
        elif isinstance(value, dict):
            return {k: self.redact_value(v, evidence_id) for k, v in value.items()}
        elif isinstance(value, list):
            return [self.redact_value(v, evidence_id) for v in value]
        else:
            return value

    def redact_evidence(self, evidence):
        redacted = []
        for e in evidence:
            eid = e.get("evidence_id", "unknown")
            redacted.append(self.redact_value(e, eid))
        return redacted


if __name__ == "__main__":
    import sys
    path = sys.argv[1] if len(sys.argv) > 1 else "evidence_real.json"
    evidence = json.load(open(path, encoding="utf-8", errors="replace"))

    redactor = Redactor()
    redacted_evidence = redactor.redact_evidence(evidence)

    print(f"Redacted {len(redactor.manifest)} field(s) across {len(evidence)} evidence records.")
    print(f"Unique usernames replaced: {len(redactor._username_map)}")
    print(f"Unique internal IPs replaced: {len(redactor._ip_map)}")

    with open("evidence_redacted.json", "w") as f:
        json.dump(redacted_evidence, f, indent=2)
    print("\nRedacted evidence written to evidence_redacted.json (safe to share)")

    # Manifest is LOCAL-ONLY — never bundle this with shared output.
    with open("redaction_manifest_LOCAL_ONLY.json", "w") as f:
        json.dump(redactor.manifest, f, indent=2)
    print("Audit manifest written to redaction_manifest_LOCAL_ONLY.json (DO NOT SHARE THIS FILE)")
