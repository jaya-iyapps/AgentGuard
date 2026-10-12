"""Create explicit synthetic PDP configuration and a random local adapter credential."""

import hashlib
import json
import os
import secrets
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
context_path = ROOT / ".runtime/pdp-config/context.json"
token_path = ROOT / ".runtime/pdp-token"
if context_path.exists() or token_path.exists():
    raise SystemExit("Existing PDP configuration preserved. See docs/policy-pdp.md.")

credential = secrets.token_urlsafe(32)
document = {
    "identities": [
        {
            "credential_sha256": hashlib.sha256(credential.encode()).hexdigest(),
            "agent_id": "support-agent",
            "adapter_id": "local-mcp-adapter",
            "surface": "mcp",
            "status": "ACTIVE",
            "permissions": [
                {"action": "case.read", "resource_id": "case-1042", "status": "ACTIVE"},
                {"action": "email.send", "resource_id": "report-1042", "status": "ACTIVE"},
            ],
        }
    ],
    "resources": [
        {
            "id": "case-1042",
            "type": "case",
            "classification": "CONFIDENTIAL",
            "owner_agent_id": "support-agent",
        },
        {
            "id": "report-1042",
            "type": "report",
            "classification": "CONFIDENTIAL",
            "owner_agent_id": "support-agent",
            "provenance_refs": ["case-1042"],
        },
    ],
    "approved_destinations": ["support@company.example"],
}
context_path.parent.mkdir(parents=True, exist_ok=True)
# Configuration contains only synthetic metadata and a high-entropy credential hash.
# It is readable by the unprivileged Docker user but writable only by its owner.
with os.fdopen(os.open(context_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644), "w") as stream:
    stream.write(json.dumps(document, indent=2) + "\n")
with os.fdopen(os.open(token_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as stream:
    stream.write(credential + "\n")
print("Created synthetic context in .runtime/pdp-config/context.json.")
print("Random credential stored in .runtime/pdp-token (not printed, not committed).")
print("Set AG_PDP_CONTEXT_PATH=.runtime/pdp-config/context.json before starting the backend.")
