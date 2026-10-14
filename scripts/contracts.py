"""Generate committed JSON Schemas, or check them without modifying files."""

import argparse
import json
from pathlib import Path

import agentguard_contracts as contracts

ROOT = Path(__file__).resolve().parents[1]
MODELS = (
    "AuthorizationRequest",
    "AuthorizationResponse",
    "TrustedContext",
    "PolicyDecision",
    "AgentCapabilities",
    "GraphNode",
    "GraphEdge",
    "CapabilityGraph",
    "RuntimeEvent",
    "HealthResponse",
)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    target = ROOT / "packages/contracts/schemas"
    if not args.check:
        target.mkdir(parents=True, exist_ok=True)
    stale = []
    for name in MODELS:
        schema = getattr(contracts, name).model_json_schema()
        schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
        content = json.dumps(schema, indent=2, sort_keys=True) + "\n"
        path = target / f"{name}.json"
        if args.check:
            if not path.exists() or path.read_text() != content:
                stale.append(name)
        else:
            path.write_text(content)
    if stale:
        raise SystemExit(f"Stale schemas: {', '.join(stale)}. Run make contracts.")
    print(f"{'Checked' if args.check else 'Generated'} {len(MODELS)} contract schemas.")


if __name__ == "__main__":
    main()
