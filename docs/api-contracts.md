# Shared API contracts

Version: **1.0.0**. Source: `packages/contracts/agentguard_contracts/__init__.py`.
Generated schemas: `packages/contracts/schemas/`. Examples:
`demo/fixtures/contracts.json`. Generation and fixture validation run in CI.

## Implemented HTTP surface

Both services implement `GET /health` using `HealthResponse`:

```json
{"status":"ok","service":"agentguard-backend","version":"0.1.0","mode":"scaffold","enforcement_enabled":false}
```

FastAPI also exposes `/docs`, `/redoc`, and `/openapi.json`. No authorization,
administration, graph, event-ingestion, or MCP endpoint exists. Unimplemented
routes return 404; health does not imply enforcement readiness.

## Contracts for future endpoints

| Model | Producer → consumer | Meaning |
|---|---|---|
| `AuthorizationRequest` | Adapter → core | Validated but untrusted action arguments |
| `TrustedContext` | Authenticated adapter/core → evaluator | Resolved agent and verified resource facts |
| `PolicyDecision` | Evaluator → coordinator | ALLOW/DENY, reason, version, and timestamp |
| `AuthorizationResponse` | Core → adapter | Versioned wrapper around the decision |
| `AgentCapabilities` | Discovery/configuration → graph builder | Declared actions and resource scope |
| `GraphNode`, `GraphEdge`, `CapabilityGraph` | Graph service → frontend | Typed relationships with evidence origin |
| `RuntimeEvent` | Trusted adapter → future ledger | Actual execution outcome, separate from decisions |

Every model rejects extra top-level fields. Caller context is explicitly
untrusted, including arbitrary strings in `context`. A request cannot set
`agent_id`, `principal`, or `trusted_context` at the top level. Authentication is
not yet implemented: the Python trusted-context type itself does not establish
trust. Future HTTP handlers must never deserialize it directly from agent input.

`resource.asserted_classification` is a claim, not authority. The synthetic fixture
deliberately pairs a PUBLIC assertion with a CONFIDENTIAL trusted classification
to make this distinction visible. Final labels must come from metadata and
provenance owned by the service.

Example decision wrapper:

```json
{
  "contract_version": "1.0.0",
  "policy_decision": {
    "decision_id": "example-decision-001",
    "request_id": "example-request-001",
    "decision": "DENY",
    "reason_code": "NOT_IMPLEMENTED",
    "explanation": "Authorization is not implemented in the development scaffold.",
    "policy_version": "scaffold-deny-all",
    "timestamp": "2026-10-12T00:00:00Z"
  }
}
```

## Versioning and changes

Teammate 1 coordinates changes; teammates 2–4 review effects on their adapters and
UI. Change Python models and fixtures together, run `make contracts` and
`make contracts-check`, and include all generated artifacts in the PR. Do not add
service-specific models in another directory when a shared model already exists.

JSON Schema is the language-neutral boundary. The frontend can generate types
from it when it begins consuming these APIs; no separate, drifting set of
authorization TypeScript interfaces is maintained in this starter.
