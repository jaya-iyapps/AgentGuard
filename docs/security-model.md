# Security boundaries for future implementation

Health routes are unauthenticated. The initial PDP authenticates explicitly
configured adapter credentials and evaluates trusted facts through OPA; it returns
correlated decisions and never executes a protected operation. The gateway stub
still denies. See [PDP limits and correlation requirements](policy-pdp.md).

The next implementation must establish these boundaries explicitly:

| Boundary | Required behavior | Current state |
|---|---|---|
| Agent → MCP gateway | Authenticate transport, bind credential to agent | Interface only |
| Salesforce → backend | Authenticate adapter and verify org/user binding | PDP bearer binding; org/user verification still planned |
| Agent claims → verified facts | Resolve identity, labels, permissions independently | Explicit server-owned file resolver; separate contract types |
| Authorization → execution | Deny on error, timeout, unknown/expired decision | No executor exists |
| Derived artifacts | Preserve trusted source classification/provenance | Contract only |
| Retries | Bind idempotency to principal, operation, resource, arguments | Not implemented |
| Revocation | Re-read current permission state for sensitive actions | Per-request file reload; persistent state still planned |
| Audit | Distinguish attempted, authorized, executed, and blocked | Event schema only |
| Administration | Keep policy administration separate from agent credentials | Not implemented |

Do not accept `TrustedContext` directly from a model-facing HTTP body. Its type
represents an ownership boundary, not cryptographic verification. Likewise, a
valid JSON Schema does not make the values trustworthy.

Graph edges can describe potential capabilities without proving execution. A
future denied action must not be displayed as a successful leak. Preserve
declared/observed semantics throughout graph storage and UI rendering.

The future policy evaluator must be deterministic. An LLM may explain a decision
but must never grant authorization. Do not turn the disabled stubs into implicit
ALLOW behavior to unblock another teammate; use explicit isolated fixtures in
tests instead.

No real secrets or customer records belong in fixtures. Local `.env`, Salesforce
authentication folders, local databases, and build output are ignored by Git.
