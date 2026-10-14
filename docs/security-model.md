# Security boundaries and remaining integration work

Health routes are unauthenticated. The initial PDP authenticates explicitly
configured adapter credentials and evaluates trusted facts through OPA; it returns
correlated decisions and never executes a protected operation. MCP transport
calls still deny because no verified caller authenticator is installed. The
gateway preserves a local archive demonstration and optional lazy downstream
forwarder. See [PDP limits and correlation requirements](policy-pdp.md).

The next implementation must establish these boundaries explicitly:

| Boundary | Required behavior | Current state |
|---|---|---|
| Agent → MCP gateway | Authenticate transport, bind credential to agent | Interface only |
| Salesforce → backend | Authenticate adapter and verify org/user binding | PDP bearer binding; org/user verification still planned |
| Agent claims → verified facts | Resolve identity, labels, permissions independently | Server-owned file or PostgreSQL resolver; separate contract types |
| Authorization → execution | Deny on error, timeout, unknown/expired decision | HTTP client validates correlation/freshness; archive executor and optional forwarder preserved; MCP transport remains unauthenticated and denied |
| Derived artifacts | Preserve trusted source classification/provenance | Internal trusted report creation and transitive classification inheritance; no public ingestion |
| Retries | Bind idempotency to principal, operation, resource, arguments | Not implemented |
| Revocation | Re-read current permission state for sensitive actions | File reload or fresh database transaction; durable revocation overrides ACTIVE flags |
| Audit | Distinguish attempted, authorized, executed, and blocked | PostgreSQL decision audit required before ALLOW; no execution ledger |
| Administration | Keep policy administration separate from agent credentials | Not implemented |
| Graph reads | Authenticate reader, restrict scope, bound projection/analysis | Verified development binding, self-scope only, read-only PostgreSQL transaction; production disabled pending RBAC |

Do not accept `TrustedContext` directly from a model-facing HTTP body. Its type
represents an ownership boundary, not cryptographic verification. Likewise, a
valid JSON Schema does not make the values trustworthy.

Graph edges describe potential capabilities without proving execution. Graph
readers cannot supply trusted identity/classification or request another agent's
scope. Exact permission-bound data-flow records, not common action names, ground
possible transfer paths. Unknown lineage/destinations and bounds produce
incomplete assessments. Declared assumptions are explicit; observed provenance
does not prove tool execution. Database errors fail closed with sanitized 503s.
Authorization audit records remain separate, with destination correlation and
execution outcome explicitly NOT_RECORDED. A denied action or potential path
must not be displayed as a successful leak. See [graph security limits](capabilitygraph.md).

The policy evaluator is deterministic OPA/Rego. An LLM may explain a decision
but must never grant authorization. Do not turn the disabled stubs into implicit
ALLOW behavior to unblock another teammate; use explicit isolated fixtures in
tests instead.

No real secrets or customer records belong in fixtures. Local `.env`, Salesforce
authentication folders, local databases, and build output are ignored by Git.

Database mode denies on missing facts, invalid lineage, database errors or failed
audit writes. The development database owner remains trusted; append-only roles,
production identity verification and atomic execution are not implemented.
See [PostgreSQL limits](postgresql-context.md#remaining-security-limits-and-next-milestone).
