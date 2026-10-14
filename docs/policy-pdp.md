# Initial Policy Decision Point

This iteration implements `POST /v1/authorize` with the existing
`AuthorizationRequest` and `AuthorizationResponse` JSON contracts. It resolves
trusted facts, asks OPA, validates the decision, and returns ALLOW/DENY. It does
not execute email, MCP tools, or Salesforce mutations.

## Start locally

Install the project with the root README's `make setup`. Install an OPA 1.x CLI
from the official releases, or use the pinned Docker service.

```bash
make pdp-init
export AG_PDP_CONTEXT_PATH=.runtime/pdp-config/context.json
# Terminal 1: choose one OPA option
make opa
# OR: docker compose up opa
# Terminal 2, with AG_PDP_CONTEXT_PATH set:
make backend
```

Alternatively, after `pdp-init` and exporting the path, `docker compose up --build`
starts the backend and its OPA sidecar. The generated configuration contains
synthetic metadata and a SHA-256 hash of a random credential. The credential
itself is stored in `.runtime/pdp-token` with owner-only permissions and is never
printed by the setup script. Both paths are ignored by Git. Existing files are
preserved; the initializer refuses to overwrite them.

An empty `AG_PDP_CONTEXT_PATH`, missing file, unknown credential, or unavailable
OPA cannot produce ALLOW. The file is reloaded per authorization request so
editing a permission to `REVOKED` affects the next request in the same session.
Use an atomic file replacement when editing a running service; malformed or
partially written configuration temporarily denies rather than grants access.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `AG_OPA_URL` | `http://127.0.0.1:8181` | Server-owned OPA base URL; Compose uses `http://opa:8181` |
| `AG_OPA_DECISION_PATH` | `agentguard/authz/decision` | OPA Data API decision path |
| `AG_OPA_TIMEOUT_SECONDS` | `1.0` | HTTP timeout, positive and at most 30 seconds |
| `AG_OPA_POLICY_VERSION` | `pdp-v1` | Expected deployed policy version; mismatches deny |
| `AG_PDP_CONTEXT_PATH` | empty | Explicit server-owned credential/resource/permission configuration |
| `AG_PDP_DECISION_TTL_SECONDS` | `5` | Response expiry interval, at most 15 seconds |

`AG_PDP_CONTEXT_BACKEND=postgres` selects the database implementation instead of
the default file resolver. See [database setup, migrations and provenance](postgresql-context.md)
for its required URL, driver, seeding, audit behavior and validation limits.

`/health` remains the existing liveness contract. Its `enforcement_enabled=false`
is accurate: this service returns decisions and performs no protected execution.
It does not claim OPA readiness; authenticated authorization fails closed while
OPA is starting or unreachable.

## Example request

```bash
PDP_TOKEN=$(<.runtime/pdp-token)
curl --include http://127.0.0.1:8000/v1/authorize \
  -H "Authorization: Bearer $PDP_TOKEN" \
  -H 'Content-Type: application/json' \
  --data '{"request_id":"read-001","session_id":"session-001","action":"case.read","resource":{"id":"case-1042","type":"case"}}'
```

With the supplied Rego loaded and generated context configured, the response is
expected to have this shape (IDs and timestamp vary):

```json
{
  "contract_version": "1.0.0",
  "policy_decision": {
    "decision_id": "server-generated-uuid",
    "request_id": "read-001",
    "decision": "ALLOW",
    "reason_code": "CG-ALLOW-001",
    "explanation": "Verified identity, current permission, and trusted resource facts permit this action.",
    "policy_version": "pdp-v1",
    "timestamp": "2026-10-12T00:00:00Z"
  }
}
```

An authenticated request for `email.send`, resource `report-1042` of type `report`,
and destination `outsider@example.test` returns DENY / `CG-DATA-EGRESS-001`.
Claiming `asserted_classification=PUBLIC` does not change the trusted label.
`support@company.example` is the generated configuration's only approved address.
PUBLIC email can be allowed by Rego when explicit permission exists; email is not
universally prohibited. This iteration supports `case.read` and `email.send`.
Unknown actions, including the MCP branch's `archive.local_demo`, default to DENY.

Authentication identifies a configured adapter/agent binding. The request's
`context`, `provenance_refs`, and classification assertions are untrusted and do
not populate policy facts. Resources, provenance references, owner, classification,
and permission states come from the server-owned file or database. The input does not contain
the bearer credential or raw case contents.

## Required adapter correlation — coordinate with MCP and Salesforce owners

The JSON models remain unchanged. The response adds two mandatory headers for
future enforcement clients:

- `X-AgentGuard-Request-Digest`: lowercase SHA-256 of the validated request's
  canonical JSON, including request ID, session, action, resource, destination,
  provenance assertions, and context.
- `X-AgentGuard-Decision-Expires-At`: UTC ISO timestamp. Expired decisions deny.

Canonicalization is defined by `request_digest()` in the PDP: validate the shared
model, include its defaults and nulls, serialize JSON with sorted keys, no extra
whitespace, UTF-8 and `ensure_ascii=False`, then hash. Do not hash the raw HTTP
body; omitted defaults and JSON key order would otherwise differ.

A future adapter must validate the model, require the matching response
`request_id`, compare the digest against its exact pending request (which binds
the action), require the expected policy version and a valid unexpired header,
and require `decision=ALLOW`. Missing headers, parsing failures, HTTP errors, or
mismatches deny. `HTTP 200` alone never authorizes an operation. Do not reuse
decisions or treat request IDs as execution idempotency keys. The OPA client also
checks echoed request ID, action, digest, and version before returning any ALLOW.

The integrated gateway's `HTTPAuthorizationClient` validates these headers,
request ID, policy version, `CG-ALLOW-001` for ALLOW, and UTC decision timestamps
before returning the shared JSON model. It rejects missing/expired headers,
future timestamps, TTLs above 15 seconds, redirects, malformed bodies and HTTP
errors. Canonicalization lives in `agentguard_contracts.canonical`; the PDP
continues to export `request_digest` for existing consumers. No API schema changed.
Its credential and agent/adapter binding come from server configuration, not tool
arguments. This does not implement MCP caller authentication: transport calls
still supply no trusted identity and deny. The current Rego still denies the
archive action. Complete verified caller binding and separately reviewed action
policy before enabling any protected transport execution.

## Tests

```bash
make test-pdp            # Endpoint, resolver, and mocked OPA tests
make test                # Existing contracts and other scaffold tests too
make contracts-check    # No shared schema changes in this iteration
make opa-test            # Fourteen real Rego cases; requires an OPA CLI
# With OPA running locally:
AG_TEST_OPA_URL=http://127.0.0.1:8181 .venv/bin/python -m pytest services/policy-engine/tests/test_real_opa.py
```

Python real-OPA tests skip explicitly when the CLI or opt-in HTTP URL is absent.
CI adds a Docker-based OPA policy-test job, pinned to `openpolicyagent/opa:1.6.0`.
Mocked endpoint tests verify failure/correlation behavior; they do not establish
that Rego ran. Actual real-OPA execution must be reported separately.

## Security limits and next iteration

This is a development credential binding and a curated synthetic context store,
not OAuth, a production identity provider, or a provenance registry. Use HTTPS
and separate per-adapter/agent credentials outside isolated local development.
OPA's management API is unauthenticated in this local Compose configuration and
must remain private; do not expose it publicly.

The PDP trusts the configured OPA and context administrator. PostgreSQL mode now
persists decision audits before returning ALLOW; file mode has no durable ledger.
There is no one-shot token consumption or distributed atomic authorization
and execution. Expiry limits stale use but does not remove the authorization-to-
execution race. No model-generated provenance is ingested or declassified.

The PostgreSQL resolver, resource ownership, inherited artifact classification,
revocations and audit migrations are implemented behind `TrustedContextResolver`.
Real PostgreSQL and OPA HTTP tests passed in the project lead's developer terminal;
see [verification evidence](verification.md). Next project this persisted context
into a read-only NetworkX graph before introducing trusted
artifact registration or protected execution.

References: [OPA Data API](https://www.openpolicyagent.org/docs/rest-api),
[Rego](https://www.openpolicyagent.org/docs/policy-language), and
[pinned OPA release](https://github.com/open-policy-agent/opa/releases/tag/v1.6.0).
