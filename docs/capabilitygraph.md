# CapabilityGraph: trusted, read-only capability analysis

CapabilityGraph projects the current PostgreSQL facts into a NetworkX
`MultiDiGraph`. It answers **what combinations of declared capabilities might
expose sensitive data**, not whether an action was authorized or executed.
`POST /v1/authorize` still independently evaluates trusted context through OPA.
The graph is not called from that endpoint and cannot grant authorization.

## Model and evidence sources

The shared `CapabilityGraph`, `GraphNode`, `GraphEdge` and `AgentCapabilities`
contracts remain version 1.0.0 and unchanged. Backend-owned envelopes in
`graph/models.py` add keyed metadata, issues, permission status, audit summaries
and explainable findings. FastAPI's `/openapi.json` describes these models.

| Node | Stable logical identity | Trusted source |
|---|---|---|
| Agent | Principal ID | Verified `pdp_principals` / `pdp_principal_bindings` |
| Action | Principal + action + exact resource scope | `pdp_permissions` |
| Resource/artifact | Resource ID | `pdp_resources` and validated ancestry |
| Destination | Destination ID | Verified, active `graph_destinations` referenced by scoped flows |

IDs are namespaced SHA-256 prefixes over canonical JSON tuples. They do not
include credentials. Different scopes of the same action produce different
nodes. Arrays and metadata keys are deterministically ordered for a fixed
database snapshot. IDs survive permission-row replacement; supporting record
IDs still identify the actual rows. The unpaired lists in `AgentCapabilities`
are a summary/selector, **not** permission to form an action/resource product.
`NetworkXGraphBuilder.build()` accepts only its authenticated snapshot's agent
and resolves capabilities from the snapshot, never the supplied lists.

| Edge | Direction | Grounding / status |
|---|---|---|
| `CAN_INVOKE` | Agent → scoped action | Active exact-scope permission, no current revocation; declared capability, not PDP ALLOW |
| `READS` | Scoped action → input resource | Active `graph_tool_data_flows` row for that exact permission/resource; never inferred from action name |
| `DERIVED_FROM` | **Child artifact → source artifact** | `pdp_provenance_edges`; retained after permission revocation |
| `MAY_SEND_TO` | Scoped action → destination | The same scoped flow declares this output destination; verified active destination metadata required |

`edge_metadata` retains database record IDs, evidence references, flow IDs,
per-flow verification/assumptions, permission IDs and revocation status.
`node_metadata` includes scope, stored classification, classification completeness,
resource type/origin and destination location. `classification: null` on a resource
means **unknown**, not PUBLIC. Null on other node kinds is not a resource label.

NetworkX supports directed parallel typed edges and metadata, and supplies
strongly connected components for explicit provenance cycle detection. There is
no persistent graph database: each query projects a fresh SQL snapshot.

## Additive database migration: team review required

Run `make db-migrate` to apply **0002_capability_graph**, following
`0001_trusted_context`. It adds:

- `graph_destinations`: ID, address, INTERNAL/EXTERNAL/UNKNOWN location,
  ACTIVE/INACTIVE/REVOKED status, trusted verification timestamp.
- `graph_tool_data_flows`: ID, permission FK, exact input resource FK, optional
  destination FK, status, DECLARED/VERIFIED verification, assumption, supporting
  reference and verification timestamp.
- `pdp_provenance_edges.evidence` (declared/observed, existing rows default to
  declared) and optional `evidence_ref`. Observed provenance requires a nonblank
  supporting reference. Defaults do not retroactively claim observed execution.

The previous schema lacked destination location and permission-bound tool data
flow; the PDP's approved-address table cannot supply either. These are the
smallest curated additions used by this detector. They **do not** grant a
permission or alter the PDP's allowlist. A null flow destination establishes an
input relationship only, not a guarantee that the tool has no other outputs.

Only trusted administrators/internal writers may populate these tables. No
agent-facing import or mutation endpoint exists. DECLARED flows require an
explicit assumption. VERIFIED requires a timestamp and supporting reference;
it means a tool contract was verified, **not** that the tool ran. References are
trusted administrative assertions, not cryptographic proof or a new event ledger.

Downgrading to revision 0001 removes graph metadata and provenance evidence
columns but preserves existing PDP facts and lineage. Downgrading to base deletes
the entire schema. Tests downgrade only disposable stores. Review/back up shared
databases; do not downgrade the developer database just to run a demo.

## Projection, classification and revocation

Authentication, permissions and graph facts are read in one fresh REPEATABLE READ
transaction. PostgreSQL graph transactions are marked READ ONLY. Nine bounded
SELECT statements load identity, resources, permissions/current revocation
existence, provenance, flows, referenced destinations and recent audit summaries;
there are no per-resource/ancestor SQL queries. There is no cross-agent join of
action names. Only the caller principal's owned resources and scoped permissions
are included, including historical resource lineage.

The projector uses the **same bounded validator** as the PDP, with bulk-loaded
record lookup instead of SQL lookup. Effective classification is the maximum of
the stored floor and all trusted source labels:
PUBLIC < INTERNAL < CONFIDENTIAL < RESTRICTED. A PUBLIC claim or stored report
floor cannot lower confidential ancestry. SOURCE/DERIVED contradictions, reports
without parents, missing/unverified/cross-owner sources, cycles or excessive
lineage produce unknown classification and incomplete assessment.

Inactive/revoked permissions do not produce usable action relationships. Durable
revocations override ACTIVE flags every query. Provenance remains present even
when a capability is removed. Revoking Case access does not erase an existing
derived report: a separately active report-send permission can still produce a
potential finding. Revoking that send permission removes the finding. Revoking
the caller binding/principal also removes graph API access; this is not an
administrator/history explorer.

Foreign/missing endpoints never become implicit NetworkX nodes. Snapshot, node,
edge, depth, issue and finding bounds are explicit; omitted facts are unknown,
not evidence of safety. Limits are conservative subsets, not pagination. A
provenance-row truncation invalidates classification rather than silently omitting
an ancestor. Graph size and metadata are bounded; at most 50 audit summaries and
100 issues plus a limit indicator are returned.

## Sensitive exposure algorithm

1. Follow an active `CAN_INVOKE` edge to a scoped action.
2. Consider only its `READS` input and `MAY_SEND_TO` output that share the **same
   trusted flow record and permission**. Different tools with the same name or
   agent are never spliced into a path.
3. Require trusted effective CONFIDENTIAL/RESTRICTED input and an EXTERNAL
   destination. External is independently curated, never guessed from absence
   in the PDP allowlist.
4. Traverse only `DERIVED_FROM` ancestry with a sorted, visited-node breadth-first
   search. Select a deterministic strongest sensitive-source proof, preferring
   source records at the same label. Retain one representative path, not all
   simple paths. A verified matching flow is preferred to a duplicate assumed
   flow; unrelated flow assumptions do not contaminate that finding.
5. Return a potential finding with supporting nodes/edges/record references,
   explicit transfer assumptions and missing execution evidence.

`chain` is ordered **source → artifact → scoped tool → destination**. Because
graph DERIVED_FROM and READS point the other way, those proof steps set
`traversal: REVERSE`; their `source`/`target` still preserve the stored graph
orientation. `capability_steps` separately proves the active agent → invocation
permission. `max_depth` counts the lineage steps plus the input/output pair;
the separate permission proof is not part of that transfer-depth budget.

There are no confidence scores, unconstrained shortest paths or exponential path
enumeration. This initial detector analyzes an existing trusted artifact entering
one scoped output capability; it does not synthesize a new report-generation
capability or claim a live inter-tool handoff. Missing mappings/parents/destinations
and bounds yield `incomplete: true`. Zero findings never means the agent is safe.
An external destination may be PDP-approved; a potential exposure finding is not
itself a policy violation. Actual requests still need OPA authorization.

## Four separate evidence categories

| Category | Meaning / current handling |
|---|---|
| Potential capability | CAN_INVOKE/READS/MAY_SEND_TO, always declared even with a verified tool contract |
| Observed fact | Explicitly recorded provenance with a trusted reference; not an email execution event |
| Authorization decision | Actual `pdp_authorization_audits` row, returned separately in `policy_decisions` |
| Confirmed execution | Not stored in this schema; `execution_evidence: NOT_RECORDED`, findings `NOT_ESTABLISHED` |

Audit rows do not store destination or outcome. They cannot prove that an email
was sent, or even correlate an ALLOW to a graph destination. Never render a prior
ALLOW, denial, or static path as successful leakage. The synthetic seed keeps
its provenance declared; tests separately exercise explicit observed registry
facts surviving revocation without inventing runtime execution events.

## Local setup and protected API

Use [PostgreSQL setup](postgresql-context.md) first. No new secrets/environment
variables are required:

```bash
.venv/bin/python -m pip install -e '.[dev,postgres]'
# Existing AG_DATABASE_URL must point to your local development PostgreSQL.
make db-migrate
# For a NEW context store only: make db-seed
# Explicit opt-in, requires the existing exact synthetic PDP fixture/grants:
make graph-demo-seed
AG_ENV=development AG_PDP_CONTEXT_BACKEND=postgres make backend
```

`graph-demo-seed` imports only fixture destination/flow declarations, creates no
permissions/resources, refuses existing graph facts, and never reads or overwrites
`.runtime` credentials. It is not a production manifest importer. Do not reseed
a populated context store or delete volumes to make a command succeed.

Routes:

- `GET /v1/capability-graph` → `GraphProjection`
- `GET /v1/capability-graph/risks` → `RiskAnalysis`

Both require the existing verified development bearer binding. Scope defaults
to the authenticated principal; `agent_id` may select **only that same principal**.
Anonymous/unknown/unverified/revoked identity → 401; other scope → 403; malformed
query → 422; unavailable/unmigrated database or file backend → 503. Successful
and authentication/database error responses set `Cache-Control: no-store`.
Production environments are explicitly disabled (503) pending real graph-reader
authorization/RBAC; localhost binding and CORS are not production authentication.

Use the existing token without printing it or putting it in command arguments:

```bash
.venv/bin/python - <<'PY'
from pathlib import Path
import httpx
token = Path('.runtime/pdp-token').read_text().strip()
headers = {'Authorization': f'Bearer {token}'}
with httpx.Client(base_url='http://127.0.0.1:8000', headers=headers, trust_env=False) as client:
    for route in ['/v1/capability-graph', '/v1/capability-graph/risks']:
        response = client.get(route, params={'agent_id': 'support-agent', 'max_depth': 8})
        response.raise_for_status()
        print(response.json())  # Synthetic graph only; never print headers/token.
PY
```

| Query | Default | Range |
|---|---|---|
| `agent_id` | Authenticated principal | Same principal only; 1–160 characters |
| `max_nodes` | 512 | 2–2000 |
| `max_edges` | 1024 | 1–5000 |
| `max_depth` | 8 | 1–32 |
| `max_findings` | 25 | 1–100 |

`max_depth`/`max_findings` affect risk analysis; the graph route accepts the same
query vocabulary. `/health` remains liveness, not PostgreSQL/OPA readiness.

## Reproducible demonstration and response examples

```bash
make graph-demo
.venv/bin/python demo/scenarios/capability_graph.py --full
```

This is opt-in, disposable **SQLite plus actual OPA CLI/Rego**. It does not use the
developer database, open a network listener, read `.runtime`, send email or mutate
Salesforce. It demonstrates 6 nodes/6 edges, one assumed potential disclosure,
case-read ALLOW, external-report `CG-DATA-EGRESS-001` DENY, and
`CG-PERMISSION-REVOKED` after a disposable grant revocation. The finding count
changes from 1 to 0 and historical provenance remains.

Graph response **excerpt** (additional nodes, edges and metadata omitted here;
`--full` prints the complete, validated envelopes). IDs below are actual stable
IDs for the demo, not React Flow layout positions:

```json
{
  "graph": {
    "nodes": [
      {"id":"resource:019075ed594e31291fea259807435785","label":"report-1042","kind":"resource","classification":"CONFIDENTIAL"},
      {"id":"resource:9ab744fcef7dcbe3368e91210ea99e24","label":"case-1042","kind":"resource","classification":"CONFIDENTIAL"}
    ],
    "edges": [
      {"id":"edge:f568e4005605b7536617a711f0ce9529","source":"resource:019075ed594e31291fea259807435785","target":"resource:9ab744fcef7dcbe3368e91210ea99e24","relationship":"DERIVED_FROM","evidence":"declared"}
    ],
    "semantics":"potential_capabilities"
  },
  "capabilities":{"agent_id":"support-agent","actions":["case.read","email.send"],"resource_ids":["case-1042","report-1042"],"status":"ACTIVE"},
  "execution_evidence":"NOT_RECORDED",
  "incomplete":false,
  "truncated":false
}
```

Risk response **excerpt** (chain, supporting metadata and issue explanation
omitted; `capability_steps` contains the separate active-permission proof):

```json
{
  "agent_id":"support-agent",
  "semantics":"potential_capabilities",
  "findings":[{
    "finding_id":"finding:8e38a8bfa168abc8768a62ba0a141d92",
    "agent_id":"support-agent",
    "risk_category":"POTENTIAL_CONFIDENTIAL_EXTERNAL_DISCLOSURE",
    "priority":"HIGH",
    "affected_resource":"report-1042",
    "sensitive_source":"case-1042",
    "effective_classification":"CONFIDENTIAL",
    "destination":"outsider@example.test",
    "destination_id":"destination:15ad006ccc664f6dd1def51b69326565",
    "assumptions":["Assume the future email.send tool can consume this report and address this external mailbox; transfer has NOT been verified or executed."],
    "missing_evidence":["No correlated trusted execution outcome is stored.","The tool's ability to transfer this input to this destination is declared, not verified."],
    "evidence":["declared"],
    "potentially_reachable":true,
    "reachability":"ASSUMPTION_DEPENDENT",
    "execution_outcome":"NOT_ESTABLISHED"
  }],
  "incomplete":true,
  "truncated":false,
  "execution_evidence":"NOT_RECORDED"
}
```

## Dashboard handoff

Consume `response.graph.nodes/edges` directly using stable IDs and map `label`,
`kind` and classification into React Flow node data. Join metadata by node/edge
ID; expose exact scopes and supporting records on selection.
`node_metadata.resource_id` / `resource_type` are the original PDP resource
reference; do not send hashed React Flow node IDs as `/v1/authorize` resource IDs.
Highlight a finding's
`edge_ids`/`node_ids`, render its ordered `chain` respecting `traversal`, and show
the independent `capability_steps`. Show unknown classification, truncated or
incomplete coverage and assumptions prominently. Distinguish declared edges from
observed provenance. Display audit decisions in a separate panel; no “exfiltrated”
badge without a future correlated trusted execution event.

Do not embed a bearer credential in `VITE_*`, frontend source or committed storage.
This iteration has no dashboard session/BFF or administrator graph-reading role.
For team/browser integration, implement that authorization boundary first; the
existing adapter bearer is for local self-scope API testing only. Frontend, MCP
and Salesforce code were not changed by this milestone. The authorization request,
response, Rego policies and response-correlation requirements remain unchanged.

## Verification and remaining work

```bash
make test-graph
.venv/bin/python -m pytest
.venv/bin/python -m ruff check .
.venv/bin/python -m ruff format --check .
make contracts-check
git diff --check
# Opt-in: UUID-isolated schemas in a disposable PostgreSQL test database.
AG_TEST_DATABASE_URL="$AG_DATABASE_URL" make test-graph
AG_TEST_DATABASE_URL="$AG_DATABASE_URL" make test-db
```

Tests cover scoped projection, cross-agent isolation, current revocations,
historical observed provenance, inherited labels, multi-hop/diamond ancestry,
cycles, deduplication, missing facts, deterministic ordering, bounded output,
API identity/scope failures, sanitized database errors, unchanged contracts and
actual Rego denial/revocation. CI's existing disposable PostgreSQL job runs the
whole suite, including graph cases when the test URL is configured. Local SQLite
and offline PostgreSQL DDL validation are not real PostgreSQL verification.
See [environment-separated verification](verification.md).

Remaining: production identity and graph-reader RBAC, authenticated/append-only
provenance ingestion and verified tool-contract writers, execution-ledger
correlation, cross-owner delegation, schema indexes/query-plan work at enterprise
scale, pagination/rate limits, authenticated dashboard integration, and richer
inter-tool transformation/output scopes. A future manifest importer must validate
tool input/output contracts and exact scopes into these trusted records; it must
not silently promote model-generated descriptions to verified data flow.

References: [NetworkX MultiDiGraph](https://networkx.org/documentation/stable/reference/classes/multidigraph.html),
[NetworkX strongly connected components](https://networkx.org/documentation/stable/reference/algorithms/generated/networkx.algorithms.components.strongly_connected_components.html).
