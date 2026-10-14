# AgentGuard

AgentGuard is a team development repository for **CapabilityGraph**, a
continuous authorization system for autonomous agents. The hackathon problem is:

> Build a policy engine that re-evaluates authorization on every sensitive action an agent takes.

This repository prepares four independent workstreams. It includes the
OPA-backed `POST /v1/authorize` Policy Decision Point. It authenticates a
configured adapter, resolves server-owned facts, and returns correlated ALLOW/DENY
decisions. A read-only NetworkX CapabilityGraph now projects trusted PostgreSQL
facts and explains potential confidential external-disclosure chains. Protected
execution and deployed Salesforce integration remain future work. The gateway
mounts `/mcp`, registers the archive demonstration tool, and preserves the latest
downstream forwarding implementation. Transport calls deny until verified caller
authentication exists; graph paths never prove execution.

See [PDP setup and security limits](docs/policy-pdp.md) for OPA, local credential
generation, and the required downstream decision-correlation protocol.
The PDP also has an opt-in [PostgreSQL context and provenance store](docs/postgresql-context.md)
with migrations, fresh permission/revocation resolution and durable decision audits.
See [CapabilityGraph setup, evidence semantics and API](docs/capabilitygraph.md).
See [integration provenance, validation and VM startup](docs/integration.md).

## Prerequisites

- Python **3.11–3.14** with `venv` and pip; development was checked with Python 3.14.
- Node.js **22.12+ (22 LTS recommended)** and npm 10+; `.nvmrc` selects Node 22.
- Git and Make, on Linux/macOS or Windows through WSL2.
- Internet access to PyPI and npm for the initial install.
- Optional: Docker Engine with the **Compose v2 plugin**.
- Salesforce CLI and an org are needed only for the Salesforce workstream.

## Install and start

From the repository root:

```bash
make setup
make dev
```

`setup` creates `.venv`, installs the Python project and development tools,
installs frontend dependencies, and creates `.env` only if it does not already
exist. There are no credentials to obtain for local development. `dev` starts
three processes; Ctrl-C stops all three.

| Component | Address | Current behavior |
|---|---|---|
| Frontend | http://localhost:5173 | Project shell and backend status |
| Backend | http://127.0.0.1:8000/health | Typed health response |
| Backend API docs | http://127.0.0.1:8000/docs | Authorization and protected read-only graph APIs |
| OPA | http://127.0.0.1:8181 | Rego decision service; start separately or through Compose |
| MCP gateway | http://127.0.0.1:8001/mcp | Streamable HTTP; archive demonstration denies unverified callers |

For independent terminals, use `make backend`, `make gateway`, and `make frontend`.
The frontend forwards `/api/health` to the backend through Vite's development
proxy. Configuration comes from the root `.env`; nothing secret is embedded in
browser code. Restart after changing environment configuration.

Without Make:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
npm --prefix apps/dashboard install
python3 scripts/init_env.py
.venv/bin/python scripts/dev.py
```

Optional container workflow:

```bash
docker compose up --build
# In another terminal, stop containers without deleting data:
docker compose down
```

Compose also starts OPA. To enable authenticated PDP decisions, run `make pdp-init`
and set `AG_PDP_CONTEXT_PATH` as documented in `docs/policy-pdp.md` first.
Compose binds published ports to loopback. Container images are for development,
not a production deployment. Containers need rebuilding after source changes;
the native workflow provides reload. PostgreSQL is optional, enabled through the
`database` profile; follow [database setup](docs/postgresql-context.md) for its
explicit password, migrations, seeding and resolver selection.

## Validation commands

```bash
make test              # Python/contract smoke tests and frontend shell checks
make lint              # Ruff, formatting, ESLint, TypeScript, Prettier
make build             # TypeScript check and Vite production bundle
make contracts-check   # Generated schemas must match their Python source
make check             # All of the above
make smoke             # HTTP smoke checks while make dev is running
make format            # Apply Python and frontend formatting
make test-db           # Trusted context, provenance, audit and migration tests
make test-graph        # Scoped NetworkX graph, risk and protected API tests
make graph-demo        # Disposable SQLite + real Rego demo; no sensitive execution
```

After an intentional contract edit, run `make contracts`, review the generated
JSON Schemas, and include them in the same PR. `make smoke` checks health and the
Vite proxy; it does not test security enforcement. Validation status for the
bootstrap environment is recorded in [docs/verification.md](docs/verification.md).

## Repository layout

```text
apps/dashboard/                      React + TypeScript + Vite starter
services/policy-engine/
  agentguard_backend/
    api/                             Stable schema imports; future routers
    policy/                          PolicyEvaluator interface; DENY stub
    graph/                           Read-only NetworkX projector, risk analysis and API
    salesforce/                      Identity resolver interface
    pdp/                             Existing OPA client and decision coordinator
    db/                              Trusted facts, provenance and audit persistence
  migrations/                        Alembic schema revisions
services/mcp-gateway/
  agentguard_gateway/                 MCP server, forwarding, validated HTTP PDP client
integrations/salesforce/              Salesforce DX project and DENY-only Apex stub
packages/contracts/
  agentguard_contracts/               Authoritative Pydantic models
  schemas/                           Generated JSON Schema artifacts
demo/fixtures/                       Synthetic contracts and opt-in graph declarations
demo/scenarios/                      Disposable graph/PDP/Rego demonstration
tests/                               Contract and metadata validation
scripts/                             Setup, process runner, schema generation, smoke checks
docs/                                Architecture, setup, interfaces, ownership
.github/                             CI and collaboration templates
```

The original research Markdown and Word document remain at the repository root.
They describe a proposed future product, not the implemented scaffold. Where
they differ, the current README and interface documentation describe this branch.

## Team ownership

| Teammate | Primary area | First task |
|---|---|---|
| 1 — Policy & security | `services/policy-engine/`, `packages/contracts/` | Agree on trusted-context resolution and write policy acceptance tests |
| 2 — Salesforce | `integrations/salesforce/`, backend `salesforce/` | Validate the starter in an org and confirm Agentforce prerequisites |
| 3 — MCP | `services/mcp-gateway/` | Design credential-to-agent binding and transport initialization |
| 4 — Frontend & integration | `apps/dashboard/`, integration tests | Define typed API consumption and loading/error states |

See [exact deliverables and boundaries](docs/team-roles.md) and
[CONTRIBUTING.md](CONTRIBUTING.md) before branching. Shared contracts are reviewed
jointly before teammates change their dependent implementations.

## Implemented versus planned

Implemented: the initial OPA-backed authorization endpoint, server-owned synthetic
file and PostgreSQL context resolution, inherited artifact classification,
database decision audits, response correlation, scoped NetworkX graph projection,
bounded evidence-backed exposure analysis, protected graph APIs and failure-path tests. The surrounding
scaffold includes package imports, health endpoints, CORS, the frontend shell,
shared contracts, fixtures, and development commands.
The preserved MCP implementation includes lazy forwarding to the fixed
`archive_record` downstream tool. The HTTP PDP client validates request ID,
canonical digest, policy version, ALLOW reason and decision freshness.

Planned: richer inter-tool graph analysis/manifest importing, production identity integration,
production provenance ingestion and immutable audit controls, real MCP tools, Salesforce
callouts/data mutations, and the final dashboard. Permission changes in the local
context file are re-read on each authorization request.
NetworkX powers the implemented analytical graph. React Flow remains available
for future UI work. The dashboard currently displays backend health.

The Apex class is a source starter and has not been compiled/deployed in an org.
See [Salesforce setup](docs/salesforce-setup.md). Health routes and the gateway
shell are unauthenticated; the PDP requires a configured credential for ALLOW.
This is local development infrastructure, not production security enforcement.

## Troubleshooting

- **Missing dependency / command:** run `make setup` from the repository root.
  For a different Python binary, use `make setup PYTHON=python3.14`.
- **PyPI/npm DNS or connection errors:** installation requires network access.
  Retry when the registries are reachable; do not disable TLS verification.
- **Backend offline in the UI:** check `http://127.0.0.1:8000/health`, then
  `http://localhost:5173/api/health`. Check `AG_BACKEND_URL` and restart Vite.
- **Port already used:** stop the process using 8000, 8001, or 5173 before starting.
  Vite deliberately uses `--strictPort` so proxy/CORS settings stay consistent.
- **`docker compose` missing:** install the Compose v2 plugin or use native setup.
- **Docker socket permission denied:** use your platform's documented Docker
  installation procedure; Docker is optional.
- **Schema check fails:** run `make contracts` and inspect the diff. Do not hand-edit
  generated JSON Schema files.
- **Git metadata read-only:** code can be edited, but branching, staging, and
  committing require a writable checkout. Do not change filesystem restrictions.
- **Frontend preview:** `npm run preview` serves only the built static site. Its
  backend proxy is not configured; use `make dev` for the integrated shell.

Additional reading: [architecture](docs/architecture.md),
[contracts](docs/api-contracts.md), [setup](docs/setup.md), and
[security boundaries](docs/security-model.md).
