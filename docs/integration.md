# Full project integration

This branch imports prior implementation; it does not claim the imported PDP,
PostgreSQL provenance, capability graph, dashboard or Salesforce scaffold were
created during integration. Both original working trees were preserved.

## Provenance and Git history

- Current GitHub `main`: `384dd3710641a03d1f044585dae485c33048d875`, initial repository files.
- Selected team base: `/home/pyro/trial`'s `chore/team-bootstrap` at
  `375b4647be08d30c8df232b68c60ea9b5aa67eb4`. This includes the prior PDP and
  PostgreSQL work at `b1ded49` and `58c2c38`.
- GitHub gateway baseline: `origin/feat/mcp-gateway` at
  `df3f4572807c8c7943759550dfb0370392e6608b`.
- Latest gateway: `origin/feat/mcp-forwarding` at
  `4c4ecc9c25a0918f16bfa716be707a273f236c41`, a descendant of that baseline.
- GitHub no longer advertises `chore/team-bootstrap`. The retained team base and
  current GitHub history have no common ancestor. The integration uses a normal
  two-parent merge with `--allow-unrelated-histories`; no history is rewritten.
- Destination: `feat/full-project-integration`. No shared branch or PR is merged.

The source had uncommitted capability-graph implementation and an unmerged
README index entry. Its working README contained no conflict markers. That
working content was imported, then updated for the current MCP state. The source
index, local credentials and staged LICENSE deletion were left untouched. The
repository's existing LICENSE was preserved.

## Import inventory

Files inherited through the team-base history supply the prior application and
configuration. Uncommitted source work is listed separately below. Original
research documents remain as background, not implementation claims.

<details>
<summary>Files inherited from the retained team base</summary>

- `.dockerignore`
- `.editorconfig`
- `.env.example`
- `.github/ISSUE_TEMPLATE/bug.md`
- `.github/ISSUE_TEMPLATE/task.md`
- `.github/pull_request_template.md`
- `.github/workflows/ci.yml`
- `.gitignore`
- `.nvmrc`
- `.python-version`
- `CONTRIBUTING.md`
- `CapabilityGraph for Salesforce Agentforce_ A Portable Continuous-Authorization Architecture.docx`
- `Dockerfile`
- `LICENSE`
- `Makefile`
- `README.md`
- `apps/dashboard/.dockerignore`
- `apps/dashboard/.prettierignore`
- `apps/dashboard/.prettierrc.json`
- `apps/dashboard/Dockerfile`
- `apps/dashboard/eslint.config.js`
- `apps/dashboard/index.html`
- `apps/dashboard/package.json`
- `apps/dashboard/src/App.tsx`
- `apps/dashboard/src/health.ts`
- `apps/dashboard/src/main.tsx`
- `apps/dashboard/src/style.css`
- `apps/dashboard/tests/shell.test.mjs`
- `apps/dashboard/tsconfig.json`
- `apps/dashboard/vite.config.ts`
- `conftest.py`
- `deep-research-report.md`
- `demo/fixtures/contracts.json`
- `docker-compose.yml`
- `docs/api-contracts.md`
- `docs/architecture.md`
- `docs/policy-pdp.md`
- `docs/postgresql-context.md`
- `docs/salesforce-setup.md`
- `docs/security-model.md`
- `docs/setup.md`
- `docs/team-roles.md`
- `docs/verification.md`
- `integrations/salesforce/.forceignore`
- `integrations/salesforce/README.md`
- `integrations/salesforce/force-app/main/default/classes/AgentGuardScaffold.cls`
- `integrations/salesforce/force-app/main/default/classes/AgentGuardScaffold.cls-meta.xml`
- `integrations/salesforce/force-app/main/default/classes/AgentGuardScaffoldTest.cls`
- `integrations/salesforce/force-app/main/default/classes/AgentGuardScaffoldTest.cls-meta.xml`
- `integrations/salesforce/sfdx-project.json`
- `packages/contracts/README.md`
- `packages/contracts/agentguard_contracts/__init__.py`
- `packages/contracts/schemas/AgentCapabilities.json`
- `packages/contracts/schemas/AuthorizationRequest.json`
- `packages/contracts/schemas/AuthorizationResponse.json`
- `packages/contracts/schemas/CapabilityGraph.json`
- `packages/contracts/schemas/GraphEdge.json`
- `packages/contracts/schemas/GraphNode.json`
- `packages/contracts/schemas/HealthResponse.json`
- `packages/contracts/schemas/PolicyDecision.json`
- `packages/contracts/schemas/RuntimeEvent.json`
- `packages/contracts/schemas/TrustedContext.json`
- `pyproject.toml`
- `scripts/contracts.py`
- `scripts/dev.py`
- `scripts/init_env.py`
- `scripts/smoke.py`
- `services/policy-engine/agentguard_backend/__init__.py`
- `services/policy-engine/agentguard_backend/api/__init__.py`
- `services/policy-engine/agentguard_backend/app.py`
- `services/policy-engine/agentguard_backend/config.py`
- `services/policy-engine/agentguard_backend/db/__init__.py`
- `services/policy-engine/agentguard_backend/db/audit.py`
- `services/policy-engine/agentguard_backend/db/engine.py`
- `services/policy-engine/agentguard_backend/db/models.py`
- `services/policy-engine/agentguard_backend/db/provenance.py`
- `services/policy-engine/agentguard_backend/db/resolver.py`
- `services/policy-engine/agentguard_backend/db/seed.py`
- `services/policy-engine/agentguard_backend/graph/__init__.py`
- `services/policy-engine/agentguard_backend/pdp/__init__.py`
- `services/policy-engine/agentguard_backend/pdp/audit.py`
- `services/policy-engine/agentguard_backend/pdp/context.py`
- `services/policy-engine/agentguard_backend/pdp/models.py`
- `services/policy-engine/agentguard_backend/pdp/opa.py`
- `services/policy-engine/agentguard_backend/pdp/service.py`
- `services/policy-engine/agentguard_backend/policy/__init__.py`
- `services/policy-engine/agentguard_backend/salesforce/__init__.py`
- `services/policy-engine/alembic.ini`
- `services/policy-engine/migrations/env.py`
- `services/policy-engine/migrations/script.py.mako`
- `services/policy-engine/migrations/versions/0001_trusted_context.py`
- `services/policy-engine/policies/authorize.rego`
- `services/policy-engine/policies/authorize_test.rego`
- `services/policy-engine/scripts/init_context.py`
- `services/policy-engine/scripts/seed_database.py`
- `services/policy-engine/tests/conftest.py`
- `services/policy-engine/tests/test_context.py`
- `services/policy-engine/tests/test_database.py`
- `services/policy-engine/tests/test_migrations.py`
- `services/policy-engine/tests/test_pdp.py`
- `services/policy-engine/tests/test_real_opa.py`
- `services/policy-engine/tests/test_scaffold.py`
- `tests/test_contracts.py`
- `tests/test_salesforce_metadata.py`

</details>

<details>
<summary>Selective working-copy imports from /home/pyro/trial</summary>

- `Makefile`
- `README.md`
- `demo/fixtures/capability-graph.json`
- `demo/scenarios/capability_graph.py`
- `docs/api-contracts.md`
- `docs/architecture.md`
- `docs/capabilitygraph.md`
- `docs/postgresql-context.md`
- `docs/security-model.md`
- `docs/verification.md`
- `pyproject.toml`
- `services/policy-engine/agentguard_backend/app.py`
- `services/policy-engine/agentguard_backend/db/models.py`
- `services/policy-engine/agentguard_backend/db/provenance.py`
- `services/policy-engine/agentguard_backend/graph/__init__.py`
- `services/policy-engine/agentguard_backend/graph/analyzer.py`
- `services/policy-engine/agentguard_backend/graph/api.py`
- `services/policy-engine/agentguard_backend/graph/demo.py`
- `services/policy-engine/agentguard_backend/graph/models.py`
- `services/policy-engine/agentguard_backend/graph/projector.py`
- `services/policy-engine/agentguard_backend/graph/repository.py`
- `services/policy-engine/agentguard_backend/graph/service.py`
- `services/policy-engine/migrations/versions/0002_capability_graph.py`
- `services/policy-engine/scripts/seed_graph_demo.py`
- `services/policy-engine/tests/conftest.py`
- `services/policy-engine/tests/test_graph.py`
- `services/policy-engine/tests/test_graph_api.py`
- `services/policy-engine/tests/test_migrations.py`

</details>

Excluded: `.git`, virtual environments, caches, bytecode, `node_modules`,
`.runtime`, secret `.env` files, database files and generated build outputs.
Every overlapping file was compared. The shared models and all ten generated
schemas were identical in the two sources and remain unchanged.

## Gateway preservation and conflict resolution

GitHub's current gateway implementation takes precedence over the older source
scaffold. The following files came from the latest gateway branch:

- `services/mcp-gateway/agentguard_gateway/__init__.py`
- `services/mcp-gateway/agentguard_gateway/app.py`
- `services/mcp-gateway/agentguard_gateway/config.py`
- `services/mcp-gateway/agentguard_gateway/interfaces.py`
- `services/mcp-gateway/agentguard_gateway/mcp_server.py`
- `services/mcp-gateway/tests/test_gateway_scaffold.py`
- `services/mcp-gateway/tests/test_interfaces.py`
- `services/mcp-gateway/tests/test_mcp_forwarding.py`

`mcp_server.py` is byte-identical to `4c4ecc9`: the MCP tool registration,
request-ID validation, response revalidation, lazy fixed-tool forwarding and
failure paths are preserved. `interfaces.py`, `__init__.py` and
`test_interfaces.py` are unchanged. `app.py` additionally injects the HTTP PDP
client; `config.py` gains explicit server-owned credential/binding settings. Two
existing test files received Ruff formatting only, verified by identical ASTs.
No existing gateway test was removed or weakened.

The six merge conflicts were resolved explicitly:

| File | Resolution |
|---|---|
| `.gitignore` | Union of both exclusion sets |
| `README.md` | Existing full-project text, corrected for integrated state |
| `pyproject.toml` | Existing MCP pins plus source SQLAlchemy/Alembic and PostgreSQL extra |
| Gateway `__init__.py` | Latest GitHub description |
| Gateway `app.py` | Latest GitHub MCP mount/lifespan, then HTTP client injection |
| Gateway `tests/test_gateway_scaffold.py` | Latest GitHub tests, formatting only |

## Integration changes

- New `HTTPAuthorizationClient` calls `AG_POLICY_URL/v1/authorize`. Its credential
  and agent/adapter binding come from gateway settings, never model arguments.
  Binding mismatches are rejected before any HTTP request.
- The client validates the shared response, request ID, canonical SHA-256 digest,
  expected policy version, ALLOW reason, UTC issuance and unexpired decision.
  Lifetime must be positive and at most 15 seconds. Malformed responses, missing
  headers, redirects, HTTP errors and timeouts cannot authorize execution.
- Canonicalization moved without changing its bytes into
  `agentguard_contracts.canonical`. The backend still exports the existing
  `request_digest` import. No redundant authorization models were added.
- Compose uses `backend`, `opa` and `postgres` DNS names inside containers.
  Policy version/timeout/expiry and gateway binding configuration are explicit.
  OPA/PostgreSQL and application ports remain loopback-only. The existing
  `pdp_postgres_data` volume declaration is retained.
- The dashboard lockfile is committed; Make, CI and its image use `npm ci`.
  Documentation and the dashboard's status text reflect the integrated backend.
  Docker/Git exclusions keep runtime secrets and development artifacts out.
- The graph seed command supplies a repository fixture path explicitly, and the
  Python image includes the synthetic fixtures. This fixes the installed-wheel
  path mismatch found by the container startup check.
- `tests/test_gateway_pdp.py` adds 24 security/contract integration cases.

## Validation on 2026-10-14

The isolated validation environment used Python 3.14.4, Node 22.22.1, pinned
Python dependencies, PostgreSQL 16 and OPA 1.6.0. Initial dependency installation
needed network access outside the sandbox. Host npm 9.2.0 emitted the declared
npm-version warning; frontend checks still executed successfully. The supported
Node 22 container supplies its own npm.

- Gateway baseline: **17 passed** independently.
- Backend baseline without external services: **134 passed, 6 explicitly skipped**.
- New cross-service tests: **24 passed**.
- Full suite with disposable PostgreSQL, OPA CLI and OPA HTTP: **282 passed,
  zero skipped**. PostgreSQL migration round-trip and graph cases ran against
  isolated test schemas, including preservation of existing PDP rows.
- Real Rego policy suite: **14/14 passed**.
- Synthetic graph demo with real Rego passed: authorized read, confidential egress
  denied, revocation denied, potential finding removed while provenance remained.
- Direct gateway HTTP-client / backend ASGI / real PostgreSQL / live OPA HTTP
  check passed: read ALLOW, confidential egress DENY, archive DENY, protected graph
  query and fresh permission revocation. The ASGI link was in-process; PostgreSQL
  and OPA connections were real network connections.
- Ruff lint/format, ten generated contract schemas, Compose configuration,
  frontend ESLint/Prettier, frontend tests, TypeScript and Vite build passed.
- Both Docker images built. Full Compose startup passed with disposable
  PostgreSQL/OPA: migrations, PDP seeding, graph seeding, all application health
  checks, frontend proxy, authenticated PDP ALLOW, graph risk query and real MCP
  discovery/authentication DENY. Stopping OPA produced `CG-OPA-UNAVAILABLE` / DENY
  through the gateway HTTP client. The full 282-case suite passed again after the
  installed-package fixture fix.
- All validation containers and their owned temporary volumes were removed.
  No existing database volume was reset or deleted.

Salesforce source metadata checks passed; no Apex compilation, Salesforce org
login, deployment, Agentforce invocation or Named Credential callout was run.
Remote CI results and actual Proxmox deployment are separate from these checks.
Python 3.11 is configured in CI but was not executed in this local session.

To reproduce the service-dependent suite, install the development and PostgreSQL
extras, provide an OPA 1.x CLI and live HTTP service, and use a **disposable** test
PostgreSQL database:

```bash
.venv/bin/python -m pip install -e '.[dev,postgres]'
# Export AG_TEST_DATABASE_URL and AG_TEST_OPA_URL for those disposable services.
.venv/bin/python -m pytest
make opa-test
make check
```

## Proxmox VM startup

Ready for a private hackathon/development deployment after configuring secrets.
The dashboard image serves Vite development mode. Production identity verification,
TLS ingress, graph-reader RBAC and guarded business execution remain unfinished.
MCP transport intentionally denies unverified callers; merely setting a PDP
credential does not turn it into an authenticated transport. The current Rego
supports `case.read` and `email.send` and still denies `archive.local_demo`.

On a new Linux VM, install Git, Python 3 and Docker Engine with Compose first.
The container workflow needs no host Python packages or Node installation.
Run these commands for a **new, empty development database**:

```bash
git clone --branch feat/full-project-integration https://github.com/jaya-iyapps/AgentGuard.git AgentGuard
cd AgentGuard
python3 scripts/init_env.py
python3 services/policy-engine/scripts/init_context.py
export AG_PDP_CONTEXT_PATH=.runtime/pdp-config/context.json
export AG_PDP_CONTEXT_BACKEND=postgres
read -r -s -p 'PostgreSQL password (URL-safe): ' AG_POSTGRES_PASSWORD
export AG_POSTGRES_PASSWORD
export AG_DATABASE_URL="postgresql+psycopg://agentguard:${AG_POSTGRES_PASSWORD}@postgres:5432/agentguard"
docker compose --profile database config --quiet
docker compose --profile database build
docker compose --profile database up -d --wait postgres opa
docker compose --profile database run --rm --no-deps backend python -m alembic -c services/policy-engine/alembic.ini upgrade head
docker compose --profile database run --rm --no-deps backend python services/policy-engine/scripts/seed_database.py
docker compose --profile database run --rm --no-deps backend python services/policy-engine/scripts/seed_graph_demo.py --synthetic-demo
docker compose --profile database up -d --wait backend gateway dashboard
curl --fail http://127.0.0.1:8000/health
curl --fail http://127.0.0.1:8001/health
```

The initializer refuses to replace existing credentials; the database seed
refuses a populated context store. Existing installations must retain their
Compose project name (`COMPOSE_PROJECT_NAME` or `-p`) and volume, reuse the
configured password, back up before migrations, and skip initialization/seeding.
Never use `down -v` on persistent deployment data. Stop with
`docker compose --profile database down`, which preserves the volume.
Persist deployment settings in the ignored `.env` with owner-only permissions
or the VM secret manager before recreating services. Never print rendered
Compose secrets; validate with `config --quiet`.

For a simpler file-backed demo, generate context as above, export only
`AG_PDP_CONTEXT_PATH`, and run `docker compose up -d --build --wait`.
For native development with Python 3.11–3.14 and Node 22/npm 10+, use
`make setup`, `make pdp-init`, set `AG_PDP_CONTEXT_PATH`, start `make opa`, then
`make dev` in another terminal. PostgreSQL and graph setup remain optional there.

Loopback backend, gateway and dashboard addresses are reachable on the VM or via
an SSH tunnel. Public Salesforce access requires a reachable HTTPS reverse proxy
for the backend; keep OPA and PostgreSQL private. A `/health` result establishes
liveness only, not authenticated authorization readiness.

## Review and Salesforce handoff

Review the integration branch and the additive graph migration before team
adoption. The Salesforce teammate needs the deployed backend HTTPS base URL,
a trusted certificate/DNS route, and a distinct server-owned Salesforce adapter
credential with the agreed agent/org/execution-user binding. Do not reuse the
synthetic MCP credential as a production Salesforce identity.

The current Apex class always returns DENY and has no callout implementation.
Implement and test its Named Credential callout to `POST /v1/authorize`, preserving
sharing and CRUD/field checks, and validating the response/digest/expiry/version
before any side effect. Configure the Named/External Credential and permission
set only after the endpoint and authentication agreement are available. Verify
ALLOW, DENY, outage and revocation behavior from the target org before enabling
an Agentforce action. See [Salesforce setup](salesforce-setup.md).
