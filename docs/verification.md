# Bootstrap verification

## CapabilityGraph validation — 2026-10-13

Implemented on `feat/capability-graph`, based on committed PDP/PostgreSQL milestone
`58c2c38` and integration merge `375b464`. The clean Git checkpoint was confirmed
before changes; the project lead created the feature branch in the writable host
terminal. No commit, push, merge or credential changes were made in this session.

| Environment | Check | Result |
|---|---|---|
| Sandbox | Complete Python suite | **152 passed, 3 skipped** |
| Sandbox | New graph/API suite | **65 passed, 1 skipped** |
| Sandbox | Real CLI Rego policy suite | **14/14 passed**, policies unchanged |
| Sandbox | Ruff lint / formatting | Passed; all 56 Python files formatted |
| Sandbox | Shared contract validation | Passed; all 10 schemas unchanged |
| Sandbox | Migration tests | **3 passed, 1 skipped**: SQLite round-trip, legacy row preservation and PostgreSQL offline DDL |
| Sandbox | Disposable graph/PDP demo | 6 nodes / 6 edges; potential finding 1 → 0 after email permission revocation; real Rego read ALLOW / disclosure DENY / revoked DENY |

The previous 86 passing Python cases are retained; the additional 66 passing
cases cover graph projection, evidence-backed bounded analysis, protected API
behavior and legacy migration preservation. The new graph/API tests use isolated
SQLite by default. With `AG_TEST_DATABASE_URL` they also run against fresh
UUID-named PostgreSQL schemas; CI already opts in to a disposable database.
The three explicit skips are the real PostgreSQL graph opt-in check, real
PostgreSQL migration round-trip, and live OPA HTTP authorization. No PostgreSQL
graph or revision-0002 live migration result is claimed here.

ASGI graph API tests execute the actual synchronous FastAPI handlers in worker
threads. This restricted sandbox stalls even a trivial AnyIO worker completion
unless a scheduler timer wakes the event loop; a minimal reproduction confirmed
the behavior. The graph API test fixture supplies only a periodic timer and a
30-second safety deadline. It does not mock graph queries, database resolution or
authentication, and production threadpool behavior is unchanged. This is
in-process API verification, not a live listening server/browser check.

The synthetic graph/PDP vertical slice uses real `opa eval` through an in-process
test transport, plus a CLI demonstration using the same Rego directly. Neither
is a live OPA HTTP connection. No email/Salesforce operations exist in this demo;
potential findings and prior ALLOW audits explicitly do not establish execution.

`git fetch origin --prune` remains blocked by read-only `.git/FETCH_HEAD`; current
remote state beyond cached references could not be refreshed. Socket/Docker
restrictions and unconfigured live-test URLs prevent live-service checks. The
previous developer-terminal **56 database** and **2 real OPA** results below
belong to the PDP milestone, not this graph/migration iteration. Follow
[graph setup and verification](capabilitygraph.md) to validate the new migration
and graph against a disposable PostgreSQL database in the developer terminal.

## Latest PDP persistence validation — 2026-10-13

On `feat/policy-pdp`, the existing PDP was preserved and PostgreSQL context,
provenance, audit storage and migrations were added. Existing tests were retained.

| Environment | Check | Result |
|---|---|---|
| Sandbox | Complete Python suite | **86 passed, 2 skipped** |
| Sandbox | Real CLI Rego policy suite | **14/14 passed** |
| Sandbox | Ruff lint | Passed |
| Sandbox | Ruff formatting | Passed, all 44 Python files |
| Sandbox | Contract schema validation | Passed, all 10 schemas unchanged |
| Sandbox | `git diff --check` | Passed |
| Developer terminal, reported by project lead | Database suite, SQLite and real PostgreSQL | **56 passed** |
| Developer terminal, reported by project lead | Real OPA suite, including live HTTP authorization | **2 passed** |

The sandbox also evaluated database facts through actual `opa eval` for read
ALLOW, inherited confidential disclosure DENY and revocation DENY. SQLite
migration upgrade/downgrade/upgrade, PostgreSQL offline DDL, Compose configuration
and dependency checks passed. These are not live PostgreSQL or OPA HTTP results.

Subsequent developer-terminal verification supplied by the project lead:

- `AG_TEST_DATABASE_URL="$AG_DATABASE_URL" make test-db`: **56 passed**, exercising
  both isolated SQLite and real PostgreSQL, including migration round-trip.
- Real OPA tests: **2 passed** with the configured local OPA endpoint. The test
  file contains a CLI/Rego suite test and a live HTTP authorization test covering
  read ALLOW, confidential egress DENY and revocation DENY.
- PostgreSQL container healthy; migration and seed commands succeeded; the
  explicitly PostgreSQL-configured backend worker completed startup.

The sandbox's two live-service tests skipped because `AG_TEST_DATABASE_URL` and
`AG_TEST_OPA_URL` were not configured. It cannot open TCP sockets or access the
Docker daemon, and does not inherit the lead's shell exports. The reported live
checks were not rerun inside the sandbox. Psycopg and Ruff are now installed.
The four formerly unformatted files were cleaned up using Ruff only; their
syntax trees, including test assertions, were unchanged. Lint and formatting
now pass repository-wide. Remote CI has not been run.
See [database setup and limits](postgresql-context.md) for verification commands.
The historical bootstrap findings below describe an earlier environment, not
the current Git branch or installed tools. No credentials were overwritten.

## Historical bootstrap session

Scope: development scaffold only. Original research documents were preserved;
the MIT license was restored byte-for-byte from `origin/main`.

## Verified in this session

- Editable Python package installation from cached wheels.
- **18 Python tests passed**, covering health routes through in-process ASGI,
  CORS, absence of sensitive routes, always-DENY stubs, contract examples,
  identity-field rejection, and Salesforce JSON/XML structure.
- Ten generated JSON Schemas matched their Pydantic sources.
- `python -m pip check`: no broken requirements.
- Frontend file smoke tests passed using Node's test runner.
- Vite production bundling passed using cached React 19.2.8 and Vite 8.2.2.
  This checks transpilation/bundling, **not TypeScript type checking**.
- Python source compilation passed.
- A standard Python wheel built successfully (in addition to the editable install).
- Compose/CI YAML syntax and relative documentation links validated successfully.
- `.env` creation preserved existing configuration on repeated runs.

## Environment blockers

- Outbound DNS/network access is unavailable. GitHub, PyPI, and npm could not be
  reached. Cached dependencies enabled partial verification only.
- Ruff, TypeScript, ESLint, Prettier, and React Flow were not available in local
  caches. Their dependencies/configuration are declared, but full installation,
  linting, formatting, and type checking could not be verified.
- Creating an IPv4 socket raises `PermissionError: [Errno 1] Operation not
  permitted`. `make dev` cannot start live HTTP listeners in this session.
  In-process ASGI tests pass; live browser-to-backend startup remains unverified.
- Docker Compose is not installed; Docker daemon access is denied. Container
  builds and Compose startup have not been run.
- Salesforce CLI and an org are absent. Apex compilation/deployment and Agentforce
  configuration remain unverified.
- `.git` is mounted read-only. `git fetch origin` failed creating `FETCH_HEAD`;
  branch creation failed creating `index.lock`. No commit, push, or merge was made.
  The worktree remains on the unborn local `master`; recorded remote default is
  `main`, commit `52d999c`.

## Required follow-up on an unrestricted developer machine

1. Run `make setup`, then `make format` and `make check`.
2. Review/commit the generated npm lockfile and adopt `npm ci` in setup/CI/Docker.
3. Run `make dev` and `make smoke`; inspect the project shell in a browser.
4. Run `docker compose config --quiet` and optionally `docker compose up --build`.
5. Put the scaffold on the bootstrap branch in a writable checkout and have the
   four teammates review their interfaces. Salesforce org validation is separate.

The acceptance criteria requiring a fresh online install, complete lint/type
checks, and live service startup are not claimed as verified here.


## Full-project integration, 2026-10-14

Current validation is recorded in [integration provenance and verification](integration.md).
The integrated full suite ran with disposable real PostgreSQL 16 and OPA 1.6.0:
**282 passed with zero skips**, plus **14/14** real Rego tests. The direct gateway
HTTP-client/backend ASGI/live PostgreSQL/live OPA check also passed. Earlier
results above describe prior source milestones, not this integration session.
Both Docker images and the full Compose migration/seed/startup sequence passed,
including the dashboard proxy, MCP authentication denial and fail-closed OPA
outage. A missing installed-package graph fixture was fixed and revalidated.
