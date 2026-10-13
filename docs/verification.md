# Bootstrap verification

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
