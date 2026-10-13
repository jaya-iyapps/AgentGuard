# Development environment

Follow the root README for `make setup` and `make dev`. Use Python 3.11–3.14 and
Node 22.12+. All commands assume the repository root unless stated otherwise.
No Salesforce credentials, Docker daemon, or database are necessary for native
development.
The optional persisted PDP requires separate [PostgreSQL setup](postgresql-context.md);
default file-backed tests remain independent of it.

## Configuration

`scripts/init_env.py` copies `.env.example` only when `.env` does not exist.
Pydantic Settings loads backend/gateway variables. Vite loads the same root file
for the development proxy. Unknown settings are ignored so services can share
one file. There are no default passwords, API keys, or production secrets.

| Variable | Purpose |
|---|---|
| `AG_ENV` | Descriptive environment label, development by default |
| `AG_SERVICE_NAME` | Backend health service name |
| `AG_CORS_ORIGINS` | Explicit comma-separated browser origin allowlist |
| `AG_POLICY_URL` | Future gateway authorization client URL |
| `AG_MCP_TRANSPORT` | Reserved transport choice; does not start MCP |
| `AG_BACKEND_URL` | Vite server-side proxy destination |

Do not set secret `VITE_*` values: Vite exposes those to browser code. Future
authentication requires a separate design, not adding a shared secret to the UI.

## Dependencies

Direct Python dependencies are pinned in `pyproject.toml`; JavaScript dependencies are
constrained in `apps/dashboard/package.json`. The initial session could not
access registries to produce a complete frontend lockfile. After a successful
online `npm install`, review and commit `apps/dashboard/package-lock.json` and
switch onboarding/CI/Docker to `npm ci`. Until then, installations resolve within
the declared ranges; this is not a fully locked dependency tree.

Do not commit virtual environments, caches, or `node_modules`. There is one root
Python editable install, not an independent virtual environment per module.

## Running individual workstreams

- Backend: `make backend`. Open `/docs` to inspect its current HTTP surface.
- Gateway: `make gateway`. Health only; no tools are registered.
- Frontend: `make frontend`. Backend offline is a supported starter UI state.
- Salesforce: read `docs/salesforce-setup.md`; never block other workstreams on an org.

## Container workflow

`docker compose up --build` builds Python and Node development images. Backend
and gateway share the Python image. The dashboard proxy uses Docker service DNS;
browsers still use `localhost:5173`. Health checks gate frontend startup on backend
readiness. Source is copied into images, so rebuild after edits.

## Checks

`make check` runs contract drift checks, lint/format checks, smoke tests, type checks,
and frontend build. `make smoke` checks actual running HTTP services. The
Salesforce metadata test checks file structure and XML only; it is not an Apex
compiler. CI repeats the Python checks on 3.11 and 3.14.
