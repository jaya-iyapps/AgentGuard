# PostgreSQL trusted context and artifact provenance

The PDP can resolve trusted facts from PostgreSQL behind the existing
`TrustedContextResolver` interface. The `/v1/authorize` body, response models,
correlation headers, and Rego policies are unchanged. File-backed resolution
remains the default for isolated development. Neither resolver executes actions.

## Local setup

Requirements: root Python setup, PostgreSQL 16 (native or Docker), and the
Psycopg 3 extra. Run from the repository root:

```bash
make setup-python
.venv/bin/python -m pip install -e '.[dev,postgres]'
# Supply a new local password, or reuse the existing volume's password.
# Hidden interactive input avoids storing it in shell history.
read -r -s -p 'Local PostgreSQL password: ' AG_POSTGRES_PASSWORD
export AG_POSTGRES_PASSWORD
export AG_DATABASE_URL="postgresql+psycopg://agentguard:${AG_POSTGRES_PASSWORD}@127.0.0.1:5432/agentguard"
make db-up
```

Use a URL-safe password (for example, a password manager's random hex string),
or URL-encode its password component. The Compose `database` profile binds port
5432 to loopback and persists data in `pdp_postgres_data`. No default password or
trust authentication is supplied. Initialization refuses an empty password.
Changing an environment variable does not rotate a password in an existing
volume. Do not delete the volume to fix authentication errors.

Wait for `docker compose --profile database ps postgres` to report healthy, then:

```bash
make db-migrate
export AG_PDP_CONTEXT_PATH=.runtime/pdp-config/context.json
make db-seed
export AG_PDP_CONTEXT_BACKEND=postgres
# Separate terminal with the same configuration:
make opa
# Backend terminal:
make backend
```

Seeding reads only the existing server-owned synthetic context configuration and
credential **hashes**, never `.runtime/pdp-token`. It does not overwrite local
files and refuses an already populated context store. If no context configuration
exists, first use the existing `make pdp-init` initializer; it refuses to overwrite
existing credentials. Seeding is development-only, not a manifest importer or
production identity verification workflow.

For native PostgreSQL, explicitly provision a development database and role named
`agentguard`, set its password and URL, and skip `make db-up`. The migration role
needs schema/table/index creation privileges. Backend startup does not create
schemas or reset data automatically.

For a containerized backend, migrate and seed from the host as above, then change
the URL's hostname from `127.0.0.1` to `postgres` and run:

```bash
export AG_DATABASE_URL="postgresql+psycopg://agentguard:${AG_POSTGRES_PASSWORD}@postgres:5432/agentguard"
docker compose --profile database up --build
```

Use the host URL for native commands. Compose does not add a mandatory PostgreSQL
dependency to the default file-backed backend. If the opted-in database is
unavailable, authorization fails closed until ready. `/health` remains liveness,
not database/OPA readiness.

Keep persistent secrets only in the ignored `.env` or a secret manager. Do not
commit a database URL/password or expose either in `VITE_*`. Preserve existing
`.env` and `.runtime` files. Avoid `docker compose config` without `--quiet`:
rendered configuration contains environment secrets.

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `AG_PDP_CONTEXT_BACKEND` | `file` | `file` or `postgres`; database errors never fall back to file facts |
| `AG_DATABASE_URL` | empty | Explicit `postgresql+psycopg://...` URL; Settings uses `SecretStr` |
| `AG_DATABASE_TIMEOUT_SECONDS` | `3` | Connect, pool acquisition and statement timeout; integer 1–30 |
| `AG_POSTGRES_PASSWORD` | empty | Explicit Compose initialization password for the database profile |
| `AG_PDP_CONTEXT_PATH` | empty | File resolver configuration, or explicit development seed source |
| `AG_TEST_DATABASE_URL` | unset | Opt-in **disposable test database**; never a production URL |

OPA settings and response expiry remain in [policy-pdp.md](policy-pdp.md).

## Migration and ownership

Revision `0001_trusted_context` creates eight tables plus Alembic's version table:

| Table | Trusted facts / evidence |
|---|---|
| `pdp_principals` | Principal identifier and current state |
| `pdp_principal_bindings` | Unique credential SHA-256, adapter, surface, verification and state |
| `pdp_permissions` | Principal/action/resource scoped grant and current state |
| `pdp_resources` | Trusted owner, classification, verification, SOURCE/DERIVED origin |
| `pdp_provenance_edges` | Parent source → derived child relationships |
| `pdp_revocations` | Durable principal, binding or permission revocation (exactly one target) |
| `pdp_approved_destinations` | Explicit approved email addresses and active flag |
| `pdp_authorization_audits` | Decision IDs, request digest, resolved facts and ALLOW/DENY evidence |

Foreign keys, scoped uniqueness, checked states and non-self provenance edges
provide basic integrity. Verification timestamps assert administrator approval,
not identity-provider proof. Permissions are principal-scoped: verified bindings
for the same principal share them. Adapter-specific scopes and external org/user
verification remain future work.

`make db-migrate` applies upgrades. Downgrading to base **drops all eight tables
and their data**; round-trip tests do this only in isolated test stores. Back up
and review migrations before applying them to a shared database.

## Provenance and fresh resolution

The internal `create_report(session, id, owner_id, source_ids)` validates trusted
sources, inserts a report and edges in the caller's transaction, and stores the
highest source classification. No agent-facing ingestion endpoint exists.

```python
from agentguard_backend.db.provenance import create_report

with sessions.begin() as session:
    create_report(session, "report-1043", "support-agent", ["case-1042"])
```

`CONFIDENTIAL` Case → report remains `CONFIDENTIAL` even if a request asserts
`PUBLIC`. Every authorization also recomputes the highest current label across
all transitive ancestors. Source upgrades affect existing descendants on the
next request. Label order: PUBLIC < INTERNAL < CONFIDENTIAL < RESTRICTED.

Each call opens a fresh REPEATABLE READ transaction. No permission or identity
cache survives requests. A committed revocation overrides ACTIVE flags; changing
those flags does not undo a revocation row. No reinstatement workflow is
implemented; deleting revocation history is not an approved way to regrant access.

Missing resources, unverified sources, cycles, cross-owner ancestry, contradictory
SOURCE/DERIVED facts or excessive lineage (depth >64 / 256-node bound) fail closed.
Reports require trusted parents. Database/validation errors produce
`CG-CONTEXT-UNAVAILABLE`; if audit storage also fails, the final result is
`CG-AUDIT-UNAVAILABLE`. Missing identity never reaches OPA as an ALLOW candidate.
Request identity, classification and provenance assertions never become facts.

In PostgreSQL mode every validated authorization decision must be committed to
the audit store before ALLOW can leave the service. Audits record resolved
classification, provenance, permission status and canonical request digest, but
omit credentials, destinations, prompts and raw resource content. FastAPI
validation failures are not authorization decisions and are not recorded here.
Audit failure forces DENY and logs only decision ID/outcome/reason; a database
outage cannot produce durable evidence in that same database.

## Tests and validation status

```bash
make test-db
make test-pdp
make contracts-check
make opa-test
# Optional, with a running local OPA server:
AG_TEST_OPA_URL=http://127.0.0.1:8181 .venv/bin/python -m pytest services/policy-engine/tests/test_real_opa.py
# Optional, with a disposable test database and HOST URL:
AG_TEST_DATABASE_URL="$AG_DATABASE_URL" make test-db
```

Tests create UUID-named schemas and clean up only owned schemas. The test role
needs CREATE SCHEMA privileges. Default tests use isolated SQLite stores with
foreign keys enabled plus PostgreSQL-dialect offline migration compilation.
Real PostgreSQL tests explicitly skip without the opt-in URL. SQLite passing is
not PostgreSQL verification.

Where the OPA CLI exists, a database test evaluates unchanged real Rego through
`opa eval`: authorized read, inherited confidential egress DENY, and subsequent
revocation DENY. Its in-process transport is **not** a live OPA HTTP test. CI adds
a disposable PostgreSQL job with a generated ephemeral password; local results
do not imply remote CI passed.

The project lead subsequently ran the real services from the developer terminal:
database tests reported **56 passed**, including real PostgreSQL and migration
round-trip; OPA HTTP/CLI tests reported **2 passed**. The migrated, seeded
PostgreSQL-backed backend completed startup. These are developer-terminal results,
not sandbox execution or remote CI evidence. Psycopg and Ruff are now installed;
lint and formatting pass. See [verification details](verification.md) for the
environment-separated results. The sandbox itself still cannot open TCP sockets
or access Docker.

## Remaining security limits and next milestone

- Context reads and audit writes use separate transactions. They do not make
  authorization atomic with execution. Revocations after the read snapshot can
  race a decision; adapters still need correlation, expiry and guarded execution.
- Local database administration is trusted. No authenticated artifact writer,
  declassification workflow, immutable ledger, RLS or production identity provider
  exists. Adopt least-privilege runtime/admin roles and append-only audit and
  revocation privileges before shared deployment.
- Database owners can edit provenance and labels. Inheritance protects against
  untrusted request claims, not a compromised trusted database.
- Synchronous SQLAlchemy runs behind the existing synchronous resolver interface.
  Timeouts bound stalls; async/threadpool execution and query optimization should
  precede production load.

Next implement a **read-only NetworkX projection** of principal, permission,
resource and provenance tables with explicit edge types and revocation state.
Separate potential capability paths from stored derivation and authorization
attempts. A graph path or ALLOW decision is not proof of execution or leakage;
the deterministic PDP remains the authority.

References: [SQLAlchemy transactions](https://docs.sqlalchemy.org/en/20/orm/session_transaction.html),
[Alembic supplied connections](https://alembic.sqlalchemy.org/en/latest/cookbook.html#sharing-a-connection-across-one-or-more-programmatic-migration-commands),
[Psycopg installation](https://www.psycopg.org/psycopg3/docs/basic/install.html).
