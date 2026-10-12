# Bootstrap verification

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
