# Contributing to AgentGuard

Start with `make setup`, `make check`, and `docs/team-roles.md`. This bootstrap is
a development foundation, not the final hackathon application.

## Branch and review workflow

Fetch and inspect the remote default branch; do not assume its name. This remote
currently records `origin/main`. Create feature branches from the reviewed
bootstrap branch once it is available. Suggested names:

- `feat/policy-engine`
- `feat/salesforce-agentforce`
- `feat/mcp-gateway`
- `feat/dashboard`
- `chore/project-bootstrap` for scaffold changes

Open small pull requests describing the problem, resulting behavior, and checks
run. The owner of each affected module reviews the PR; shared contract changes
require all affected consumers. Do not force-push shared branches or merge into
the default branch without the lead's agreement.

## Avoiding conflicts

Keep edits within your owned paths. Coordinate changes to root tooling and shared
contracts first. Do not reformat unrelated research documents or other modules.
Regenerate schemas instead of editing them. When lockfiles become available,
change dependencies through the package manager and keep the manifest and lock
in one PR; ask the lead to coordinate simultaneous dependency updates.

## Definition of Done

- Scope and implementation status are explicit; mocks are labeled.
- `make check` passes, or a concrete environment blocker is disclosed.
- Documented startup commands still work.
- Tests cover changed contracts and relevant failure cases.
- No credentials, local environments, customer data, or build output are staged.
- Shared schema/fixture changes are reviewed by affected owners.
- A reviewer can work on the module without reorganizing another teammate's code.

The DENY stubs are intentionally nonfunctional. Replacing them requires the
feature's real trust boundary and tests; never add a temporary default ALLOW.

## Code ownership recommendations

Use the path mapping in `docs/team-roles.md`. The lead owns `.github/`, root build
configuration, and shared development scripts. Once actual GitHub handles are
known, create CODEOWNERS with those identities and enable review requirements in
repository settings. No external repository settings are changed by this scaffold.
