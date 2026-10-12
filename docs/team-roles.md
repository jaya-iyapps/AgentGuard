# Four independent workstreams

The lead owns root tooling, CI, dependency updates, and merge sequencing. Agree
on `docs/api-contracts.md` before parallel feature work. No teammate needs to
restructure the repository to start.

| Owner / branch | Owned paths | Inputs → outputs | First task |
|---|---|---|---|
| 1: Policy & security / `feat/policy-engine` | `services/policy-engine/` except `salesforce/`; contract coordination | Request + trusted facts → decision; declared capabilities → graph | Specify rule priority, trust resolution, and ledger interfaces in tests |
| 2: Salesforce / `feat/salesforce-agentforce` | `integrations/salesforce/`; backend `salesforce/` | Platform execution context + action arguments → normalized request; decision → guarded result | Validate org access and deploy/test the DENY-only starter |
| 3: MCP / `feat/mcp-gateway` | `services/mcp-gateway/` | Authenticated transport + tool arguments → request; response → future enforcement | Write authentication/client contract tests without invoking sensitive tools |
| 4: Frontend & integration / `feat/dashboard` | `apps/dashboard/`; future integration tests | Shared graph/decision schemas → UI; health → connection state | Plan typed clients and loading/error states using synthetic fixtures |

## Teammate 1

Own `PolicyEvaluator`, `GraphBuilder`, and future backend API routes. Separate
policy evaluation from graph facts and mutable state. Completion for the next
feature PR requires deterministic tests and explicit DENY behavior for unknown
input; implementation of that feature is outside this bootstrap.

## Teammate 2

Own `SalesforceIdentityResolver` and all org metadata. Expected adapter inputs
are authenticated platform context and validated action arguments. Never let
model-provided arguments override the agent identity. Record actual org/API
version and test results before claiming native integration works. No other
teammate should need Salesforce credentials.

## Teammate 3

Own `CallerAuthenticator` and `AuthorizationClient`. MCP SDK 1.x is constrained
for predictable transport APIs; choose and pin any version migration with the
lead. Implementation must eventually authorize before execution and fail closed
on dependency errors. Do not import the backend evaluator into the gateway.

## Teammate 4

React Flow is available as a declared dependency, but no graph component is built.
Keep policy logic out of browser code. Use the shared schemas to generate or
validate API types; do not independently redefine them. Coordinate cross-service
smoke tests and label synthetic versus observed data clearly.

## Shared-change protocol

1. Propose contract changes with example input/output before changing consumers.
2. Teammate 1 coordinates; every affected owner reviews.
3. Include models, fixtures, generated schemas, and validation changes together.
4. Avoid editing other owners' entry points; add local modules behind interfaces.
5. Each feature PR passes `make check` and states its implementation limits.

Do not use broad CODEOWNERS wildcards with fictional GitHub handles. The lead
should add actual usernames to `.github/CODEOWNERS` after confirming the roster.
