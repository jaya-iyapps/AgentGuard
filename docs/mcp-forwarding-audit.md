# MCP forwarding audit and merge

This review covers `4c4ecc9...origin/feat/mcp-forwarding`, containing teammate
commit `0769c5dd2769372635c30cbe4e30960a83e10d55`. The integration branch started
at `eb572856b54246cbc6615e9495332875f68b6d26`, verified against GitHub. The merge
base was `4c4ecc9`; the branches had seven integration-side commits and one
forwarding-side commit. The original working tree was clean.

The local recovery tag `recovery/full-project-integration-before-mcp-0769c5d`
retains `eb57285`. The merge is a normal two-parent merge with no resets, rebases,
force pushes or shared-branch updates.

## Audit of every incoming file

Paths below are relative to `services/mcp-gateway/` except the two root files.

| File | Classification | Resolution |
|---|---|---|
| Root `README.md` | Optional; conflicting descriptions | Keep the integrated MCP endpoint and HTTP-client description; add the archive package and current audit/setup links. Reject the redundant gateway-table rewrite and disabled-client description. |
| Root `pyproject.toml` | Necessary | Add `agentguard_archive_mcp*` to discovery; preserve all existing packages, dependency pins and PostgreSQL extra. The teammate's commit did not delete backend dependencies; their branch simply predates those integration changes. |
| `README.md` | Optional setup guide; potentially regressive protocol claim | Keep archive/identity guidance, add Linux commands, and correct the false assertion that digest, expiry and policy-version checks do not exist. Org-specific guidance remains unverified. |
| `agentguard_archive_mcp/__init__.py` | Necessary | Preserve the separate package export. |
| `agentguard_archive_mcp/__main__.py` | Necessary | Preserve the standalone CLI; validated host configuration controls its listener. |
| `agentguard_archive_mcp/app.py` | Necessary | Preserve independent health/MCP mount and session-manager lifespan; never mount it into the public gateway. |
| `agentguard_archive_mcp/config.py` | Necessary security boundary | Preserve loopback-only host validation and bounded port settings. |
| `agentguard_archive_mcp/server.py` | Necessary | Preserve only `archive_record`, identifier validation and deterministic stateless demonstration output. No production archive or persistence is implied. |
| `agentguard_gateway/app.py` | Necessary endpoint wiring; conflicting and potentially regressive | Combine optional lazy archive executor selection with `HTTPAuthorizationClient(settings)`. Taking the teammate's factory wholesale would silently replace the integrated HTTP client with the disabled default. |
| `agentguard_gateway/config.py` | Necessary; conflicting | Add only the optional archive URL while preserving credential, agent/adapter binding, expected policy version and timeout fields. |
| `agentguard_gateway/interfaces.py` | Necessary authentication scaffold | Preserve the resolver's missing-credential/configuration denial, authenticator delegation, model revalidation and error denial. It provides no production authenticator. |
| `agentguard_gateway/mcp_server.py` | Necessary forwarding/handler code; optional wording | Preserve the lazy Streamable HTTP factory, fixed-tool allowlist, non-retry behavior and explicit authenticated-handler boundary. Transport still supplies no credential and denies execution. Updated demonstration wording is consistent with the stateless service. |
| `tests/test_archive_server.py` | Necessary | Preserve discovery, deterministic result, invalid identifier, health and non-loopback rejection tests. |
| `tests/test_gateway_scaffold.py` | Necessary | Preserve every security assertion and add endpoint-configured denial and authenticator-derived context tests. Description assertions track the updated demonstration wording. |
| `tests/test_interfaces.py` | Necessary | Preserve and extend disabled-client/default settings, missing credentials, malformed/unavailable authenticator and contract revalidation coverage. |
| `tests/test_mcp_forwarding.py` | Necessary | Preserve old cases and add the actual archive service, missing allowlisted-tool denial and downstream error non-retry cases. |

No backend, frontend, database, OPA policy or shared-contract implementation was
replaced. `authorization.py` and existing PDP security tests remain byte-identical
to the integration base. The merge conflicts were `README.md`, gateway `app.py`
and gateway `config.py`; dependency discovery merged without a conflict.

## Files outside the MCP directory

Only these files change relative to the integration base:

- `README.md`: preserve existing behavior descriptions and document the new package/audit.
- `pyproject.toml`: discover the new package without dropping backend dependencies.
- `.env.example`: a commented optional native archive URL, with no credential or enabled default.
- `docker-compose.yml`: optional gateway URL pass-through; an unset value stays absent
  from the container environment. No archive service, public port or volume change.
- This audit: record decisions, conflicts, validation and deployment limits.

Two incoming test files needed Ruff formatting. Their Python ASTs remain the same
as the normal merged versions before formatting; no security test was removed or
relaxed. The additional `tests/test_pdp_forwarding.py` verifies application wiring
and the combined authenticator, HTTP PDP client and real archive MCP service.
Invalid/missing identity, HTTP errors, request-ID/digest/version mismatches,
expired decisions and DENY never create the downstream client. An isolated mocked
valid ALLOW forwards once after the authenticator supplies the configured binding.

## Validation

- Independent MCP suite: **42 passed, 0 failed, 0 skipped**.
- Full suite with disposable PostgreSQL 16, OPA 1.6.0 CLI and live OPA HTTP:
  **307 passed, 0 failed, 0 skipped**.
- Real Rego suite: **14/14 passed**.
- Direct HTTP PDP client/backend/real PostgreSQL/live OPA integration and synthetic
  graph/revocation demonstration passed.
- Ruff lint/format, ten generated contract schemas and dependency consistency passed.
- Frontend ESLint, Prettier, tests, TypeScript and Vite production build passed.
- Compose configuration passed with the archive URL unset and explicitly set.
  The default Compose project exposes no archive service.
- Backend/gateway and dashboard images built successfully.
- Full Compose migrations, both seed commands, service health, dashboard proxy,
  authenticated PDP ALLOW, graph query, MCP authentication DENY and fail-closed
  OPA outage passed. Only the owned temporary project/volume was removed.
- The standalone archive CLI and configured lazy endpoint factory passed over
  real loopback TCP through an authenticator-derived context and mocked valid
  HTTP PDP decision; missing identity denied. The owned test process was stopped.

The first run of the added combined test failed because its test factory accessed
the MCP session manager before creating the Streamable HTTP app. Correcting that
SDK lifecycle order preserved every assertion; all subsequent suite checks passed.

The host uses Python 3.14.4 and Node 22.22.1; host npm 9.2.0 reports the existing
manifest's npm-version warning. The supported Node 22 image uses npm 10. Python
3.11, remote CI, actual Salesforce org behavior and Proxmox deployment are not
established by these local results. No existing database volume is reset by tests.

## Deployment status

The integrated application remains suitable for a private Proxmox development
deployment using [the existing startup commands](integration.md#proxmox-vm-startup).
The separate archive demo is loopback-only and is not automatically started by
Compose. Its `demo_archived` result validates the MCP path; it does not persist
or archive real records.

Actual gateway transport execution remains denied until a real credential
extractor/authenticator is implemented. The existing Rego still denies
`archive.local_demo`. Adding a downstream URL or a standalone service does not
grant permission. Production caller identity, reviewed action policy, downstream
authentication, deployment/TLS and execution-time freshness/idempotency must be
completed before protected production forwarding is enabled.
