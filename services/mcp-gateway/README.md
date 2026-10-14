# MCP gateway and demonstration archive

`agentguard_gateway` is a fail-closed MCP gateway. Its `/mcp` transport is
registered and `/health` remains available. No transport caller authenticator is
configured in this repository, so every transport tool invocation deliberately
receives no `TrustedContext` and is denied before authorization or downstream
execution.

The gateway accepts an `AuthorizationClient` and an archive executor through
dependency injection for integration tests and a future authenticated deployment.
The application wires the existing `HTTPAuthorizationClient`, including
server-owned PDP credential/agent/adapter settings, and optionally selects a
downstream executor with `AG_ARCHIVE_MCP_URL`. It retains every PDP security check.
`McpArchiveForwarder` constructs its downstream client only after a valid,
matching `ALLOW`, discovers the allowlisted `archive_record` tool, and invokes it
once. It does not retry errors because execution may already have occurred.

`agentguard_archive_mcp` is a separate, stateless demonstration MCP server. Its
only tool, `archive_record`, validates a synthetic record identifier and returns
a deterministic result. It does not persist records, authenticate callers, or
provide production archiving. It must be deployed only behind an authenticated,
authorized gateway. For a local demonstration, run:

```bash
.venv/bin/python -m agentguard_archive_mcp
```

It listens on `127.0.0.1:8002` by default, exposing `/health` and `/mcp`. It
accepts only loopback values for `AG_ARCHIVE_HOST`; `AG_ARCHIVE_PORT` selects the
port. The demo has no Compose service or published container port. Do not bind
its ASGI factory to a public interface. Start the gateway separately with:

```bash
.venv/bin/python -m uvicorn agentguard_gateway.app:create_app --factory --host 127.0.0.1 --port 8001
```

For a future authenticated gateway deployment, set
`AG_ARCHIVE_MCP_URL=http://127.0.0.1:8002/mcp`. This setting creates only a lazy
Streamable HTTP downstream client factory; it does not enable forwarding. Until
real credential extraction and a `CallerAuthenticator` implementation are
provided, `/mcp` continues to deny every tool call.
The loopback example assumes native processes on one host. In Compose,
`127.0.0.1` refers to the gateway container itself; an approved downstream must
be reachable from that container. Compose passes the optional URL only when set
and does not provision or expose the unauthenticated demo archive service.

Run the local MCP tests with:

```bash
.venv/bin/python -m pytest services/mcp-gateway/tests -q
```

## Identity integration required from the lead

The `CallerAuthenticator` protocol is the authentication boundary. A production
implementation must validate the transport credential and derive
`TrustedContext` solely from verified, server-owned data; tool arguments,
headers other than the credential, and caller JSON must not establish identity.

The gateway also provides an injectable `McpCallerAuthentication` resource-server
boundary for the pinned MCP SDK. A deployment supplies the SDK `TokenVerifier`,
approved OAuth resource-server settings, and a server-owned mapper from the
SDK-verified access token to `TrustedContext`. The SDK rejects missing, invalid,
expired, or insufficient-scope bearer tokens before MCP tool dispatch. The mapper
is still required to derive `agent_id` and `adapter_id` from server-owned bindings,
not from arbitrary token claims. This integration is deliberately not configured
from environment variables: until the deployment supplies those reviewed pieces,
the default transport remains deny-all.

Before implementing it, the lead must provide:

- identity-provider issuer URL and the exact token-validation mechanism (JWKS
  endpoint/key rotation or introspection endpoint), with TLS trust requirements;
- expected OAuth audience/resource indicator, accepted signing algorithms, and
  clock-skew/session-revocation policy;
- required scopes/claims and a server-owned mapping from verified subject,
  client/tenant, and credential type to `agent_id` and `adapter_id`;
- the policy authorization endpoint, its service authentication method, and the
  production downstream MCP endpoint plus its server-identity/TLS configuration.

The integrated HTTP PDP client validates request ID, canonical request digest,
expected policy version, the explicit ALLOW reason and current UTC issuance/expiry.
Digest and expiry travel in the established response headers; the JSON schemas
remain unchanged. Errors, malformed responses and mismatches never imply ALLOW.
See [the established protocol](../../docs/policy-pdp.md).
`TrustedContextResolver` revalidates only authenticator output and rejects missing,
malformed or unavailable authentication. The mounted transport passes no credential
and deliberately denies every execution request. The current Rego still denies
`archive.local_demo`; a separate archive service or configured URL does not grant it.

## Salesforce API Catalog and Agentforce prerequisites

This checkout has no Salesforce org configuration, connected app, Agentforce
adapter, or credentials. Do not register the local loopback demonstration server
with Salesforce. Before an org integration, deploy the gateway at a TLS-reachable
URL with a real caller authenticator and a configured downstream archive endpoint.

With an appropriately licensed org and a user granted the required agent-management
permissions, the integration owner must:

1. In Setup, open **API Catalog** and register the external gateway, or use
   **Agentforce Registry** to create the external MCP connection.
2. Configure OAuth 2.0 only with the issuer URL, scopes, client ID, client secret,
   audience, and validation rules approved for the deployed gateway. Do not select
   no-authentication for an operational gateway.
3. Review the discovered `archive_local_demonstration` tool name and description,
   allowlist only that tool, and review the catalog's tool-poisoning/risk findings.
4. Add the resulting action to the intended Agentforce agent, then test one
   unauthenticated/denied invocation and one authorized invocation against the
   deployed service. Verify the authorization audit and downstream result without
   exposing credentials in prompts, logs, or test fixtures.

Salesforce documents manual external-server registration and per-tool allowlisting
in its [API Catalog guide](https://help.salesforce.com/s/articleView?id=platform.api_catalog_view_manual_external_mcp_servers.htm&language=en_US&type=5)
and [Agentforce Registry guide](https://help.salesforce.com/s/articleView?id=ai.agent_mcp_connect_register.htm&language=en_US&type=5).
Those are external-org steps and have not been performed or verified here.
