# MCP gateway and demonstration archive

`agentguard_gateway` is a fail-closed MCP gateway. Its `/mcp` transport is
registered and `/health` remains available. No transport caller authenticator is
configured in this repository, so every transport tool invocation deliberately
receives no `TrustedContext` and is denied before authorization or downstream
execution.

The gateway accepts an `AuthorizationClient` and an archive executor through
dependency injection for integration tests and a future authenticated deployment.
`McpArchiveForwarder` constructs its downstream client only after a valid,
matching `ALLOW`, discovers the allowlisted `archive_record` tool, and invokes it
once. It does not retry errors because execution may already have occurred.

`agentguard_archive_mcp` is a separate, stateless demonstration MCP server. Its
only tool, `archive_record`, validates a synthetic record identifier and returns
a deterministic result. It does not persist records, authenticate callers, or
provide production archiving. It must be deployed only behind an authenticated,
authorized gateway. For a local demonstration, run:

```powershell
.\.venv\Scripts\python.exe -m agentguard_archive_mcp
```

It listens on `127.0.0.1:8002` by default, exposing `/health` and `/mcp`. It
accepts only loopback values for `AG_ARCHIVE_HOST`; change that or
`AG_ARCHIVE_PORT` before starting it. Start the gateway separately with:

```powershell
.\.venv\Scripts\python.exe -m uvicorn agentguard_gateway.app:create_app --factory --host 127.0.0.1 --port 8001
```

For a future authenticated gateway deployment, set
`AG_ARCHIVE_MCP_URL=http://127.0.0.1:8002/mcp`. This setting creates only a lazy
Streamable HTTP downstream client factory; it does not enable forwarding. Until
real credential extraction and a `CallerAuthenticator` implementation are
provided, `/mcp` continues to deny every tool call.

Run the local MCP tests with:

```powershell
.\.venv\Scripts\python.exe -m pytest services/mcp-gateway/tests -q
```

## Identity integration required from the lead

The `CallerAuthenticator` protocol is the authentication boundary. A production
implementation must validate the transport credential and derive
`TrustedContext` solely from verified, server-owned data; tool arguments,
headers other than the credential, and caller JSON must not establish identity.

Before implementing it, the lead must provide:

- identity-provider issuer URL and the exact token-validation mechanism (JWKS
  endpoint/key rotation or introspection endpoint), with TLS trust requirements;
- expected OAuth audience/resource indicator, accepted signing algorithms, and
  clock-skew/session-revocation policy;
- required scopes/claims and a server-owned mapping from verified subject,
  client/tenant, and credential type to `agent_id` and `adapter_id`;
- the policy authorization endpoint, its service authentication method, and the
  production downstream MCP endpoint plus its server-identity/TLS configuration.

The current authorization contract correlates only `request_id`. It has no
digest, action/resource binding, expiry, or policy-version validation field that
the gateway can enforce. Those are contract and policy decisions for the lead;
this service intentionally does not invent them.

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
