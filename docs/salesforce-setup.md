# Salesforce workstream setup

Status: **source scaffold only; not compiled, deployed, or tested in an org**.
No Salesforce credentials are required for local Python/React development.

## Starter contents

`integrations/salesforce` is a Salesforce DX source project using API 66.0.
`AgentGuardScaffold` is a `with sharing` invocable that always returns DENY and
does no callouts, queries, or DML. It is deliberately not an authorization
adapter. Its Apex test is ready for org-side execution; Python CI validates only
JSON/XML and companion-file structure.

## Prerequisites for teammate 2

- Install Salesforce CLI (`sf`) using the official installation instructions.
- Obtain a development org supporting the configured API version and Apex.
- For future Agentforce work, confirm Agentforce/Service Cloud availability,
  licenses, an agent execution user, and permission to register custom actions.
- Confirm who can create Named Credentials, External Credentials, and associated
  permission sets. No credentials or agent activation are included here.

## Optional starter deployment

Run from `integrations/salesforce` after obtaining a suitable development org:

```bash
sf org login web --alias agentguard-dev
sf project deploy start --source-dir force-app --target-org agentguard-dev --test-level RunLocalTests
sf apex run test --class-names AgentGuardScaffoldTest --target-org agentguard-dev --result-format human --wait 10
```

These are manual future steps, not commands executed during bootstrap. Successful
deployment validates only the DENY-only starter. Do not register it as a working
security integration in a demo.

## Future adapter checklist

Agree on the shared request/response shape with teammate 1. Map an authenticated
integration credential to an agent, org, and execution-user binding server-side.
Take `UserInfo` context from trusted Apex execution, not action arguments.

Configure a Named Credential for a reachable HTTPS authorization endpoint and
an External Credential for the selected authentication mechanism. Grant only the
agent's permission set access to its external credential principal. Populate
secrets manually through supported org configuration; never commit tokens.
`localhost` on a developer laptop is not reachable from Salesforce.

When actual data operations are implemented, preserve sharing and explicit CRUD/
field-level security checks, make any necessary callout before the protected
side effect, and fail closed on errors. These controls are not implemented by
the stub's `with sharing` declaration alone.

Primary references:

- [Salesforce CLI](https://developer.salesforce.com/tools/salesforcecli)
- [Apex invocable Agentforce actions](https://developer.salesforce.com/docs/ai/agentforce/guide/agent-invocablemethod.html)
- [Named Credentials](https://developer.salesforce.com/docs/platform/named-credentials/guide/get-started.html)

Feature availability and command flags should be checked against the selected
org and installed CLI before implementation.
