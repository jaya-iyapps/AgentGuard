# Shared contracts v1

The `agentguard_contracts` Python package is the source of truth for authorization,
capability, and graph models. Generated JSON Schema files live in `schemas/`.
Run `make contracts` after intentionally changing models; `make contracts-check`
detects stale artifacts. Examples in `demo/fixtures/contracts.json` are validated
by tests. These are interface examples, not evidence of enforcement.

All models reject extra properties. `AuthorizationRequest` contains caller
assertions. `TrustedContext` is a separate adapter-owned input, deliberately absent
from request JSON. The scaffold does not authenticate callers, resolve provenance,
or execute sensitive operations. See `docs/api-contracts.md` before implementing.
