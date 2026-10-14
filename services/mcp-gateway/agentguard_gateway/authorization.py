"""HTTP PDP client; validate the complete decision protocol before returning ALLOW.

The credential and its agent binding are gateway configuration, never tool input.
This client does not authenticate MCP callers. The transport stays disabled until
a CallerAuthenticator can construct verified TrustedContext for each caller.
"""

import re
from datetime import datetime, timedelta, timezone

import httpx
from agentguard_contracts import AuthorizationRequest, AuthorizationResponse, TrustedContext
from agentguard_contracts.canonical import request_digest

from agentguard_gateway.config import GatewaySettings


class AuthorizationRejected(Exception):
    """The PDP transport or its decision cannot safely authorize execution."""


class HTTPAuthorizationClient:
    def __init__(
        self, settings: GatewaySettings, *, transport: httpx.AsyncBaseTransport | None = None
    ):
        self.settings = settings
        self.transport = transport

    async def authorize(
        self, request: AuthorizationRequest, trusted: TrustedContext
    ) -> AuthorizationResponse:
        credential = self.settings.policy_credential.get_secret_value()
        if (
            not re.fullmatch(r"[A-Za-z0-9_-]{32,256}", credential)
            or not self.settings.policy_agent_id
            or not self.settings.policy_adapter_id
            or trusted.agent_id != self.settings.policy_agent_id
            or trusted.adapter_id != self.settings.policy_adapter_id
            or trusted.surface != "mcp"
        ):
            raise AuthorizationRejected(
                "A matching server-owned MCP credential binding is required"
            )

        # Snapshot the request before awaiting transport; bind the digest to what was sent.
        payload = AuthorizationRequest.model_validate(request.model_dump(mode="json"))
        expected_digest = request_digest(payload)
        try:
            async with httpx.AsyncClient(
                timeout=self.settings.policy_timeout_seconds,
                transport=self.transport,
                follow_redirects=False,
                trust_env=False,
            ) as client:
                response = await client.post(
                    str(self.settings.policy_url).rstrip("/") + "/v1/authorize",
                    json=payload.model_dump(mode="json"),
                    headers={"Authorization": f"Bearer {credential}"},
                )
            if response.status_code != 200:
                raise AuthorizationRejected("The PDP did not return a successful decision")
            result = AuthorizationResponse.model_validate(response.json())
            decision = result.policy_decision
            expiry = datetime.fromisoformat(response.headers["X-AgentGuard-Decision-Expires-At"])
            now = datetime.now(timezone.utc)
            if (
                decision.request_id != payload.request_id
                or response.headers.get("X-AgentGuard-Request-Digest") != expected_digest
                or decision.policy_version != self.settings.policy_version
                or decision.decision == "ALLOW"
                and decision.reason_code != "CG-ALLOW-001"
                or not decision.decision_id
                or decision.timestamp.tzinfo is None
                or expiry.tzinfo is None
                or decision.timestamp.utcoffset() != timedelta(0)
                or expiry.utcoffset() != timedelta(0)
                or not decision.timestamp <= now < expiry
                or not timedelta(0) < expiry - decision.timestamp <= timedelta(seconds=15)
            ):
                raise AuthorizationRejected("The PDP decision binding or freshness is invalid")
            return result
        except AuthorizationRejected:
            raise
        except (httpx.HTTPError, ValueError, KeyError, TypeError) as exc:
            # Do not include credentials, request contents, or response bodies in the error.
            raise AuthorizationRejected("The PDP decision is unavailable or invalid") from exc
