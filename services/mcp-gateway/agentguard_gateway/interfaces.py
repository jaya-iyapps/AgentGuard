from datetime import datetime, timezone
from typing import Protocol
from uuid import uuid4

from agentguard_contracts import (
    AuthorizationRequest,
    AuthorizationResponse,
    PolicyDecision,
    TrustedContext,
)


class CallerAuthenticator(Protocol):
    async def authenticate(self, credential: str) -> TrustedContext:
        """Validate transport credentials and resolve their server-owned agent binding."""
        ...


class AuthorizationClient(Protocol):
    async def authorize(
        self, request: AuthorizationRequest, trusted: TrustedContext
    ) -> AuthorizationResponse:
        """Use the shared policy API. Errors must never imply ALLOW."""
        ...


class DisabledAuthorizationClient:
    async def authorize(
        self, request: AuthorizationRequest, trusted: TrustedContext
    ) -> AuthorizationResponse:
        return AuthorizationResponse(
            policy_decision=PolicyDecision(
                decision_id=str(uuid4()),
                request_id=request.request_id,
                decision="DENY",
                reason_code="NOT_IMPLEMENTED",
                explanation="MCP authorization and execution are disabled in this scaffold.",
                policy_version="scaffold-deny-all",
                timestamp=datetime.now(timezone.utc),
            )
        )
