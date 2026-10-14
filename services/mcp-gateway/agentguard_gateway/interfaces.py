from dataclasses import dataclass
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
        """Validate a transport credential and resolve only server-owned identity facts.

        Implementations must reject absent or invalid credentials and must not derive
        TrustedContext from caller-supplied JSON fields. The gateway intentionally has
        no implementation until the deployment supplies identity-provider validation
        and an agent-binding source.
        """
        ...


@dataclass
class TrustedContextResolver:
    """Fail closed while converting a transport credential to trusted context.

    A transport adapter is responsible only for credential extraction. This
    resolver delegates verification and server-owned identity mapping to the
    configured authenticator, then re-validates the returned contract model.
    It intentionally returns ``None`` for missing configuration, missing
    credentials, malformed contexts, and authentication errors.
    """

    caller_authenticator: CallerAuthenticator | None = None

    async def resolve(self, credential: str | None) -> TrustedContext | None:
        if not credential or self.caller_authenticator is None:
            return None

        try:
            raw_context = await self.caller_authenticator.authenticate(credential)
            if isinstance(raw_context, TrustedContext):
                raw_context = raw_context.model_dump()
            return TrustedContext.model_validate(raw_context)
        except Exception:
            return None


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
