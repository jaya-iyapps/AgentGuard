from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Protocol
from uuid import uuid4

from agentguard_contracts import (
    AuthorizationRequest,
    AuthorizationResponse,
    PolicyDecision,
    TrustedContext,
)
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.provider import AccessToken, TokenVerifier


class CallerAuthenticator(Protocol):
    async def authenticate(self, credential: str) -> TrustedContext:
        """Validate a transport credential and resolve only server-owned identity facts.

        Implementations must reject absent or invalid credentials and must not derive
        TrustedContext from caller-supplied JSON fields. The gateway intentionally has
        no implementation until the deployment supplies identity-provider validation
        and an agent-binding source.
        """
        ...


class TrustedContextProvider(Protocol):
    """Resolve trusted context without exposing a caller-controlled identity path."""

    async def resolve(self, credential: str | None) -> TrustedContext | None:
        """Return validated trusted context or ``None`` when authentication fails."""
        ...


class VerifiedAccessTokenMapper(Protocol):
    """Map an SDK-verified access token to server-owned AgentGuard identity.

    Implementations must not treat arbitrary token claims as an AgentGuard agent
    or adapter identifier. They must use a reviewed, server-owned binding source.
    """

    async def resolve(self, access_token: AccessToken) -> TrustedContext:
        """Return identity facts for an access token already verified by the SDK."""
        ...


@dataclass(frozen=True)
class McpCallerAuthentication:
    """Explicit verifier and server-owned identity mapping for MCP callers."""

    token_verifier: TokenVerifier
    trusted_context_mapper: VerifiedAccessTokenMapper
    required_scopes: tuple[str, ...] = ("archive.execute",)


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


@dataclass
class McpAccessTokenTrustedContextResolver:
    """Resolve context from the MCP SDK's already verified bearer-token context.

    Raw credentials are intentionally unavailable at this boundary. The SDK
    authentication middleware verifies the bearer token before MCP dispatch; this
    resolver then asks a server-owned mapper for AgentGuard identity facts and
    revalidates the returned contract model. Any absent/malformed context or
    mapper error is a denial.
    """

    trusted_context_mapper: VerifiedAccessTokenMapper
    access_token_supplier: Callable[[], AccessToken | None] = get_access_token

    async def resolve(self, credential: str | None) -> TrustedContext | None:
        # This resolver is for the MCP middleware path only. A raw credential
        # supplied by a handler caller must never bypass that verified context.
        if credential is not None:
            return None

        try:
            access_token = self.access_token_supplier()
            if not isinstance(access_token, AccessToken):
                return None
            raw_context = await self.trusted_context_mapper.resolve(access_token)
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
