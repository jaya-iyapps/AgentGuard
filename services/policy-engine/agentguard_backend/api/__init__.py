"""Future API routers belong here; shared schemas have this stable import path."""

from agentguard_contracts import AuthorizationRequest, AuthorizationResponse, HealthResponse

__all__ = ["AuthorizationRequest", "AuthorizationResponse", "HealthResponse"]
