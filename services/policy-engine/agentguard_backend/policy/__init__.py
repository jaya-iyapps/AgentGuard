"""Teammate 1 owns deterministic policy implementation behind PolicyEvaluator."""

from datetime import datetime, timezone
from typing import Protocol
from uuid import uuid4

from agentguard_contracts import AuthorizationRequest, PolicyDecision, TrustedContext


class PolicyEvaluator(Protocol):
    def evaluate(self, request: AuthorizationRequest, trusted: TrustedContext) -> PolicyDecision:
        """Evaluate verified facts; never trust asserted identity or labels."""
        ...


class DenyAllPolicy:
    """Explicit placeholder, not a policy engine. It can never grant permission."""

    def evaluate(self, request: AuthorizationRequest, trusted: TrustedContext) -> PolicyDecision:
        return PolicyDecision(
            decision_id=str(uuid4()),
            request_id=request.request_id,
            decision="DENY",
            reason_code="NOT_IMPLEMENTED",
            explanation="Authorization is not implemented in the development scaffold.",
            policy_version="scaffold-deny-all",
            timestamp=datetime.now(timezone.utc),
        )
