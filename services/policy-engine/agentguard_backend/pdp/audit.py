"""Decision audit interface, independent of storage and public response contracts."""

from typing import Protocol

from agentguard_backend.pdp.models import ResolvedFacts
from agentguard_contracts import AuthorizationRequest, PolicyDecision


class AuditUnavailable(Exception):
    """An authorization attempt could not be durably recorded."""


class DecisionAuditWriter(Protocol):
    def record(
        self, request: AuthorizationRequest, decision: PolicyDecision, facts: ResolvedFacts | None
    ) -> None: ...
