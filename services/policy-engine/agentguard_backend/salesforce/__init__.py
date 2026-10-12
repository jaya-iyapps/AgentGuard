"""Teammate 2's boundary for authenticated Salesforce execution context."""

from typing import Protocol

from agentguard_contracts import TrustedContext


class SalesforceIdentityResolver(Protocol):
    def resolve(self, authenticated_subject: str, org_id: str, execution_user_id: str) -> TrustedContext:
        """Resolve an authenticated adapter binding, never an LLM-supplied agent name."""
        ...
