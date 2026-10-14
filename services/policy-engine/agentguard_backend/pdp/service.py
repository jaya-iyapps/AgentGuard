"""Coordinate trusted resolution and OPA; never execute an agent action."""

import logging
from datetime import datetime, timezone
from uuid import uuid4

from agentguard_contracts import AuthorizationRequest, AuthorizationResponse, PolicyDecision
from agentguard_contracts.canonical import request_digest

from agentguard_backend.pdp.audit import AuditUnavailable, DecisionAuditWriter
from agentguard_backend.pdp.context import ContextUnavailable, TrustedContextResolver
from agentguard_backend.pdp.models import DecisionBinding, PolicyInput
from agentguard_backend.pdp.opa import (
    InvalidOPADecision,
    OPAUnavailable,
    PolicyClient,
    validate_result,
)

log = logging.getLogger("agentguard.pdp")


class DecisionService:
    def __init__(
        self,
        resolver: TrustedContextResolver,
        opa: PolicyClient,
        policy_version: str,
        audit: DecisionAuditWriter | None = None,
    ):
        self.resolver = resolver
        self.opa = opa
        self.policy_version = policy_version
        self.audit = audit

    async def authorize(
        self, request: AuthorizationRequest, authorization: str | None
    ) -> AuthorizationResponse:
        outcome = "DENY"
        facts = None
        try:
            facts = self.resolver.resolve(authorization, request)
            if not facts.identity.verified:
                reason = "CG-IDENTITY-UNVERIFIED"
                explanation = "A verified adapter credential is required."
            else:
                document = PolicyInput(
                    request=DecisionBinding(
                        request_id=request.request_id,
                        session_id=request.session_id,
                        action=request.action,
                        resource_id=request.resource.id,
                        resource_type=request.resource.type,
                        destination_present=request.destination is not None,
                        request_digest=request_digest(request),
                    ),
                    facts=facts,
                )
                result = await self.opa.evaluate(document)
                validate_result(result, document, self.policy_version)
                outcome = result.decision
                reason, explanation = result.reason_code, result.explanation
        except ContextUnavailable:
            reason, explanation = "CG-CONTEXT-UNAVAILABLE", "Trusted context cannot be resolved."
        except OPAUnavailable:
            reason, explanation = "CG-OPA-UNAVAILABLE", "Policy evaluation is unavailable."
        except InvalidOPADecision:
            reason = "CG-OPA-INVALID"
            explanation = "Policy evaluation returned an invalid decision."
        decision = PolicyDecision(
            decision_id=str(uuid4()),
            request_id=request.request_id,
            decision=outcome,
            reason_code=reason,
            explanation=explanation,
            policy_version=self.policy_version,
            timestamp=datetime.now(timezone.utc),
        )
        if self.audit is not None:
            try:
                self.audit.record(request, decision, facts)
            except AuditUnavailable:
                # A failed audit must never let an otherwise valid ALLOW escape.
                decision = decision.model_copy(
                    update={
                        "decision": "DENY",
                        "reason_code": "CG-AUDIT-UNAVAILABLE",
                        "explanation": "Authorization audit persistence is unavailable.",
                    }
                )
                reason = decision.reason_code
        log.info(
            "decision_id=%s decision=%s reason=%s", decision.decision_id, decision.decision, reason
        )
        return AuthorizationResponse(policy_decision=decision)
