"""Persist only IDs, hashes, classifications and deterministic decision evidence."""

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import sessionmaker

from agentguard_backend.db.models import AuthorizationAudit
from agentguard_backend.pdp.audit import AuditUnavailable
from agentguard_backend.pdp.models import ResolvedFacts
from agentguard_backend.pdp.service import request_digest
from agentguard_contracts import AuthorizationRequest, PolicyDecision


class DatabaseAuditWriter:
    def __init__(self, sessions: sessionmaker):
        self.sessions = sessions

    def record(
        self, request: AuthorizationRequest, decision: PolicyDecision, facts: ResolvedFacts | None
    ) -> None:
        identity = facts.identity if facts else None
        resource = facts.resource if facts else None
        try:
            with self.sessions.begin() as session:
                session.add(
                    AuthorizationAudit(
                        decision_id=decision.decision_id,
                        request_id=request.request_id,
                        session_id=request.session_id,
                        principal_id=identity.agent_id if identity and identity.verified else None,
                        adapter_id=identity.adapter_id if identity and identity.verified else None,
                        action=request.action,
                        resource_id=request.resource.id,
                        request_digest=request_digest(request),
                        decision=decision.decision,
                        reason_code=decision.reason_code,
                        explanation=decision.explanation,
                        policy_version=decision.policy_version,
                        resource_classification=resource.classification if resource else None,
                        provenance_refs=resource.provenance_refs if resource else [],
                        permission_status=facts.permission_status if facts else None,
                        timestamp=decision.timestamp,
                    )
                )
        except SQLAlchemyError as exc:
            raise AuditUnavailable("Cannot persist authorization audit") from exc
