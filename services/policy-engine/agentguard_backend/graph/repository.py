"""Bounded, read-only SQL snapshots. Authentication and facts share one transaction."""

from dataclasses import dataclass
from hashlib import sha256

from sqlalchemy import exists, or_, select, text
from sqlalchemy.orm import Session

from agentguard_backend.db.models import (
    AuthorizationAudit,
    GraphDestination,
    Permission,
    Principal,
    PrincipalBinding,
    ProvenanceEdge,
    Resource,
    Revocation,
    ToolDataFlow,
)
from agentguard_backend.graph.models import GraphIssue, GraphLimits
from agentguard_backend.pdp.context import BEARER


class GraphAccessDenied(Exception):
    def __init__(self, status_code: int = 401):
        self.status_code = status_code


class GraphUnavailable(Exception):
    """No trustworthy graph can be returned; never expose driver details/credentials."""


@dataclass
class GraphSnapshot:
    principal: Principal
    binding: PrincipalBinding
    resources: list[Resource]
    permissions: list[tuple[Permission, bool]]
    provenance: list[ProvenanceEdge]
    flows: list[ToolDataFlow]
    destinations: list[GraphDestination]
    audits: list[AuthorizationAudit]
    issues: list[GraphIssue]


def authenticate(
    session: Session, authorization: str | None, agent_id: str | None
) -> tuple[Principal, PrincipalBinding]:
    match = BEARER.fullmatch(authorization or "")
    if not match:
        raise GraphAccessDenied()
    binding = session.scalar(
        select(PrincipalBinding).where(
            PrincipalBinding.credential_sha256 == sha256(match.group(1).encode()).hexdigest()
        )
    )
    if binding is None or binding.verified_at is None or binding.status != "ACTIVE":
        raise GraphAccessDenied()
    principal = session.get(Principal, binding.principal_id)
    if principal is None or principal.status != "ACTIVE":
        raise GraphAccessDenied()
    revoked = session.scalar(
        select(
            exists().where(
                or_(Revocation.principal_id == principal.id, Revocation.binding_id == binding.id)
            )
        )
    )
    if revoked:
        raise GraphAccessDenied()
    if agent_id is not None and agent_id != principal.id:
        raise GraphAccessDenied(403)
    return principal, binding


def load_snapshot(
    session: Session, authorization: str | None, agent_id: str | None, limits: GraphLimits
) -> GraphSnapshot:
    if session.bind.dialect.name == "postgresql":
        session.execute(text("SET TRANSACTION READ ONLY"))
    principal, binding = authenticate(session, authorization, agent_id)
    issues: list[GraphIssue] = []

    def bounded(statement, count: int, label: str):
        rows = list(session.scalars(statement.limit(count + 1)))
        if len(rows) > count:
            issues.append(
                GraphIssue(
                    code="SNAPSHOT_LIMIT",
                    record_ids=[label],
                    explanation="The database snapshot was bounded; omitted facts are unknown.",
                )
            )
        return rows[:count]

    resources = bounded(
        select(Resource).where(Resource.owner_principal_id == principal.id).order_by(Resource.id),
        limits.max_nodes,
        "resources",
    )
    resource_ids = [row.id for row in resources]
    permission_rows = list(
        session.execute(
            select(
                Permission,
                exists().where(Revocation.permission_id == Permission.id).label("revoked"),
            )
            .where(Permission.principal_id == principal.id)
            .order_by(Permission.action, Permission.resource_id, Permission.id)
            .limit(limits.max_nodes + 1)
        )
    )
    if len(permission_rows) > limits.max_nodes:
        issues.append(
            GraphIssue(
                code="SNAPSHOT_LIMIT",
                record_ids=["permissions"],
                explanation="Permission snapshot exceeded its bound.",
            )
        )
    permissions = [(row[0], row[1]) for row in permission_rows[: limits.max_nodes]]
    permission_ids = [row.id for row, _ in permissions]
    provenance = bounded(
        select(ProvenanceEdge)
        .where(ProvenanceEdge.child_id.in_(resource_ids))
        .order_by(ProvenanceEdge.child_id, ProvenanceEdge.parent_id),
        limits.max_edges,
        "provenance",
    )
    flows = bounded(
        select(ToolDataFlow)
        .where(ToolDataFlow.permission_id.in_(permission_ids))
        .order_by(ToolDataFlow.id),
        limits.max_edges,
        "flows",
    )
    destination_ids = sorted(
        {row.destination_id for row in flows if row.destination_id is not None}
    )
    destinations = bounded(
        select(GraphDestination)
        .where(GraphDestination.id.in_(destination_ids))
        .order_by(GraphDestination.id),
        limits.max_nodes,
        "destinations",
    )
    audits = bounded(
        select(AuthorizationAudit)
        .where(AuthorizationAudit.principal_id == principal.id)
        .order_by(AuthorizationAudit.timestamp.desc(), AuthorizationAudit.decision_id)
        .limit(51),
        50,
        "audit_history",
    )
    return GraphSnapshot(
        principal, binding, resources, permissions, provenance, flows, destinations, audits, issues
    )
