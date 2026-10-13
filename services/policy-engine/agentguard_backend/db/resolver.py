"""PostgreSQL implementation of the existing trusted-context resolver interface."""

import hashlib

from pydantic import ValidationError
from sqlalchemy import or_, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import sessionmaker

from agentguard_backend.db.models import (
    ApprovedDestination,
    Permission,
    Principal,
    PrincipalBinding,
    Resource,
    Revocation,
)
from agentguard_backend.db.provenance import InconsistentProvenance, trusted_lineage
from agentguard_backend.pdp.context import BEARER, EMAIL, ContextUnavailable
from agentguard_backend.pdp.models import (
    DestinationFacts,
    IdentityFacts,
    ResolvedFacts,
    ResourceFacts,
)
from agentguard_contracts import AuthorizationRequest


class PostgresContextResolver:
    def __init__(self, sessions: sessionmaker):
        self.sessions = sessions

    def resolve(self, authorization: str | None, request: AuthorizationRequest) -> ResolvedFacts:
        match = BEARER.fullmatch(authorization or "")
        if match is None:
            return ResolvedFacts()
        digest = hashlib.sha256(match.group(1).encode()).hexdigest()
        try:
            # A new session/transaction per call: no identity-map or permission cache survives.
            with self.sessions.begin() as session:
                binding = session.scalar(
                    select(PrincipalBinding).where(PrincipalBinding.credential_sha256 == digest)
                )
                if binding is None or binding.verified_at is None:
                    return ResolvedFacts()
                principal = session.get(Principal, binding.principal_id)
                if principal is None:
                    raise ContextUnavailable("Principal binding has no trusted principal")
                grant = session.scalar(
                    select(Permission).where(
                        Permission.principal_id == principal.id,
                        Permission.action == request.action,
                        Permission.resource_id == request.resource.id,
                    )
                )
                revocations = list(
                    session.scalars(
                        select(Revocation).where(
                            or_(
                                Revocation.principal_id == principal.id,
                                Revocation.binding_id == binding.id,
                                Revocation.permission_id == grant.id if grant else False,
                            )
                        )
                    )
                )
                identity_status = "ACTIVE"
                if (
                    principal.status == "REVOKED"
                    or binding.status == "REVOKED"
                    or any(row.principal_id or row.binding_id for row in revocations)
                ):
                    identity_status = "REVOKED"
                elif principal.status != "ACTIVE" or binding.status != "ACTIVE":
                    identity_status = "INACTIVE"
                permission_status = grant.status if grant else "MISSING"
                if grant and any(row.permission_id == grant.id for row in revocations):
                    permission_status = "REVOKED"
                resource = session.get(Resource, request.resource.id)
                if resource is None:
                    raise ContextUnavailable("Requested resource has no trusted database facts")
                resource, classification, ancestors = trusted_lineage(session, resource.id)
                resource_facts = ResourceFacts(
                    verified=True,
                    type=resource.type,
                    classification=classification,
                    owner_agent_id=resource.owner_principal_id,
                    provenance_refs=ancestors,
                )
                destination = request.destination
                valid = destination is not None and EMAIL.fullmatch(destination) is not None
                approved_record = (
                    session.get(ApprovedDestination, destination.lower()) if valid else None
                )
                approved = bool(approved_record and approved_record.active)
                return ResolvedFacts(
                    identity=IdentityFacts(
                        verified=True,
                        agent_id=principal.id,
                        adapter_id=binding.adapter_id,
                        surface=binding.surface,
                        status=identity_status,
                    ),
                    permission_status=permission_status,
                    resource=resource_facts,
                    destination=DestinationFacts(valid=valid, approved=approved),
                )
        except (SQLAlchemyError, ValidationError, InconsistentProvenance) as exc:
            raise ContextUnavailable(
                "Database trusted context is unavailable or inconsistent"
            ) from exc
