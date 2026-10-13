"""Explicit development seeding from existing trusted context, without reading raw tokens."""

from sqlalchemy import func, select
from sqlalchemy.orm import sessionmaker

from agentguard_backend.db.models import (
    ApprovedDestination,
    Permission,
    Principal,
    PrincipalBinding,
    Resource,
    utc_now,
)
from agentguard_backend.db.provenance import InconsistentProvenance, create_report
from agentguard_backend.pdp.context import EMAIL
from agentguard_backend.pdp.models import ContextDocument


def seed_context(sessions: sessionmaker, document: ContextDocument) -> None:
    """Only seed an empty context store; all rows commit or roll back together."""
    with sessions.begin() as session:
        if any(
            session.scalar(select(func.count()).select_from(model))
            for model in (Principal, PrincipalBinding, Resource, Permission, ApprovedDestination)
        ):
            raise ValueError("Existing database context preserved; seed requires an empty store")
        identity_ids = {binding.agent_id for binding in document.identities}
        owner_ids = identity_ids | {resource.owner_agent_id for resource in document.resources}
        session.add_all(
            [
                Principal(
                    id=identifier, status="ACTIVE" if identifier in identity_ids else "INACTIVE"
                )
                for identifier in sorted(owner_ids)
            ]
        )
        session.flush()
        for binding in document.identities:
            session.add(
                PrincipalBinding(
                    principal_id=binding.agent_id,
                    adapter_id=binding.adapter_id,
                    surface=binding.surface,
                    status=binding.status,
                    credential_sha256=binding.credential_sha256,
                    verified_at=utc_now(),
                )
            )
        for resource in document.resources:
            if not resource.provenance_refs:
                if resource.type == "report":
                    raise InconsistentProvenance("Reports require a trusted source")
                session.add(
                    Resource(
                        id=resource.id,
                        type=resource.type,
                        owner_principal_id=resource.owner_agent_id,
                        classification=resource.classification,
                        origin="SOURCE",
                        verified_at=utc_now(),
                    )
                )
        session.flush()
        pending = [resource for resource in document.resources if resource.provenance_refs]
        known = {resource.id for resource in document.resources if not resource.provenance_refs}
        while pending:
            ready = [resource for resource in pending if set(resource.provenance_refs) <= known]
            if not ready:
                raise InconsistentProvenance("Unresolved or cyclic seed provenance")
            for resource in ready:
                if resource.type != "report":
                    raise InconsistentProvenance(
                        "Only derived reports are seeded in this iteration"
                    )
                create_report(
                    session,
                    resource.id,
                    resource.owner_agent_id,
                    resource.provenance_refs,
                    resource.classification,
                )
                known.add(resource.id)
                pending.remove(resource)
        for binding in document.identities:
            for grant in binding.permissions:
                session.add(
                    Permission(
                        principal_id=binding.agent_id,
                        action=grant.action,
                        resource_id=grant.resource_id,
                        status=grant.status,
                    )
                )
        session.add_all(
            [
                ApprovedDestination(address=address.lower(), active=True)
                for address in sorted(set(document.approved_destinations))
                if EMAIL.fullmatch(address)
            ]
        )
