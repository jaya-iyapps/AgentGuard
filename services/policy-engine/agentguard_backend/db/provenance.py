"""Bounded lineage validation and classification inheritance, without NetworkX."""

from collections.abc import Callable, Mapping, Sequence

from sqlalchemy import select
from sqlalchemy.orm import Session

from agentguard_backend.db.models import ProvenanceEdge, Resource, utc_now

CLASSIFICATION_RANK = {"PUBLIC": 0, "INTERNAL": 1, "CONFIDENTIAL": 2, "RESTRICTED": 3}


class InconsistentProvenance(Exception):
    """A trusted lineage is missing, cyclic, unverifiable, or inconsistent."""


def trusted_lineage(session: Session, resource_id: str) -> tuple[Resource, str, list[str]]:
    return _validate_lineage(
        resource_id,
        lambda identifier: session.get(Resource, identifier),
        lambda identifier: list(
            session.scalars(
                select(ProvenanceEdge.parent_id).where(ProvenanceEdge.child_id == identifier)
            )
        ),
    )


def trusted_lineage_records(
    resource_id: str,
    resources: Mapping[str, Resource],
    parents: Mapping[str, Sequence[str]],
) -> tuple[Resource, str, list[str]]:
    """The same PDP validation over a bulk-loaded snapshot; no per-node SQL queries."""
    return _validate_lineage(
        resource_id, resources.get, lambda identifier: parents.get(identifier, ())
    )


def _validate_lineage(
    resource_id: str,
    resource_for: Callable[[str], Resource | None],
    parents_for: Callable[[str], Sequence[str]],
) -> tuple[Resource, str, list[str]]:
    visited: dict[str, str] = {}
    visiting: set[str] = set()
    ancestors: set[str] = set()
    target = resource_for(resource_id)
    if target is None:
        raise InconsistentProvenance("Resource does not exist")

    def visit(identifier: str, depth: int) -> str:
        if identifier in visiting or depth > 64 or len(visited) + len(visiting) >= 256:
            raise InconsistentProvenance("Cyclic or excessive lineage")
        if identifier in visited:
            return visited[identifier]
        resource = resource_for(identifier)
        if (
            resource is None
            or resource.verified_at is None
            or resource.owner_principal_id != target.owner_principal_id
            or resource.classification not in CLASSIFICATION_RANK
        ):
            raise InconsistentProvenance("Unverified or conflicting source")
        parents = parents_for(identifier)
        if (
            resource.origin not in {"SOURCE", "DERIVED"}
            or (resource.origin == "SOURCE" and parents)
            or (resource.origin == "DERIVED" and not parents)
            or (resource.type == "report" and resource.origin != "DERIVED")
        ):
            raise InconsistentProvenance("Source/derived origin does not match its lineage")
        visiting.add(identifier)
        labels = [resource.classification]
        for parent in parents:
            ancestors.add(parent)
            labels.append(visit(parent, depth + 1))
        visiting.remove(identifier)
        classification = max(labels, key=CLASSIFICATION_RANK.__getitem__)
        visited[identifier] = classification
        return classification

    classification = visit(resource_id, 0)
    return target, classification, sorted(ancestors)


def create_report(
    session: Session,
    identifier: str,
    owner_id: str,
    source_ids: list[str],
    classification_floor: str = "PUBLIC",
) -> Resource:
    """Trusted administrative/internal operation; no agent-facing ingestion endpoint exists."""
    if not source_ids or len(source_ids) != len(set(source_ids)):
        raise InconsistentProvenance("A report needs distinct trusted sources")
    if classification_floor not in CLASSIFICATION_RANK:
        raise InconsistentProvenance("Unknown classification floor")
    labels = [classification_floor]
    for source_id in source_ids:
        source, classification, _ = trusted_lineage(session, source_id)
        if source.owner_principal_id != owner_id:
            raise InconsistentProvenance("Cannot combine sources owned by another principal")
        labels.append(classification)
    report = Resource(
        id=identifier,
        type="report",
        owner_principal_id=owner_id,
        origin="DERIVED",
        classification=max(labels, key=CLASSIFICATION_RANK.__getitem__),
        verified_at=utc_now(),
    )
    session.add(report)
    session.flush()
    session.add_all(
        [ProvenanceEdge(parent_id=parent, child_id=identifier) for parent in source_ids]
    )
    session.flush()
    return report
