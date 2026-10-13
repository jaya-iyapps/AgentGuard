"""Resolve credentials and current trusted facts from an explicit server-owned file."""

import hashlib
import re
import secrets
from pathlib import Path
from typing import Protocol

from agentguard_contracts import AuthorizationRequest
from pydantic import ValidationError

from agentguard_backend.pdp.models import (
    ContextDocument,
    DestinationFacts,
    IdentityFacts,
    ResolvedFacts,
    ResourceFacts,
)

BEARER = re.compile(r"Bearer ([A-Za-z0-9_-]{32,256})", re.IGNORECASE)
EMAIL = re.compile(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@(?:[A-Za-z0-9-]+\.)+[A-Za-z0-9-]+")


class ContextUnavailable(Exception):
    """Trusted configuration is unavailable, invalid, or ambiguous."""


class TrustedContextResolver(Protocol):
    def resolve(self, authorization: str | None, request: AuthorizationRequest) -> ResolvedFacts:
        """Resolve identity and facts independently of all model-provided claims."""
        ...


class FileContextResolver:
    def __init__(self, path: str):
        self.path = Path(path) if path else None

    def resolve(self, authorization: str | None, request: AuthorizationRequest) -> ResolvedFacts:
        match = BEARER.fullmatch(authorization or "")
        if match is None:
            return ResolvedFacts()
        if self.path is None:
            raise ContextUnavailable("No trusted context source configured")
        try:
            # Reload each time: a permission revoked in the file affects the next request.
            document = ContextDocument.model_validate_json(self.path.read_text())
        except (OSError, UnicodeError, ValidationError) as exc:
            raise ContextUnavailable("Cannot resolve trusted context") from exc
        credential_hash = hashlib.sha256(match.group(1).encode()).hexdigest()
        identity = next(
            (
                item
                for item in document.identities
                if secrets.compare_digest(item.credential_sha256, credential_hash)
            ),
            None,
        )
        if identity is None:
            return ResolvedFacts()
        permission = next(
            (
                item
                for item in identity.permissions
                if item.action == request.action and item.resource_id == request.resource.id
            ),
            None,
        )
        resource = next(
            (item for item in document.resources if item.id == request.resource.id), None
        )
        destination = request.destination
        valid = destination is not None and EMAIL.fullmatch(destination) is not None
        approved = valid and destination.lower() in {
            item.lower() for item in document.approved_destinations if EMAIL.fullmatch(item)
        }
        return ResolvedFacts(
            identity=IdentityFacts(
                verified=True,
                agent_id=identity.agent_id,
                adapter_id=identity.adapter_id,
                surface=identity.surface,
                status=identity.status,
            ),
            permission_status=permission.status if permission else "MISSING",
            resource=(
                ResourceFacts(
                    verified=True,
                    type=resource.type,
                    classification=resource.classification,
                    owner_agent_id=resource.owner_agent_id,
                    provenance_refs=resource.provenance_refs,
                )
                if resource
                else ResourceFacts()
            ),
            destination=DestinationFacts(valid=valid, approved=approved),
        )
