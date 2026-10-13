"""Backend-private resolved facts. These models are never HTTP request bodies."""

from typing import Literal

from agentguard_contracts import Classification, Contract
from pydantic import Field, model_validator

Status = Literal["ACTIVE", "INACTIVE", "REVOKED"]


class PermissionBinding(Contract):
    action: str
    resource_id: str
    status: Status


class IdentityBinding(Contract):
    credential_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    agent_id: str = Field(min_length=1)
    adapter_id: str = Field(min_length=1)
    surface: Literal["mcp", "salesforce"]
    status: Status
    permissions: list[PermissionBinding]


class ResourceRecord(Contract):
    id: str
    type: str
    classification: Classification
    owner_agent_id: str
    provenance_refs: list[str] = Field(default_factory=list)


class ContextDocument(Contract):
    identities: list[IdentityBinding]
    resources: list[ResourceRecord]
    approved_destinations: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def reject_ambiguous_bindings(self) -> "ContextDocument":
        credentials = [identity.credential_sha256 for identity in self.identities]
        resources = [resource.id for resource in self.resources]
        if len(credentials) != len(set(credentials)) or len(resources) != len(set(resources)):
            raise ValueError("Duplicate identity credential or resource ID")
        for identity in self.identities:
            grants = [(grant.action, grant.resource_id) for grant in identity.permissions]
            if len(grants) != len(set(grants)):
                raise ValueError("Duplicate permission binding")
        return self


class IdentityFacts(Contract):
    verified: bool = False
    agent_id: str | None = None
    adapter_id: str | None = None
    surface: Literal["mcp", "salesforce"] | None = None
    status: Status | None = None


class ResourceFacts(Contract):
    verified: bool = False
    type: str | None = None
    classification: Classification | None = None
    owner_agent_id: str | None = None
    provenance_refs: list[str] = Field(default_factory=list)


class DestinationFacts(Contract):
    valid: bool = False
    approved: bool = False


class ResolvedFacts(Contract):
    identity: IdentityFacts = Field(default_factory=IdentityFacts)
    permission_status: Literal["ACTIVE", "INACTIVE", "REVOKED", "MISSING"] = "MISSING"
    resource: ResourceFacts = Field(default_factory=ResourceFacts)
    destination: DestinationFacts = Field(default_factory=DestinationFacts)


class DecisionBinding(Contract):
    request_id: str
    session_id: str
    action: str
    resource_id: str
    resource_type: str
    destination_present: bool
    request_digest: str


class PolicyInput(Contract):
    request: DecisionBinding
    facts: ResolvedFacts


class OPAResult(Contract):
    decision: Literal["ALLOW", "DENY"]
    reason_code: str = Field(min_length=1)
    explanation: str = Field(min_length=1)
    policy_version: str = Field(min_length=1)
    request_id: str
    action: str
    request_digest: str
