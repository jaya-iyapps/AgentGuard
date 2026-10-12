"""Shared AgentGuard interfaces, without enforcement logic."""

from datetime import datetime
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class Contract(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Classification(StrEnum):
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    RESTRICTED = "RESTRICTED"


class ResourceReference(Contract):
    id: str = Field(min_length=1, max_length=160)
    type: str = Field(min_length=1, max_length=80)
    asserted_classification: Classification | None = None


class AuthorizationRequest(Contract):
    """Untrusted input. No authenticated principal can be supplied here."""

    request_id: str = Field(min_length=1, max_length=128)
    session_id: str = Field(min_length=1, max_length=128)
    action: str = Field(min_length=1, max_length=80)
    resource: ResourceReference
    destination: str | None = Field(default=None, max_length=254)
    provenance_refs: list[str] = Field(default_factory=list, max_length=20)
    context: dict[str, str] = Field(default_factory=dict)


class TrustedContext(Contract):
    """Future adapters construct this after authentication and server-side resolution."""

    agent_id: str = Field(min_length=1)
    adapter_id: str = Field(min_length=1)
    surface: Literal["mcp", "salesforce", "test"]
    resource_classification: Classification | None = None
    verified_provenance_refs: list[str] = Field(default_factory=list)


class PolicyDecision(Contract):
    decision_id: str
    request_id: str
    decision: Literal["ALLOW", "DENY"]
    reason_code: str
    explanation: str
    policy_version: str
    timestamp: datetime


class AuthorizationResponse(Contract):
    contract_version: Literal["1.0.0"] = "1.0.0"
    policy_decision: PolicyDecision


class AgentCapabilities(Contract):
    agent_id: str
    actions: list[str]
    resource_ids: list[str]
    status: Literal["ACTIVE", "REVOKED"]


class GraphNode(Contract):
    id: str
    label: str
    kind: Literal["agent", "action", "resource", "destination"]
    classification: Classification | None = None


class GraphEdge(Contract):
    id: str
    source: str
    target: str
    relationship: Literal["CAN_INVOKE", "READS", "DERIVED_FROM", "MAY_SEND_TO"]
    evidence: Literal["declared", "observed"]


class CapabilityGraph(Contract):
    nodes: list[GraphNode]
    edges: list[GraphEdge]
    semantics: Literal["potential_capabilities"] = "potential_capabilities"


class RuntimeEvent(Contract):
    event_id: str
    decision_id: str
    agent_id: str
    session_id: str
    action: str
    resource_id: str
    input_provenance: list[str]
    output_provenance: list[str]
    execution_outcome: Literal["SUCCEEDED", "FAILED", "BLOCKED"]
    timestamp: datetime


class HealthResponse(Contract):
    status: Literal["ok"] = "ok"
    service: str
    version: str = "0.1.0"
    mode: Literal["scaffold"] = "scaffold"
    enforcement_enabled: Literal[False] = False
