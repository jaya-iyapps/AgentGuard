"""Backend-owned analytical envelopes; shared graph/authorization contracts are unchanged."""

from datetime import datetime
from typing import Literal

from agentguard_contracts import AgentCapabilities, CapabilityGraph, Classification, Contract
from pydantic import Field


class GraphLimits(Contract):
    max_nodes: int = Field(default=512, ge=2, le=2000)
    max_edges: int = Field(default=1024, ge=1, le=5000)
    max_depth: int = Field(default=8, ge=1, le=32)
    max_findings: int = Field(default=25, ge=1, le=100)


class GraphIssue(Contract):
    code: str
    record_ids: list[str] = Field(default_factory=list)
    explanation: str


class NodeMetadata(Contract):
    record_ids: list[str]
    resource_id: str | None = None
    resource_type: str | None = None
    action: str | None = None
    resource_scope: str | None = None
    resource_origin: Literal["SOURCE", "DERIVED"] | None = None
    stored_classification: Classification | None = None
    classification_complete: bool = True
    destination_location: Literal["INTERNAL", "EXTERNAL", "UNKNOWN"] | None = None
    permission_status: str | None = None


class ToolFlowEvidence(Contract):
    record_id: str
    evidence_ref: str
    permission_id: str
    verification: Literal["DECLARED", "VERIFIED"]
    assumption: str | None = None


class EdgeMetadata(Contract):
    record_ids: list[str]
    evidence_refs: list[str] = Field(default_factory=list)
    flow_ids: list[str] = Field(default_factory=list)
    flow_evidence: dict[str, ToolFlowEvidence] = Field(default_factory=dict)
    assumptions: list[str] = Field(default_factory=list)
    permission_ids: list[str] = Field(default_factory=list)
    permission_status: str | None = None
    revocation_status: str | None = None
    verification: Literal["DECLARED", "VERIFIED"] | None = None


class PermissionSummary(Contract):
    permission_id: str
    action: str
    resource_id: str
    status: str


class PolicyDecisionEvidence(Contract):
    """An actual audit row is a decision, NEVER an execution event or graph edge."""

    decision_id: str
    request_id: str
    action: str
    resource_id: str
    decision: Literal["ALLOW", "DENY"]
    reason_code: str
    timestamp: datetime
    execution_outcome: Literal["NOT_RECORDED"] = "NOT_RECORDED"
    destination_correlation: Literal["NOT_RECORDED"] = "NOT_RECORDED"


class GraphProjection(Contract):
    graph: CapabilityGraph
    capabilities: AgentCapabilities
    node_metadata: dict[str, NodeMetadata]
    edge_metadata: dict[str, EdgeMetadata]
    permissions: list[PermissionSummary]
    policy_decisions: list[PolicyDecisionEvidence] = Field(default_factory=list)
    execution_evidence: Literal["NOT_RECORDED"] = "NOT_RECORDED"
    incomplete: bool
    truncated: bool
    issues: list[GraphIssue]


class ChainStep(Contract):
    edge_id: str
    source: str
    target: str
    relationship: Literal["CAN_INVOKE", "READS", "DERIVED_FROM", "MAY_SEND_TO"]
    evidence: Literal["declared", "observed"]
    traversal: Literal["FORWARD", "REVERSE"] = "FORWARD"


class CapabilityFinding(Contract):
    finding_id: str
    agent_id: str
    risk_category: Literal["POTENTIAL_CONFIDENTIAL_EXTERNAL_DISCLOSURE"] = (
        "POTENTIAL_CONFIDENTIAL_EXTERNAL_DISCLOSURE"
    )
    priority: Literal["HIGH"] = "HIGH"
    affected_resource: str
    sensitive_source: str
    effective_classification: Classification
    destination: str
    destination_id: str
    chain: list[ChainStep]
    capability_steps: list[ChainStep]
    node_ids: list[str]
    edge_ids: list[str]
    supporting_record_ids: list[str]
    evidence: list[Literal["declared", "observed"]]
    assumptions: list[str]
    missing_evidence: list[str]
    explanation: str
    potentially_reachable: Literal[True] = True
    reachability: Literal["ASSUMPTION_DEPENDENT", "VERIFIED_TOOL_CONTRACT"]
    execution_outcome: Literal["NOT_ESTABLISHED"] = "NOT_ESTABLISHED"


class RiskAnalysis(Contract):
    agent_id: str
    semantics: Literal["potential_capabilities"] = "potential_capabilities"
    findings: list[CapabilityFinding]
    incomplete: bool
    truncated: bool
    issues: list[GraphIssue]
    execution_evidence: Literal["NOT_RECORDED"] = "NOT_RECORDED"
