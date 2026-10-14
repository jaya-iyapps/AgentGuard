"""Deterministic NetworkX MultiDiGraph projection, never an authorization engine."""

import json
from collections import defaultdict
from hashlib import sha256

import networkx as nx
from agentguard_contracts import AgentCapabilities, CapabilityGraph, GraphEdge, GraphNode

from agentguard_backend.db.provenance import InconsistentProvenance, trusted_lineage_records
from agentguard_backend.graph.models import (
    EdgeMetadata,
    GraphIssue,
    GraphLimits,
    GraphProjection,
    NodeMetadata,
    PermissionSummary,
    PolicyDecisionEvidence,
    ToolFlowEvidence,
)
from agentguard_backend.graph.repository import GraphSnapshot


def stable_id(kind: str, *parts: str) -> str:
    """Logical IDs survive repeated queries and permission-row replacement."""
    digest = sha256(
        json.dumps(parts, ensure_ascii=True, separators=(",", ":")).encode()
    ).hexdigest()
    return f"{kind}:{digest[:32]}"


class NetworkXGraphBuilder:
    """A GraphBuilder-compatible implementation over a trusted, authenticated snapshot.

    AgentCapabilities' unpaired lists are selectors/summary ONLY. They cannot
    grant permission or connect any action to any resource.
    """

    def __init__(self, snapshot: GraphSnapshot, limits: GraphLimits | None = None):
        self.snapshot = snapshot
        self.limits = limits or GraphLimits()
        self.network: nx.MultiDiGraph = nx.MultiDiGraph(semantics="potential_capabilities")
        self.node_metadata: dict[str, NodeMetadata] = {}
        self.edge_metadata: dict[str, EdgeMetadata] = {}
        self.issues: dict[tuple, GraphIssue] = {}
        self.truncated = False

    def build(self, capabilities: list[AgentCapabilities]) -> CapabilityGraph:
        if any(row.agent_id != self.snapshot.principal.id for row in capabilities):
            raise ValueError("A snapshot cannot project another agent's capabilities")
        return self.project().graph

    def issue(self, code: str, ids: list[str], explanation: str) -> None:
        key = (code, tuple(sorted(ids)))
        if len(self.issues) < 100 or key in self.issues:
            self.issues[key] = GraphIssue(
                code=code, record_ids=sorted(ids), explanation=explanation
            )
        else:
            self.issues[("ISSUE_LIMIT", ())] = GraphIssue(
                code="ISSUE_LIMIT", explanation="Additional incomplete facts were omitted."
            )
            self.truncated = True
        if code.endswith("LIMIT"):
            self.truncated = True

    def add_node(self, node: GraphNode, metadata: NodeMetadata) -> bool:
        if node.id in self.network:
            return True
        if len(self.network) >= self.limits.max_nodes:
            self.issue("NODE_LIMIT", [], "Graph node bound reached; omitted facts are unknown.")
            return False
        self.network.add_node(node.id, contract=node)
        self.node_metadata[node.id] = metadata
        return True

    def add_edge(
        self, source: str, target: str, relationship: str, evidence: str, metadata: EdgeMetadata
    ) -> None:
        # NetworkX otherwise creates endpoint nodes implicitly. Never fabricate them.
        if source not in self.network or target not in self.network:
            self.issue(
                "MISSING_ENDPOINT",
                metadata.record_ids,
                "A relationship has an absent or bounded endpoint; no edge was fabricated.",
            )
            return
        identifier = stable_id("edge", source, target, relationship, evidence)
        if identifier in self.edge_metadata:
            previous = self.edge_metadata[identifier]
            for field in (
                "record_ids",
                "evidence_refs",
                "flow_ids",
                "assumptions",
                "permission_ids",
            ):
                setattr(
                    previous,
                    field,
                    sorted(set(getattr(previous, field) + getattr(metadata, field))),
                )
            if metadata.verification == "DECLARED":
                previous.verification = "DECLARED"
            previous.flow_evidence.update(metadata.flow_evidence)
            previous.flow_evidence = dict(sorted(previous.flow_evidence.items()))
            return
        if self.network.number_of_edges() >= self.limits.max_edges:
            self.issue("EDGE_LIMIT", [], "Graph edge bound reached; omitted paths are unknown.")
            return
        edge = GraphEdge(
            id=identifier,
            source=source,
            target=target,
            relationship=relationship,
            evidence=evidence,
        )
        self.network.add_edge(source, target, key=identifier, contract=edge)
        self.edge_metadata[identifier] = metadata

    def project(self) -> GraphProjection:
        # Reusable builder calls must not retain an earlier projection's transient state.
        self.network.clear()
        self.network.graph["semantics"] = "potential_capabilities"
        self.node_metadata.clear()
        self.edge_metadata.clear()
        self.issues.clear()
        self.truncated = False
        for issue in self.snapshot.issues:
            self.issue(issue.code, issue.record_ids, issue.explanation)
        agent = self.snapshot.principal.id
        agent_node = stable_id("agent", agent)
        self.add_node(
            GraphNode(id=agent_node, label=agent, kind="agent"),
            NodeMetadata(
                record_ids=[
                    f"pdp_principals:{agent}",
                    f"pdp_principal_bindings:{self.snapshot.binding.id}",
                ]
            ),
        )
        resources = {row.id: row for row in self.snapshot.resources}
        parents: dict[str, list[str]] = defaultdict(list)
        for edge in self.snapshot.provenance:
            parents[edge.child_id].append(edge.parent_id)
        for values in parents.values():
            values[:] = sorted(set(values))
        classifications: dict[str, str | None] = {}
        lineage_truncated = any(
            issue.code == "SNAPSHOT_LIMIT" and "provenance" in issue.record_ids
            for issue in self.snapshot.issues
        )
        for identifier, resource in sorted(resources.items()):
            try:
                if lineage_truncated:
                    raise InconsistentProvenance("Provenance snapshot is incomplete")
                _, classification, _ = trusted_lineage_records(identifier, resources, parents)
            except InconsistentProvenance:
                classification = None
                self.issue(
                    "INCONSISTENT_PROVENANCE",
                    [identifier],
                    "Classification is unknown: trusted lineage is missing, cyclic, excessive, unverified, or conflicting.",
                )
            classifications[identifier] = classification
            self.add_node(
                GraphNode(
                    id=stable_id("resource", identifier),
                    label=identifier,
                    kind="resource",
                    classification=classification,
                ),
                NodeMetadata(
                    record_ids=[f"pdp_resources:{identifier}"],
                    resource_id=identifier,
                    resource_type=resource.type,
                    resource_origin=resource.origin,
                    stored_classification=resource.classification,
                    classification_complete=classification is not None,
                ),
            )
        for row in sorted(self.snapshot.provenance, key=lambda row: (row.child_id, row.parent_id)):
            ref = f"pdp_provenance_edges:{row.child_id}->{row.parent_id}"
            if row.child_id not in resources or row.parent_id not in resources:
                self.issue(
                    "MISSING_PROVENANCE_FACT",
                    [ref],
                    "A parent is missing or outside this principal's trusted scope; no resource or edge was invented.",
                )
                continue
            self.add_edge(
                stable_id("resource", row.child_id),
                stable_id("resource", row.parent_id),
                "DERIVED_FROM",
                row.evidence,
                EdgeMetadata(
                    record_ids=[ref], evidence_refs=[row.evidence_ref] if row.evidence_ref else []
                ),
            )
        provenance_graph = nx.DiGraph()
        provenance_graph.add_edges_from(
            (u, v)
            for u, v, data in self.network.edges(data=True)
            if data["contract"].relationship == "DERIVED_FROM"
        )
        for component in sorted(
            (
                sorted(group)
                for group in nx.strongly_connected_components(provenance_graph)
                if len(group) > 1
            )
        ):
            self.issue(
                "PROVENANCE_CYCLE",
                component,
                "A strongly connected provenance component cannot ground a valid classification/path.",
            )

        flows_by_permission = defaultdict(list)
        for flow in self.snapshot.flows:
            flows_by_permission[flow.permission_id].append(flow)
        destinations = {row.id: row for row in self.snapshot.destinations}
        summaries = []
        effective_permissions = []
        for permission, revoked in sorted(
            self.snapshot.permissions,
            key=lambda pair: (pair[0].action, pair[0].resource_id, pair[0].id),
        ):
            status = "REVOKED" if revoked else permission.status
            summaries.append(
                PermissionSummary(
                    permission_id=permission.id,
                    action=permission.action,
                    resource_id=permission.resource_id,
                    status=status,
                )
            )
            if status != "ACTIVE":
                continue
            resource = resources.get(permission.resource_id)
            if (
                permission.principal_id != agent
                or resource is None
                or resource.owner_principal_id != agent
                or classifications.get(resource.id) is None
            ):
                self.issue(
                    "MISSING_PERMISSION_FACT",
                    [permission.id],
                    "An active permission lacks a consistent, verified resource in this principal's scope.",
                )
                continue
            action_node = stable_id("action", agent, permission.action, permission.resource_id)
            if not self.add_node(
                GraphNode(
                    id=action_node,
                    label=f"{permission.action} [{permission.resource_id}]",
                    kind="action",
                ),
                NodeMetadata(
                    record_ids=[f"pdp_permissions:{permission.id}"],
                    action=permission.action,
                    resource_scope=permission.resource_id,
                    permission_status="ACTIVE",
                ),
            ):
                continue
            self.add_edge(
                agent_node,
                action_node,
                "CAN_INVOKE",
                "declared",
                EdgeMetadata(
                    record_ids=[f"pdp_permissions:{permission.id}"],
                    permission_ids=[permission.id],
                    permission_status="ACTIVE",
                    revocation_status="NOT_REVOKED",
                ),
            )
            effective_permissions.append(permission)
            usable_flow = False
            for flow in sorted(flows_by_permission[permission.id], key=lambda row: row.id):
                if flow.status != "ACTIVE":
                    continue
                if (
                    flow.input_resource_id != permission.resource_id
                    or (flow.verification == "DECLARED" and not (flow.assumption or "").strip())
                    or (flow.verification == "VERIFIED" and flow.verified_at is None)
                    or flow.verification not in {"DECLARED", "VERIFIED"}
                    or not flow.evidence_ref.strip()
                ):
                    self.issue(
                        "INCONSISTENT_TOOL_FLOW",
                        [flow.id],
                        "The flow is not grounded in this exact permission/resource scope and a trusted declaration/verification.",
                    )
                    continue
                usable_flow = True
                metadata = EdgeMetadata(
                    record_ids=[
                        f"graph_tool_data_flows:{flow.id}",
                        f"pdp_permissions:{permission.id}",
                    ],
                    evidence_refs=[flow.evidence_ref],
                    flow_ids=[flow.id],
                    flow_evidence={
                        flow.id: ToolFlowEvidence(
                            record_id=f"graph_tool_data_flows:{flow.id}",
                            evidence_ref=flow.evidence_ref,
                            permission_id=permission.id,
                            verification=flow.verification,
                            assumption=flow.assumption.strip()
                            if flow.assumption and flow.assumption.strip()
                            else None,
                        )
                    },
                    assumptions=[flow.assumption.strip()]
                    if flow.assumption and flow.assumption.strip()
                    else [],
                    permission_ids=[permission.id],
                    permission_status="ACTIVE",
                    revocation_status="NOT_REVOKED",
                    verification=flow.verification,
                )
                self.add_edge(
                    action_node,
                    stable_id("resource", flow.input_resource_id),
                    "READS",
                    "declared",
                    metadata.model_copy(deep=True),
                )
                if flow.destination_id is None:
                    continue
                destination = destinations.get(flow.destination_id)
                if (
                    destination is None
                    or destination.verified_at is None
                    or destination.status != "ACTIVE"
                ):
                    self.issue(
                        "MISSING_DESTINATION_FACT",
                        [flow.id],
                        "The destination is missing, inactive, or unverified; no output edge was invented.",
                    )
                    continue
                destination_node = stable_id("destination", destination.id)
                self.add_node(
                    GraphNode(id=destination_node, label=destination.address, kind="destination"),
                    NodeMetadata(
                        record_ids=[f"graph_destinations:{destination.id}"],
                        destination_location=destination.location,
                    ),
                )
                if destination.location == "UNKNOWN":
                    self.issue(
                        "UNKNOWN_DESTINATION_LOCATION",
                        [destination.id],
                        "An unknown destination cannot be treated as internal or external.",
                    )
                self.add_edge(action_node, destination_node, "MAY_SEND_TO", "declared", metadata)
            if not usable_flow:
                self.issue(
                    "MISSING_TOOL_FLOW",
                    [permission.id],
                    "Permission alone does not establish which data a tool reads or where it can send it.",
                )

        nodes = sorted(
            (data["contract"] for _, data in self.network.nodes(data=True)),
            key=lambda node: node.id,
        )
        edges = sorted(
            (data["contract"] for _, _, data in self.network.edges(data=True)),
            key=lambda edge: edge.id,
        )
        return GraphProjection(
            graph=CapabilityGraph(nodes=nodes, edges=edges),
            capabilities=AgentCapabilities(
                agent_id=agent,
                actions=sorted({row.action for row in effective_permissions}),
                resource_ids=sorted({row.resource_id for row in effective_permissions}),
                status="ACTIVE",
            ),
            node_metadata=dict(sorted(self.node_metadata.items())),
            edge_metadata=dict(sorted(self.edge_metadata.items())),
            permissions=summaries,
            policy_decisions=[
                PolicyDecisionEvidence(
                    decision_id=row.decision_id,
                    request_id=row.request_id,
                    action=row.action,
                    resource_id=row.resource_id,
                    decision=row.decision,
                    reason_code=row.reason_code,
                    timestamp=row.timestamp,
                )
                for row in self.snapshot.audits
            ],
            incomplete=bool(self.issues),
            truncated=self.truncated,
            issues=[self.issues[key] for key in sorted(self.issues)],
        )
