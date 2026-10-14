"""Typed, bounded evidence walks; no unconstrained path enumeration or risk scores."""

from collections import deque

import networkx as nx

from agentguard_backend.db.provenance import CLASSIFICATION_RANK
from agentguard_backend.graph.models import (
    CapabilityFinding,
    ChainStep,
    GraphIssue,
    GraphLimits,
    GraphProjection,
    RiskAnalysis,
)
from agentguard_backend.graph.projector import stable_id


def analyze(
    graph: nx.MultiDiGraph, projection: GraphProjection, limits: GraphLimits
) -> RiskAnalysis:
    findings = []
    issues = list(projection.issues)
    truncated = projection.truncated
    lineage_cache = {}
    agent_id = projection.capabilities.agent_id

    def outgoing(node_id, relationship):
        return sorted(
            (
                data["contract"]
                for _, _, data in graph.out_edges(node_id, data=True)
                if data["contract"].relationship == relationship
            ),
            key=lambda edge: (edge.target, edge.id),
        )

    def step(edge, reverse=False):
        return ChainStep(
            edge_id=edge.id,
            source=edge.source,
            target=edge.target,
            relationship=edge.relationship,
            evidence=edge.evidence,
            traversal="REVERSE" if reverse else "FORWARD",
        )

    def sensitive_lineage(root):
        if root in lineage_cache:
            return lineage_cache[root]
        queue = deque([(root, [])])
        visited = {root}
        candidates = []
        limited = False
        while queue:
            identifier, path = queue.popleft()
            metadata = projection.node_metadata[identifier]
            stored = metadata.stored_classification
            if (
                metadata.classification_complete
                and stored is not None
                and CLASSIFICATION_RANK[stored] >= CLASSIFICATION_RANK["CONFIDENTIAL"]
            ):
                candidates.append(
                    (
                        -CLASSIFICATION_RANK[stored],
                        metadata.resource_origin != "SOURCE",
                        len(path),
                        identifier,
                        path,
                    )
                )
            parents = outgoing(identifier, "DERIVED_FROM")
            # Data-flow input and output consume two steps of the analysis depth budget.
            if len(path) + 2 >= limits.max_depth:
                if parents:
                    limited = True
                continue
            for edge in parents:
                if edge.target not in visited:
                    visited.add(edge.target)
                    queue.append((edge.target, path + [edge]))
        if limited:
            issues.append(
                GraphIssue(
                    code="DEPTH_LIMIT",
                    record_ids=[root],
                    explanation="Some trusted ancestors exceed the analysis depth; this is not a complete assessment.",
                )
            )
        candidates.sort(key=lambda candidate: candidate[:4])
        result = (candidates[0][3], candidates[0][4]) if candidates else None
        lineage_cache[root] = result
        return result

    stop = False
    for agent_node in sorted(
        identifier
        for identifier, data in graph.nodes(data=True)
        if data["contract"].kind == "agent" and identifier == stable_id("agent", agent_id)
    ):
        for capability in outgoing(agent_node, "CAN_INVOKE"):
            capability_metadata = projection.edge_metadata[capability.id]
            if (
                capability_metadata.permission_status != "ACTIVE"
                or capability_metadata.revocation_status != "NOT_REVOKED"
            ):
                continue
            action_node = capability.target
            for read in outgoing(action_node, "READS"):
                resource_node = graph.nodes[read.target]["contract"]
                if (
                    resource_node.classification is None
                    or CLASSIFICATION_RANK[resource_node.classification]
                    < CLASSIFICATION_RANK["CONFIDENTIAL"]
                ):
                    continue
                for send in outgoing(action_node, "MAY_SEND_TO"):
                    if projection.node_metadata[send.target].destination_location != "EXTERNAL":
                        continue
                    read_metadata = projection.edge_metadata[read.id]
                    send_metadata = projection.edge_metadata[send.id]
                    if not (set(read_metadata.flow_ids) & set(send_metadata.flow_ids)) or not (
                        set(capability_metadata.permission_ids)
                        & set(read_metadata.permission_ids)
                        & set(send_metadata.permission_ids)
                    ):
                        issues.append(
                            GraphIssue(
                                code="UNSUPPORTED_CAPABILITY_CONNECTION",
                                record_ids=[read.id, send.id],
                                explanation="Input and output do not share the same scoped trusted tool-flow record.",
                            )
                        )
                        continue
                    if limits.max_depth < 2:
                        issues.append(
                            GraphIssue(
                                code="DEPTH_LIMIT",
                                record_ids=[read.target],
                                explanation="Even a direct input/output chain exceeds this analysis depth.",
                            )
                        )
                        continue
                    matched = [
                        send_metadata.flow_evidence[identifier]
                        for identifier in sorted(
                            set(read_metadata.flow_ids) & set(send_metadata.flow_ids)
                        )
                        if identifier in send_metadata.flow_evidence
                        and send_metadata.flow_evidence[identifier].permission_id
                        in capability_metadata.permission_ids
                    ]
                    if not matched:
                        issues.append(
                            GraphIssue(
                                code="MISSING_TOOL_FLOW_EVIDENCE",
                                record_ids=[read.id, send.id],
                                explanation="A correlated flow ID without its supporting trusted record cannot ground a path.",
                            )
                        )
                        continue
                    matched.sort(
                        key=lambda entry: (
                            entry.verification != "VERIFIED",
                            bool(entry.assumption),
                            entry.record_id,
                        )
                    )
                    selected_flow = matched[0]
                    lineage = sensitive_lineage(read.target)
                    if lineage is None:
                        issues.append(
                            GraphIssue(
                                code="MISSING_SENSITIVE_SOURCE",
                                record_ids=[read.target],
                                explanation="Sensitive input exists, but no source proof fits the available graph and depth budget.",
                            )
                        )
                        continue
                    source_id, ancestry = lineage
                    if len(findings) >= limits.max_findings:
                        issues.append(
                            GraphIssue(
                                code="FINDING_LIMIT",
                                explanation="Additional potential findings were bounded, not classified as safe.",
                            )
                        )
                        truncated = True
                        stop = True
                        break
                    # Source -> artifact -> scoped tool -> destination. DERIVED_FROM and
                    # READS are traversed in reverse to explain potential data propagation.
                    chain = [step(edge, reverse=True) for edge in reversed(ancestry)] + [
                        step(read, reverse=True),
                        step(send),
                    ]
                    proof_edges = [capability] + ancestry + [read, send]
                    metadata = [
                        projection.edge_metadata[edge.id] for edge in [capability] + ancestry
                    ]
                    assumptions = [selected_flow.assumption] if selected_flow.assumption else []
                    input_id = projection.node_metadata[read.target].resource_id
                    source_resource = projection.node_metadata[source_id].resource_id
                    destination_node = graph.nodes[send.target]["contract"]
                    finding = CapabilityFinding(
                        finding_id=stable_id(
                            "finding", agent_id, action_node, input_id, source_resource, send.target
                        ),
                        agent_id=agent_id,
                        affected_resource=input_id,
                        sensitive_source=source_resource,
                        effective_classification=resource_node.classification,
                        destination=destination_node.label,
                        destination_id=destination_node.id,
                        chain=chain,
                        capability_steps=[step(capability)],
                        node_ids=sorted(
                            {
                                identifier
                                for edge in proof_edges
                                for identifier in (edge.source, edge.target)
                            }
                        ),
                        edge_ids=sorted({edge.id for edge in proof_edges}),
                        supporting_record_ids=sorted(
                            {
                                value
                                for entry in metadata
                                for value in entry.record_ids + entry.evidence_refs
                            }
                            | {
                                selected_flow.record_id,
                                selected_flow.evidence_ref,
                                f"pdp_permissions:{selected_flow.permission_id}",
                            }
                            | {
                                value
                                for edge in proof_edges
                                for node in (edge.source, edge.target)
                                for value in projection.node_metadata[node].record_ids
                            }
                        ),
                        evidence=sorted({edge.evidence for edge in proof_edges}),
                        assumptions=assumptions,
                        missing_evidence=["No correlated trusted execution outcome is stored."]
                        + (
                            [
                                "The tool's ability to transfer this input to this destination is declared, not verified."
                            ]
                            if assumptions
                            else []
                        ),
                        explanation=f"Active scoped permission permits a tool that consumes {input_id}, with trusted sensitive ancestry {source_resource}, and may output to the external destination {destination_node.label}. This is a potential capability combination, not evidence of execution or disclosure; the PDP still independently evaluates each action.",
                        reachability="ASSUMPTION_DEPENDENT"
                        if assumptions
                        else "VERIFIED_TOOL_CONTRACT",
                    )
                    findings.append(finding)
                if stop:
                    break
            if stop:
                break
        if stop:
            break
    # Incomplete means missing analytical coverage/facts, not that a potential finding
    # needs an execution event. Execution is a separate category, always NOT_ESTABLISHED.
    if any(finding.assumptions for finding in findings):
        issues.append(
            GraphIssue(
                code="UNVERIFIED_DATA_FLOW",
                explanation="At least one potential finding depends on an explicit tool-transfer assumption.",
            )
        )
    unique_issues = {(issue.code, tuple(issue.record_ids)): issue for issue in issues}
    if len(unique_issues) > 100:
        unique_issues = {key: unique_issues[key] for key in sorted(unique_issues)[:100]}
        unique_issues[("ISSUE_LIMIT", ())] = GraphIssue(
            code="ISSUE_LIMIT",
            explanation="Additional analytical uncertainties were bounded, not classified as safe.",
        )
        truncated = True
    return RiskAnalysis(
        agent_id=agent_id,
        findings=sorted(findings, key=lambda finding: finding.finding_id),
        incomplete=bool(unique_issues),
        truncated=truncated,
        issues=[unique_issues[key] for key in sorted(unique_issues)],
    )
