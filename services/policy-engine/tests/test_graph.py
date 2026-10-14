"""NetworkX projection/analysis tests: isolated SQLite and opt-in real PostgreSQL."""

import os
from dataclasses import replace

import networkx as nx
import pytest
from agentguard_contracts import AgentCapabilities, CapabilityGraph
from sqlalchemy import event, select
from sqlalchemy.exc import IntegrityError

from agentguard_backend.db.models import (
    AuthorizationAudit,
    GraphDestination,
    Permission,
    Principal,
    ProvenanceEdge,
    Resource,
    Revocation,
    ToolDataFlow,
    utc_now,
)
from agentguard_backend.db.provenance import create_report
from agentguard_backend.graph.analyzer import analyze
from agentguard_backend.graph.demo import seed_graph_demo
from agentguard_backend.graph.models import GraphLimits
from agentguard_backend.graph.projector import NetworkXGraphBuilder, stable_id
from agentguard_backend.graph.repository import GraphAccessDenied, load_snapshot
from agentguard_backend.graph.service import GraphService


def project(database, credential, **limits):
    return GraphService(database).query(f"Bearer {credential}", None, GraphLimits(**limits))


def risks(database, credential, **limits):
    return GraphService(database).query(
        f"Bearer {credential}", None, GraphLimits(**limits), risks=True
    )


def snapshot(database, credential):
    with database.begin() as session:
        return load_snapshot(session, f"Bearer {credential}", None, GraphLimits())


def scoped_permission(session, action="email.send"):
    return session.scalar(select(Permission).where(Permission.action == action))


def test_one_scoped_permission_has_exact_networkx_relationships(graph_database, credential):
    with graph_database.begin() as session:
        scoped_permission(session).status = "INACTIVE"
    builder = NetworkXGraphBuilder(snapshot(graph_database, credential))
    projection = builder.project()
    assert isinstance(builder.network, nx.MultiDiGraph)
    assert projection.graph.semantics == "potential_capabilities"
    assert [(edge.relationship, edge.evidence) for edge in projection.graph.edges].count(
        ("CAN_INVOKE", "declared")
    ) == 1
    action = [node for node in projection.graph.nodes if node.kind == "action"]
    assert len(action) == 1
    assert projection.node_metadata[action[0].id].resource_scope == "case-1042"
    reads = [edge for edge in projection.graph.edges if edge.relationship == "READS"]
    assert len(reads) == 1 and reads[0].source == action[0].id
    assert reads[0].target == stable_id("resource", "case-1042")
    assert not any(edge.relationship == "MAY_SEND_TO" for edge in projection.graph.edges)
    assert projection.capabilities.actions == ["case.read"]


def test_other_agents_permissions_and_resources_never_mix(graph_database, credential):
    with graph_database.begin() as session:
        session.add(Principal(id="other-agent", status="ACTIVE"))
        session.flush()
        session.add(
            Resource(
                id="other-case",
                type="case",
                owner_principal_id="other-agent",
                classification="CONFIDENTIAL",
                origin="SOURCE",
                verified_at=utc_now(),
            )
        )
        session.flush()
        session.add(
            Permission(
                principal_id="other-agent",
                action="case.read",
                resource_id="other-case",
                status="ACTIVE",
            )
        )
        # Even an incorrectly scoped database grant must not expose another owner's data.
        session.add(
            Permission(
                principal_id="support-agent",
                action="case.read",
                resource_id="other-case",
                status="ACTIVE",
            )
        )
    result = project(graph_database, credential)
    assert all(
        node.label != "other-agent" and "other-case" not in node.label
        for node in result.graph.nodes
    )
    assert "MISSING_PERMISSION_FACT" in {issue.code for issue in result.issues}
    with pytest.raises(GraphAccessDenied) as error:
        GraphService(graph_database).query(f"Bearer {credential}", "other-agent", GraphLimits())
    assert error.value.status_code == 403


@pytest.mark.parametrize("status", ["INACTIVE", "REVOKED", "revocation_record"])
def test_current_revocation_removes_capability_without_erasing_observed_provenance(
    graph_database, credential, status
):
    with graph_database.begin() as session:
        lineage = session.get(ProvenanceEdge, ("case-1042", "report-1042"))
        lineage.evidence = "observed"
        lineage.evidence_ref = "synthetic-artifact-registry:report-1042"
    before = project(graph_database, credential)
    assert len(risks(graph_database, credential).findings) == 1
    with graph_database.begin() as session:
        permission = scoped_permission(session)
        if status == "revocation_record":
            session.add(
                Revocation(
                    permission_id=permission.id, reason="Synthetic active-session revocation"
                )
            )
        else:
            permission.status = status
    after = project(graph_database, credential)
    assert after.capabilities.actions == ["case.read"]
    assert not risks(graph_database, credential).findings
    assert [edge for edge in before.graph.edges if edge.relationship == "DERIVED_FROM"] == [
        edge for edge in after.graph.edges if edge.relationship == "DERIVED_FROM"
    ]
    assert [edge.evidence for edge in after.graph.edges if edge.relationship == "DERIVED_FROM"] == [
        "observed"
    ]


def test_revoked_case_read_does_not_erase_preexisting_report_risk(graph_database, credential):
    with graph_database.begin() as session:
        permission = scoped_permission(session, "case.read")
        session.add(Revocation(permission_id=permission.id, reason="Revoke source access only"))
    # The already-derived report remains accessible to the separately scoped email tool.
    assert len(risks(graph_database, credential).findings) == 1
    assert project(graph_database, credential).capabilities.actions == ["email.send"]


def test_derived_report_uses_pdp_classification_logic_not_stored_downgrade(
    graph_database, credential
):
    with graph_database.begin() as session:
        session.get(Resource, "report-1042").classification = "PUBLIC"
        session.get(Resource, "case-1042").classification = "RESTRICTED"
    result = project(graph_database, credential)
    report = next(node for node in result.graph.nodes if node.label == "report-1042")
    assert report.classification == "RESTRICTED"
    assert result.node_metadata[report.id].stored_classification == "PUBLIC"
    assert result.node_metadata[report.id].resource_type == "report"
    finding = risks(graph_database, credential).findings[0]
    assert finding.sensitive_source == "case-1042"
    assert finding.effective_classification == "RESTRICTED"


def test_multihop_provenance_and_ordered_explanation_walk(graph_database, credential):
    with graph_database.begin() as session:
        create_report(session, "summary", "support-agent", ["report-1042"])
        permission = Permission(
            principal_id="support-agent",
            action="email.send",
            resource_id="summary",
            status="ACTIVE",
        )
        session.add(permission)
        session.flush()
        session.add(
            ToolDataFlow(
                id="summary-send",
                permission_id=permission.id,
                input_resource_id="summary",
                destination_id="synthetic-external-email",
                status="ACTIVE",
                verification="DECLARED",
                assumption="Synthetic summary can be consumed by the future email tool.",
                evidence_ref="synthetic:summary-flow",
            )
        )
    finding = next(
        finding
        for finding in risks(graph_database, credential).findings
        if finding.affected_resource == "summary"
    )
    assert finding.sensitive_source == "case-1042"
    assert [step.relationship for step in finding.chain] == [
        "DERIVED_FROM",
        "DERIVED_FROM",
        "READS",
        "MAY_SEND_TO",
    ]
    assert [step.traversal for step in finding.chain] == [
        "REVERSE",
        "REVERSE",
        "REVERSE",
        "FORWARD",
    ]
    walk = [
        (step.target, step.source) if step.traversal == "REVERSE" else (step.source, step.target)
        for step in finding.chain
    ]
    assert all(first[1] == second[0] for first, second in zip(walk, walk[1:], strict=False))
    assert walk[0][0] == stable_id("resource", "case-1042")


def test_cycles_are_explicit_unknown_and_do_not_enumerate_paths(graph_database, credential):
    with graph_database.begin() as session:
        session.get(Resource, "case-1042").origin = "DERIVED"
        session.add(ProvenanceEdge(parent_id="report-1042", child_id="case-1042"))
    graph = project(graph_database, credential)
    assert graph.incomplete
    assert {"PROVENANCE_CYCLE", "INCONSISTENT_PROVENANCE"} <= {issue.code for issue in graph.issues}
    assert all(node.classification is None for node in graph.graph.nodes if node.kind == "resource")
    assert not risks(graph_database, credential).findings


def test_duplicate_flows_deduplicate_logical_edges_and_keep_record_evidence(
    graph_database, credential
):
    before = project(graph_database, credential)
    with graph_database.begin() as session:
        flow = session.get(ToolDataFlow, "synthetic-report-email")
        session.add(
            ToolDataFlow(
                id="duplicate-flow",
                permission_id=flow.permission_id,
                input_resource_id=flow.input_resource_id,
                destination_id=flow.destination_id,
                status=flow.status,
                verification=flow.verification,
                assumption=flow.assumption,
                evidence_ref=flow.evidence_ref,
            )
        )
    after = project(graph_database, credential)
    assert before.graph == after.graph
    assert len(risks(graph_database, credential).findings) == 1
    send = next(edge for edge in after.graph.edges if edge.relationship == "MAY_SEND_TO")
    assert after.edge_metadata[send.id].flow_ids == ["duplicate-flow", "synthetic-report-email"]


def test_potential_disclosure_has_grounded_steps_and_explicit_uncertainty(
    graph_database, credential
):
    projection = project(graph_database, credential)
    result = risks(graph_database, credential)
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.risk_category == "POTENTIAL_CONFIDENTIAL_EXTERNAL_DISCLOSURE"
    assert finding.destination == "outsider@example.test"
    assert finding.affected_resource == "report-1042"
    assert finding.sensitive_source == "case-1042"
    assert finding.potentially_reachable is True
    assert finding.reachability == "ASSUMPTION_DEPENDENT"
    assert finding.assumptions and finding.missing_evidence
    assert finding.execution_outcome == "NOT_ESTABLISHED"
    assert result.incomplete and result.execution_evidence == "NOT_RECORDED"
    assert set(finding.edge_ids) <= {edge.id for edge in projection.graph.edges}
    assert set(finding.node_ids) <= {node.id for node in projection.graph.nodes}
    assert any(ref.startswith("pdp_permissions:") for ref in finding.supporting_record_ids)


def test_permission_name_alone_never_invents_tool_connections(graph_database, credential):
    with graph_database.begin() as session:
        session.delete(session.get(ToolDataFlow, "synthetic-report-email"))
    result = risks(graph_database, credential)
    assert not result.findings and result.incomplete
    assert "MISSING_TOOL_FLOW" in {issue.code for issue in result.issues}
    assert "email.send" in project(graph_database, credential).capabilities.actions


def test_mismatched_tool_input_scope_is_not_projected(graph_database, credential):
    with graph_database.begin() as session:
        session.get(ToolDataFlow, "synthetic-report-email").input_resource_id = "case-1042"
    result = risks(graph_database, credential)
    assert not result.findings and result.incomplete
    assert "INCONSISTENT_TOOL_FLOW" in {issue.code for issue in result.issues}


def test_missing_destination_snapshot_never_fabricates_edges_or_nodes(graph_database, credential):
    facts = replace(snapshot(graph_database, credential), destinations=[])
    builder = NetworkXGraphBuilder(facts)
    graph = builder.project()
    assert not any(node.kind == "destination" for node in graph.graph.nodes)
    assert not any(edge.relationship == "MAY_SEND_TO" for edge in graph.graph.edges)
    assert "MISSING_DESTINATION_FACT" in {issue.code for issue in graph.issues}
    assert not analyze(builder.network, graph, GraphLimits()).findings


def test_missing_parent_never_fabricates_a_resource_and_classification_is_unknown(
    graph_database, credential
):
    facts = snapshot(graph_database, credential)
    facts.resources = [row for row in facts.resources if row.id != "case-1042"]
    graph = NetworkXGraphBuilder(facts).project()
    assert not any(node.label == "case-1042" for node in graph.graph.nodes)
    assert not any(edge.relationship == "DERIVED_FROM" for edge in graph.graph.edges)
    report = next(node for node in graph.graph.nodes if node.label == "report-1042")
    assert report.classification is None and graph.incomplete


@pytest.mark.parametrize("change", ["unverified", "INACTIVE", "REVOKED", "UNKNOWN", "INTERNAL"])
def test_destination_trust_and_location_control_external_risk(graph_database, credential, change):
    with graph_database.begin() as session:
        destination = session.get(GraphDestination, "synthetic-external-email")
        if change == "unverified":
            destination.verified_at = None
        elif change in {"INACTIVE", "REVOKED"}:
            destination.status = change
        else:
            destination.location = change
    result = risks(graph_database, credential)
    assert not result.findings
    if change != "INTERNAL":
        assert result.incomplete


def test_fixed_snapshot_has_stable_ordering_and_ids(graph_database, credential):
    first = project(graph_database, credential)
    second = project(graph_database, credential)
    assert first.model_dump_json() == second.model_dump_json()
    assert (
        risks(graph_database, credential).model_dump_json()
        == risks(graph_database, credential).model_dump_json()
    )
    facts = snapshot(graph_database, credential)
    facts.resources.reverse()
    facts.permissions.reverse()
    facts.provenance.reverse()
    facts.flows.reverse()
    assert NetworkXGraphBuilder(facts).project() == first
    assert [node.id for node in first.graph.nodes] == sorted(node.id for node in first.graph.nodes)


def test_graphbuilder_unpaired_contract_lists_cannot_add_permissions(graph_database, credential):
    builder = NetworkXGraphBuilder(snapshot(graph_database, credential))
    fabricated = AgentCapabilities(
        agent_id="support-agent", actions=["root.execute"], resource_ids=["secret"], status="ACTIVE"
    )
    assert builder.build([fabricated]) == builder.project().graph
    fabricated.agent_id = "other-agent"
    with pytest.raises(ValueError, match="another agent"):
        builder.build([fabricated])


def test_two_identically_named_actions_keep_distinct_scopes(graph_database, credential):
    with graph_database.begin() as session:
        permission = Permission(
            principal_id="support-agent",
            action="email.send",
            resource_id="case-1042",
            status="ACTIVE",
        )
        session.add(permission)
        session.flush()
        session.add(
            ToolDataFlow(
                id="case-internal-send",
                permission_id=permission.id,
                input_resource_id="case-1042",
                status="ACTIVE",
                verification="DECLARED",
                assumption="Synthetic internal-only input declaration.",
                evidence_ref="synthetic:case-flow",
            )
        )
    graph = project(graph_database, credential)
    actions = [
        metadata for metadata in graph.node_metadata.values() if metadata.action == "email.send"
    ]
    assert sorted(metadata.resource_scope for metadata in actions) == ["case-1042", "report-1042"]
    findings = risks(graph_database, credential).findings
    assert len(findings) == 1 and findings[0].affected_resource == "report-1042"


def test_depth_and_graph_size_limits_report_incomplete_not_safe(graph_database, credential):
    with graph_database.begin() as session:
        for i in range(60):
            session.add(
                Resource(
                    id=f"public-{i:03}",
                    type="document",
                    owner_principal_id="support-agent",
                    classification="PUBLIC",
                    origin="SOURCE",
                    verified_at=utc_now(),
                )
            )
    graph = project(graph_database, credential, max_nodes=5, max_edges=2)
    assert len(graph.graph.nodes) <= 5 and len(graph.graph.edges) <= 2
    assert graph.incomplete and graph.truncated
    assessment = risks(graph_database, credential, max_depth=1)
    assert not assessment.findings and assessment.incomplete
    assert "DEPTH_LIMIT" in {issue.code for issue in assessment.issues}


def test_output_limit_bounds_findings_and_is_deterministic(graph_database, credential):
    with graph_database.begin() as session:
        for i in range(12):
            identifier = f"external-{i:02}"
            session.add(
                GraphDestination(
                    id=identifier,
                    address=f"outside-{i}@example.test",
                    location="EXTERNAL",
                    status="ACTIVE",
                    verified_at=utc_now(),
                )
            )
        session.flush()
        for i in range(12):
            session.add(
                ToolDataFlow(
                    id=f"flow-{i:02}",
                    permission_id=scoped_permission(session).id,
                    input_resource_id="report-1042",
                    destination_id=f"external-{i:02}",
                    status="ACTIVE",
                    verification="DECLARED",
                    assumption="Explicit synthetic report transfer assumption.",
                    evidence_ref=f"synthetic:flow-{i:02}",
                )
            )
    result = risks(graph_database, credential, max_findings=3)
    assert len(result.findings) == 3 and result.truncated and result.incomplete
    assert "FINDING_LIMIT" in {issue.code for issue in result.issues}
    assert result == risks(graph_database, credential, max_findings=3)


def test_projection_uses_constant_query_count_and_is_read_only(graph_database, credential):
    with graph_database.begin() as session:
        for i in range(25):
            create_report(session, f"report-{i}", "support-agent", ["report-1042"])
    statements = []
    engine = graph_database.kw["bind"]

    def capture(_connection, _cursor, statement, _parameters, _context, _many):
        statements.append(statement)

    event.listen(engine, "before_cursor_execute", capture)
    try:
        graph = project(graph_database, credential)
        assert len([node for node in graph.graph.nodes if node.kind == "resource"]) == 27
    finally:
        event.remove(engine, "before_cursor_execute", capture)
    assert len(statements) <= 10
    assert all(
        statement.lstrip().upper().startswith(("SELECT", "SET TRANSACTION READ ONLY"))
        for statement in statements
    )


def test_authorization_allow_is_not_execution_or_a_destination_proof(graph_database, credential):
    with graph_database.begin() as session:
        session.add(
            AuthorizationAudit(
                decision_id="synthetic-allow",
                request_id="request-allow",
                session_id="synthetic-session",
                principal_id="support-agent",
                adapter_id="mcp-adapter",
                action="email.send",
                resource_id="report-1042",
                request_digest="a" * 64,
                decision="ALLOW",
                reason_code="CG-ALLOW-001",
                explanation="Synthetic audit only",
                policy_version="pdp-v1",
                provenance_refs=["case-1042"],
                timestamp=utc_now(),
            )
        )
    graph = project(graph_database, credential)
    audit = graph.policy_decisions[0]
    assert audit.decision == "ALLOW"
    assert audit.execution_outcome == audit.destination_correlation == "NOT_RECORDED"
    assert risks(graph_database, credential).findings[0].execution_outcome == "NOT_ESTABLISHED"
    assert not any(edge.evidence == "observed" for edge in graph.graph.edges)


def test_observed_marker_requires_trusted_reference(graph_database):
    with pytest.raises(IntegrityError), graph_database.begin() as session:
        edge = session.get(ProvenanceEdge, ("case-1042", "report-1042"))
        edge.evidence = "observed"
        edge.evidence_ref = None


def test_verified_tool_contract_remains_potential_not_observed_execution(
    graph_database, credential
):
    with graph_database.begin() as session:
        flow = session.get(ToolDataFlow, "synthetic-report-email")
        flow.verification = "VERIFIED"
        flow.assumption = None
        flow.verified_at = utc_now()
    finding = risks(graph_database, credential).findings[0]
    assert finding.reachability == "VERIFIED_TOOL_CONTRACT"
    assert finding.execution_outcome == "NOT_ESTABLISHED"
    assert finding.evidence == ["declared"]


def test_unrelated_flow_evidence_cannot_form_a_path_even_in_a_multigraph(
    graph_database, credential
):
    builder = NetworkXGraphBuilder(snapshot(graph_database, credential))
    graph = builder.project()
    send = next(edge for edge in graph.graph.edges if edge.relationship == "MAY_SEND_TO")
    graph.edge_metadata[send.id].flow_ids = ["unrelated-flow"]
    result = analyze(builder.network, graph, GraphLimits())
    assert not result.findings
    assert "UNSUPPORTED_CAPABILITY_CONNECTION" in {issue.code for issue in result.issues}


def test_fixture_seed_refuses_to_overwrite_existing_graph_facts(graph_database):
    with pytest.raises(ValueError, match="preserved"):
        seed_graph_demo(graph_database)


def test_graph_contract_stays_unchanged(graph_database, credential):
    graph = project(graph_database, credential)
    parsed = CapabilityGraph.model_validate_json(graph.graph.model_dump_json())
    assert parsed == graph.graph
    assert set(parsed.model_dump()) == {"nodes", "edges", "semantics"}


def test_verified_external_flow_does_not_inherit_an_internal_flow_assumption(
    graph_database, credential
):
    with graph_database.begin() as session:
        flow = session.get(ToolDataFlow, "synthetic-report-email")
        flow.verification = "VERIFIED"
        flow.assumption = None
        flow.verified_at = utc_now()
        session.add(
            ToolDataFlow(
                id="unrelated-input-only",
                permission_id=flow.permission_id,
                input_resource_id=flow.input_resource_id,
                status="ACTIVE",
                verification="DECLARED",
                assumption="An unrelated input-only assumption, not part of the external route.",
                evidence_ref="synthetic:unrelated-input",
            )
        )
    finding = risks(graph_database, credential).findings[0]
    assert finding.reachability == "VERIFIED_TOOL_CONTRACT"
    assert finding.assumptions == []
    assert not any("unrelated-input" in ref for ref in finding.supporting_record_ids)


def test_highest_classification_source_is_in_the_proof(graph_database, credential):
    with graph_database.begin() as session:
        session.add(
            Resource(
                id="restricted-source",
                type="case",
                owner_principal_id="support-agent",
                classification="RESTRICTED",
                origin="SOURCE",
                verified_at=utc_now(),
            )
        )
        session.flush()
        session.add(ProvenanceEdge(parent_id="restricted-source", child_id="report-1042"))
    finding = risks(graph_database, credential).findings[0]
    assert finding.sensitive_source == "restricted-source"
    assert finding.effective_classification == "RESTRICTED"
    assert "pdp_resources:restricted-source" in finding.supporting_record_ids


def test_diamond_lineage_does_not_enumerate_exponentially_many_paths(
    graph_database, credential, monkeypatch
):
    def forbidden(*_args, **_kwargs):
        pytest.fail("Do not enumerate all simple paths")

    monkeypatch.setattr(nx, "all_simple_paths", forbidden)
    with graph_database.begin() as session:
        previous = ["case-1042"]
        for depth in range(15):
            layer = [f"diamond-{depth}-a", f"diamond-{depth}-b"]
            for identifier in layer:
                create_report(session, identifier, "support-agent", previous)
                session.get(Resource, identifier).classification = "PUBLIC"
            previous = layer
        create_report(session, "diamond-output", "support-agent", previous)
        session.get(Resource, "diamond-output").classification = "PUBLIC"
        permission = Permission(
            principal_id="support-agent",
            action="email.send",
            resource_id="diamond-output",
            status="ACTIVE",
        )
        session.add(permission)
        session.flush()
        session.add(
            ToolDataFlow(
                id="diamond-transfer",
                permission_id=permission.id,
                input_resource_id="diamond-output",
                destination_id="synthetic-external-email",
                status="ACTIVE",
                verification="DECLARED",
                assumption="Explicit synthetic diamond transfer assumption.",
                evidence_ref="synthetic:diamond-transfer",
            )
        )
    shallow = risks(graph_database, credential, max_depth=8)
    assert not any(finding.affected_resource == "diamond-output" for finding in shallow.findings)
    assert shallow.incomplete
    deep = risks(graph_database, credential, max_depth=32)
    finding = next(
        finding for finding in deep.findings if finding.affected_resource == "diamond-output"
    )
    assert finding.sensitive_source == "case-1042"
    assert len(finding.chain) == 18


def test_separate_public_output_never_connects_to_a_confidential_read(graph_database, credential):
    with graph_database.begin() as session:
        scoped_permission(session).status = "INACTIVE"
        session.add(
            Resource(
                id="public-notice",
                type="document",
                owner_principal_id="support-agent",
                classification="PUBLIC",
                origin="SOURCE",
                verified_at=utc_now(),
            )
        )
        session.flush()
        permission = Permission(
            principal_id="support-agent",
            action="email.send",
            resource_id="public-notice",
            status="ACTIVE",
        )
        session.add(permission)
        session.flush()
        session.add(
            ToolDataFlow(
                id="public-only-send",
                permission_id=permission.id,
                input_resource_id="public-notice",
                destination_id="synthetic-external-email",
                status="ACTIVE",
                verification="DECLARED",
                assumption="Only the public notice is an input to this exact declared scope.",
                evidence_ref="synthetic:public-only-send",
            )
        )
    graph = project(graph_database, credential)
    assert sorted(graph.capabilities.actions) == ["case.read", "email.send"]
    # Shared agent and tool name do NOT establish a sensitive-to-public data handoff.
    assert not risks(graph_database, credential).findings


@pytest.mark.parametrize("status", ["INACTIVE", "REVOKED"])
def test_inactive_tool_flows_do_not_supply_a_reachable_output(graph_database, credential, status):
    with graph_database.begin() as session:
        session.get(ToolDataFlow, "synthetic-report-email").status = status
    graph = project(graph_database, credential)
    assert not any(edge.relationship == "MAY_SEND_TO" for edge in graph.graph.edges)
    result = risks(graph_database, credential)
    assert not result.findings and result.incomplete


def test_truncated_provenance_cannot_silently_lower_classification(graph_database, credential):
    with graph_database.begin() as session:
        session.get(Resource, "report-1042").classification = "PUBLIC"
        session.add(
            Resource(
                id="aaa-public-source",
                type="document",
                owner_principal_id="support-agent",
                classification="PUBLIC",
                origin="SOURCE",
                verified_at=utc_now(),
            )
        )
        session.flush()
        session.add(ProvenanceEdge(parent_id="aaa-public-source", child_id="report-1042"))
    # Snapshot order/bound includes the public parent but omits the confidential one.
    graph = project(graph_database, credential, max_edges=1)
    report = next(node for node in graph.graph.nodes if node.label == "report-1042")
    assert report.classification is None
    assert graph.incomplete and graph.truncated
    assert any(
        issue.code == "SNAPSHOT_LIMIT" and "provenance" in issue.record_ids
        for issue in graph.issues
    )
    assert not risks(graph_database, credential, max_edges=1).findings


def test_issue_output_is_bounded_and_omissions_are_marked(graph_database, credential):
    with graph_database.begin() as session:
        for i in range(120):
            session.add(
                Resource(
                    id=f"unverified-{i:03}",
                    type="document",
                    owner_principal_id="support-agent",
                    classification="CONFIDENTIAL",
                    origin="SOURCE",
                    verified_at=None,
                )
            )
    graph = project(graph_database, credential)
    assert len(graph.issues) <= 101
    assert graph.incomplete and graph.truncated
    assert "ISSUE_LIMIT" in {issue.code for issue in graph.issues}


def test_real_postgresql_graph_opt_in():
    if not os.getenv("AG_TEST_DATABASE_URL"):
        pytest.skip(
            "Set AG_TEST_DATABASE_URL to run graph cases against UUID-isolated PostgreSQL schemas"
        )
    # All graph_database cases are parametrized against PostgreSQL when explicitly configured.
    assert os.environ["AG_TEST_DATABASE_URL"].startswith("postgresql+psycopg://")
