package agentguard.authz_test

import rego.v1
import data.agentguard.authz

base := {
    "request": {
        "request_id": "rego-test", "action": "case.read", "resource_type": "case",
        "destination_present": false, "request_digest": "synthetic-test-digest",
    },
    "facts": {
        "identity": {"verified": true, "status": "ACTIVE", "agent_id": "support-agent"},
        "permission_status": "ACTIVE",
        "resource": {
            "verified": true, "type": "case", "classification": "CONFIDENTIAL",
            "owner_agent_id": "support-agent",
        },
        "destination": {"valid": false, "approved": false},
    },
}

test_authorized_read if {
    result := authz.decision with input as base
    result.decision == "ALLOW"
    result.request_id == "rego-test"
    result.action == "case.read"
    result.request_digest == "synthetic-test-digest"
    result.policy_version == "pdp-v1"
}

test_unverified_identity if {
    result := authz.decision with input as base with input.facts.identity.verified as false
    result.decision == "DENY"
    result.reason_code == "CG-IDENTITY-UNVERIFIED"
}

test_revoked_identity if {
    result := authz.decision with input as base with input.facts.identity.status as "REVOKED"
    result.reason_code == "CG-IDENTITY-REVOKED"
}

test_inactive_identity if {
    result := authz.decision with input as base with input.facts.identity.status as "INACTIVE"
    result.reason_code == "CG-IDENTITY-INACTIVE"
}

test_revoked_permission if {
    result := authz.decision with input as base with input.facts.permission_status as "REVOKED"
    result.decision == "DENY"
    result.reason_code == "CG-PERMISSION-REVOKED"
}

test_missing_permission if {
    result := authz.decision with input as base with input.facts.permission_status as "MISSING"
    result.reason_code == "CG-PERMISSION-MISSING"
}

test_inactive_permission if {
    result := authz.decision with input as base with input.facts.permission_status as "INACTIVE"
    result.reason_code == "CG-PERMISSION-INACTIVE"
}

test_unknown_resource if {
    result := authz.decision with input as base with input.facts.resource.verified as false
    result.reason_code == "CG-RESOURCE-UNVERIFIED"
}

test_resource_scope if {
    result := authz.decision with input as base with input.facts.resource.owner_agent_id as "another-agent"
    result.reason_code == "CG-RESOURCE-SCOPE"
}

test_unknown_action if {
    result := authz.decision with input as base with input.request.action as "admin.delete"
    result.decision == "DENY"
    result.reason_code == "CG-DEFAULT-DENY"
}

test_confidential_egress if {
    result := authz.decision with input as base with input.request.action as "email.send" with input.facts.destination.valid as true
    result.decision == "DENY"
    result.reason_code == "CG-DATA-EGRESS-001"
}

test_approved_destination if {
    result := authz.decision with input as base with input.request.action as "email.send" with input.facts.destination.valid as true with input.facts.destination.approved as true
    result.decision == "ALLOW"
}

test_public_external_email if {
    result := authz.decision with input as base with input.request.action as "email.send" with input.facts.destination.valid as true with input.facts.resource.classification as "PUBLIC"
    result.decision == "ALLOW"
}

test_invalid_destination if {
    result := authz.decision with input as base with input.request.action as "email.send"
    result.reason_code == "CG-DESTINATION-INVALID"
}
