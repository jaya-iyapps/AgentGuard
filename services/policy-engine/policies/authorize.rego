package agentguard.authz

import rego.v1

policy_version := "pdp-v1"

deny(code, explanation) := {
    "decision": "DENY",
    "reason_code": code,
    "explanation": explanation,
}

default verdict := {
    "decision": "DENY",
    "reason_code": "CG-DEFAULT-DENY",
    "explanation": "No explicit allow rule matches this action.",
}

# Ordered, mutually exclusive decisions avoid conflicting complete-rule results.
verdict := deny("CG-IDENTITY-UNVERIFIED", "Identity has not been verified.") if {
    not input.facts.identity.verified
} else := deny("CG-IDENTITY-REVOKED", "The agent identity is revoked.") if {
    input.facts.identity.status == "REVOKED"
} else := deny("CG-IDENTITY-INACTIVE", "The agent identity is inactive.") if {
    input.facts.identity.status != "ACTIVE"
} else := deny("CG-PERMISSION-REVOKED", "The requested permission is revoked.") if {
    input.facts.permission_status == "REVOKED"
} else := deny("CG-PERMISSION-MISSING", "No permission exists for this action and resource.") if {
    input.facts.permission_status == "MISSING"
} else := deny("CG-PERMISSION-INACTIVE", "The requested permission is inactive.") if {
    input.facts.permission_status != "ACTIVE"
} else := deny("CG-RESOURCE-UNVERIFIED", "Resource classification is not verified.") if {
    not input.facts.resource.verified
} else := deny("CG-RESOURCE-SCOPE", "Resource owner or type does not match the request.") if {
    not resource_in_scope
} else := deny("CG-DESTINATION-INVALID", "A valid email destination is required.") if {
    input.request.action == "email.send"
    not input.facts.destination.valid
} else := deny("CG-DATA-EGRESS-001", "Non-public data cannot go to an unapproved destination.") if {
    input.request.action == "email.send"
    input.facts.resource.classification != "PUBLIC"
    not input.facts.destination.approved
} else := {
    "decision": "ALLOW",
    "reason_code": "CG-ALLOW-001",
    "explanation": "Verified identity, current permission, and trusted resource facts permit this action.",
} if {
    allowed_action
}

resource_in_scope if {
    input.facts.resource.owner_agent_id == input.facts.identity.agent_id
    input.facts.resource.type == input.request.resource_type
    input.facts.resource.classification in {"PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"}
}

allowed_action if {
    input.request.action == "case.read"
    input.facts.resource.type == "case"
    input.request.destination_present == false
}

allowed_action if {
    input.request.action == "email.send"
    input.facts.destination.valid
    input.facts.resource.classification == "PUBLIC"
}

allowed_action if {
    input.request.action == "email.send"
    input.facts.destination.valid
    input.facts.destination.approved
}

decision := object.union(verdict, {
    "policy_version": policy_version,
    "request_id": input.request.request_id,
    "action": input.request.action,
    "request_digest": input.request.request_digest,
})
