package scmbench.rules.cis_1_3_3

import rego.v1

import data.scmbench.lib

minimum := object.get(lib.cfg, ["thresholds", "minOrgAdmins"], 2)

maximum := object.get(lib.cfg, ["thresholds", "maxOrgAdmins"], 5)

set := object.get(lib.resource, "effectiveAdmins", {})

admins := lib.as_list(object.get(set, "users", []))

total := count(admins)

services := lib.as_list(object.get(set, "serviceIdentities", []))

# Zero means "no upper limit": a policy of "no administrators at all" is not
# something anybody wants.
over_limit if {
	maximum > 0
	total > maximum
}

range_note := sprintf("within the recommended range of %d to %d", [minimum, maximum]) if {
	maximum > 0
} else := sprintf("at or above the recommended minimum of %d (no upper limit configured)", [minimum])

service_evidence := [sprintf("service identities in the group, not counted: %s", [lib.joined(services, 5)])] if {
	count(services) > 0
} else := []

# Ordering matters: an over-count is conclusive even from a lower bound, so it
# is decided before the completeness gate. An under-count is not.
result := {
	"status": "FAIL",
	"details": sprintf("%d people are Project Collection Administrators (at most %d recommended), so the blast radius of any one compromised administrator is large: %s.", [total, maximum, lib.joined(admins, 10)]),
	"evidence": array.concat(sort(admins), service_evidence),
} if {
	over_limit
} else := {
	"status": "MANUAL",
	"details": "Project Collection Administrators could not be read in full (the token needs vso.identity and vso.graph, or a Microsoft Entra group in it could not be expanded), so the administrator count is unknown.",
	"evidence": service_evidence,
} if {
	not lib.available("admins")
} else := {
	"status": "MANUAL",
	"details": sprintf("At least %d people are Project Collection Administrators, but a group in it could not be fully expanded, so the count may be higher.", [total]),
	"evidence": array.concat(lib.as_list(object.get(set, "groups", [])), service_evidence),
} if {
	not lib.complete(set)
} else := {
	"status": "PASS",
	"details": sprintf("%d people are Project Collection Administrators, %s.", [total, range_note]),
	"evidence": service_evidence,
} if {
	total >= minimum
} else := {
	"status": "FAIL",
	"details": sprintf("Project Collection Administrators holds only %s; at least %d are needed so that losing one account does not lock the organization out.", [lib.people(total), minimum]),
	"evidence": array.concat(sort(admins), service_evidence),
}
