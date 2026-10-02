package scmbench.rules.cis_1_3_7

import rego.v1

import data.scmbench.lib

minimum := object.get(lib.cfg, ["thresholds", "minRepositoryAdmins"], 2)

set := object.get(lib.resource, "admins", {})

admins := lib.as_list(object.get(set, "users", []))

total := count(admins)

# The count is a lower bound only when organization administrators were fully
# subtracted: an administrator hidden in an unexpanded Entra group inside
# Project Collection Administrators is still in the set, inflating it.
lower_bound if lib.available("orgAdminsExact")

# It is an upper bound only when every administrator group was expanded.
upper_bound if lib.complete(set)

result := {
	"status": "MANUAL",
	"details": "Who may administer this repository could not be read (the token needs vso.security_manage), or organization administrators could not be told apart from repository administrators.",
} if {
	not lib.available("admins")
} else := {
	"status": "PASS",
	"details": sprintf("%d people can administer this repository: %s.", [total, lib.joined(admins, 10)]),
} if {
	total >= minimum
	lower_bound
} else := {
	"status": "PASS",
	"details": "Every member of the organization or project can administer this repository; CIS-1.3.8 reports the blanket grant.",
} if {
	lib.everyone(set)
	lower_bound
} else := {
	"status": "FAIL",
	"details": sprintf("Only %s can administer this repository; at least %d are needed so it stays maintainable if one leaves.", [lib.people(total), minimum]),
	"evidence": sort(admins),
} if {
	total < minimum
	upper_bound
} else := {
	"status": "MANUAL",
	"details": sprintf("%d people can administer this repository, but an administrator group could not be fully expanded, so whether that meets the minimum of %d is unknown.", [total, minimum]),
	"evidence": lib.as_list(object.get(set, "groups", [])),
}
