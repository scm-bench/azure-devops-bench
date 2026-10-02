package scmbench.rules.cis_1_2_2

import rego.v1

import data.scmbench.lib

maximum := object.get(lib.cfg, ["thresholds", "maxRepositoryCreators"], 0)

projects := lib.list(["repositoryCreators"])

creators(p) := lib.as_list(object.get(p, ["principals", "users"], []))

over(p) if lib.everyone(object.get(p, "principals", {}))

over(p) if count(creators(p)) > maximum

# A count over the limit is conclusive when the administrators taken out of it
# were fully known: everyone left is a real non-administrator, and an
# unexpanded group could only add more.
conclusive := [p.project |
	some p in projects
	over(p)
	object.get(p, "adminsExact", false) == true
]

uncertain := [p.project |
	some p in projects
	not settled(p)
]

settled(p) if {
	lib.complete(object.get(p, "principals", {}))
	object.get(p, "adminsExact", false) == true
}

describe(p) := sprintf("%s: %s", [p.project, lib.who(object.get(p, "principals", {}))])

evidence := [describe(p) |
	some p in projects
	p.project in conclusive
]

result := {
	"status": "FAIL",
	"details": sprintf("People who do not administer the project can create repositories in %s.", [lib.joined(conclusive, 5)]),
	"evidence": evidence,
} if {
	count(conclusive) > 0
} else := {
	"status": "MANUAL",
	"details": "Who may create repositories could not be read in every project; the token needs vso.security_manage to read Git permissions.",
} if {
	not lib.available("repositoryCreators")
} else := {
	"status": "MANUAL",
	"details": sprintf("Who may create repositories is not fully known in %s (a group could not be expanded), so whether creation is limited is unknown.", [lib.joined(uncertain, 5)]),
} if {
	count(uncertain) > 0
} else := {
	"status": "PASS",
	"details": sprintf("Repository creation is limited to administrators in all %d project(s).", [count(projects)]),
}
