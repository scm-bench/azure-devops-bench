package scmbench.rules.cis_1_1_6

import rego.v1

import data.scmbench.lib

# Which paths are sensitive is not in any API, so the verdict is a person's.
# What the scan can do is say what is already configured.
reviewers := [sprintf("policy %d: %s, paths %s", [r.id, state(r), paths(r)]) |
	some r in lib.list(["pullRequestSettings", "requiredReviewers"])
]

state(r) := "required" if {
	object.get(r, "blocking", false) == true
} else := "optional"

paths(r) := lib.joined(lib.as_list(object.get(r, "pathFilters", [])), 5) if {
	count(lib.as_list(object.get(r, "pathFilters", []))) > 0
} else := "all"

result := lib.change_na if {
	lib.archived_repository
} else := {
	"status": "MANUAL",
	"details": "Confirm by hand that changes to sensitive paths require their owners' approval, through a required, path-filtered \"Automatically included reviewers\" policy.",
	"evidence": reviewers,
}
