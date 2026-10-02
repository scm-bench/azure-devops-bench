package scmbench.rules.cis_1_1_13

import rego.v1

import data.scmbench.lib

non_linear := lib.as_list(object.get(lib.cfg, "nonLinearMergeStrategies", []))

enabled := lib.enabled_merge_strategies

offending := [s |
	some s in enabled
	s in non_linear
]

result := lib.change_na if {
	lib.change_not_applicable
} else := {
	"status": "MANUAL",
	"details": "The branch policies on the default branch could not be read, so the allowed merge types are unknown.",
} if {
	not lib.available("mergeStrategies")
} else := {
	"status": "PASS",
	"details": sprintf("Only linear merge types are allowed into %s: %s.", [lib.default_branch_name, concat(", ", sort(enabled))]),
} if {
	count(offending) == 0
} else := {
	"status": "FAIL",
	"details": sprintf("Merge types that create merge commits are allowed into %s: %s.", [lib.default_branch_name, concat(", ", sort(offending))]),
	"evidence": [sprintf("allowed merge types: %s", [concat(", ", sort(enabled))])],
}
