package scmbench.rules.cis_1_1_9

import rego.v1

import data.scmbench.lib

gates := [c |
	some c in lib.list("requiredBuilds")
	c.matchesDefaultBranch == true
]

# A path filter, or a status check that applies only once it has been posted,
# gates some pull requests and waves the rest through.
unconditional := [c |
	some c in gates
	object.get(c, "conditional", false) == false
]

# A rule of its own rather than a comprehension inside the PASS head: OPA 1.21
# rejects the latter as unsafe (rego_unsafe_var_error), which 1.19 accepted.
unconditional_names := [c.name | some c in unconditional]

conditional := [sprintf("%s %q gates only some pull requests (path filter or conditional)", [object.get(c, "kind", "check"), object.get(c, "name", "")]) |
	some c in gates
	object.get(c, "conditional", false) == true
]

result := lib.change_na if {
	lib.change_not_applicable
} else := {
	"status": "MANUAL",
	"details": "The branch policies on the default branch could not be read, so CI gating cannot be confirmed.",
} if {
	not lib.available("requiredBuilds")
} else := {
	"status": "PASS",
	"details": sprintf("Pull requests into %s cannot complete until %d required check(s) pass: %s.", [lib.default_branch_name, count(unconditional), lib.joined(unconditional_names, 5)]),
} if {
	count(unconditional) > 0
} else := {
	"status": "FAIL",
	"details": sprintf("Nothing stops a pull request into %s from completing while its checks fail or never run.", [lib.default_branch_name]),
	"evidence": array.concat(["no required, unfiltered build validation or status check applies to the default branch"], conditional),
}
