package scmbench.rules.cis_1_1_11

import rego.v1

import data.scmbench.lib

# requiredAllTasksComplete is the family's name; on Azure DevOps it is a
# required "Check for comment resolution" policy.
enabled := lib.pr_setting("requiredAllTasksComplete", false)

result := lib.change_na if {
	lib.change_not_applicable
} else := {
	"status": "MANUAL",
	"details": "The branch policies on the default branch could not be read, so whether comments must be resolved is unknown.",
} if {
	not lib.available("pullRequestSettings")
} else := {
	"status": "PASS",
	"details": sprintf("Pull requests into %s cannot complete while a comment is unresolved.", [lib.default_branch_name]),
} if {
	enabled == true
} else := {
	"status": "FAIL",
	"details": sprintf("Pull requests into %s can complete with comments still active, so review findings can be dropped silently.", [lib.default_branch_name]),
	"evidence": ["no required comment resolution policy applies to the default branch"],
}
