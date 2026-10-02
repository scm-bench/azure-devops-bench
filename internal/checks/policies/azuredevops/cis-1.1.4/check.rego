package scmbench.rules.cis_1_1_4

import rego.v1

import data.scmbench.lib

enabled := lib.pr_setting("unapproveOnUpdate", false)

# The two settings that look like this control and are not: resetting only
# rejections leaves approvals standing, and requiring one fresh approval on
# the last iteration keeps every earlier one.
near_misses := array.concat(
	[x | lib.pr_setting("resetRejectionsOnSourcePush", false) == true; x := "only votes to reject or wait are reset; approvals survive"],
	[x | lib.pr_setting("requireVoteOnLastIteration", false) == true; x := "\"Require at least one approval on the last iteration\" keeps earlier approvals"],
)

result := lib.change_na if {
	lib.change_not_applicable
} else := {
	"status": "MANUAL",
	"details": "The branch policies on the default branch could not be read, so whether approvals are reset on new pushes is unknown.",
} if {
	not lib.available("unapproveOnUpdate")
} else := {
	"status": "PASS",
	"details": sprintf("Approvals on pull requests into %s are reset when the source branch is updated.", [lib.default_branch_name]),
} if {
	enabled == true
} else := {
	"status": "FAIL",
	"details": sprintf("Approvals on pull requests into %s survive new pushes to the source branch, so code can be completed that nobody approved.", [lib.default_branch_name]),
	"evidence": array.concat(["no required minimum-reviewer policy resets approval votes"], near_misses),
}
