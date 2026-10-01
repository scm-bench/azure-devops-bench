package scmbench.rules.cis_1_1_3

import rego.v1

import data.scmbench.lib

# requiredApprovers already counts independent approvals: the fetcher takes one
# off a policy that lets the author's own vote count toward its minimum.
required := lib.pr_setting("requiredApprovers", 0)

raw := lib.pr_setting("minimumApproverCount", 0)

minimum := object.get(lib.cfg, ["thresholds", "minApprovers"], 2)

author_note := ["\"Allow requestors to approve their own changes\" is on, so the author's own vote counts toward the minimum"] if {
	lib.pr_setting("authorApprovalCounts", false) == true
} else := []

evidence := array.concat(
	[sprintf("independent approvals required: %d (minimumApproverCount %d)", [required, raw])],
	author_note,
)

result := lib.change_na if {
	lib.change_not_applicable
} else := {
	"status": "MANUAL",
	"details": "The branch policies on the default branch could not be read, so the required approval count is unknown.",
} if {
	not lib.available("pullRequestSettings")
} else := {
	"status": "PASS",
	"details": sprintf("Pull requests into %s require %d independent approval(s), meeting the minimum of %d.", [lib.default_branch_name, required, minimum]),
} if {
	required >= minimum
} else := {
	"status": "FAIL",
	"details": sprintf("Pull requests into %s require %d independent approval(s); at least %d are needed.", [lib.default_branch_name, required, minimum]),
	"evidence": evidence,
}
