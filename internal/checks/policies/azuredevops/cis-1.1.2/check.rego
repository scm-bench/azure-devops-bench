package scmbench.rules.cis_1_1_2

import rego.v1

import data.scmbench.lib

required := lib.pr_setting("workItemLinkingRequired", false)

# An optional work item linking policy warns and still lets the pull request
# complete; it is named in the evidence because it is the most common way this
# control is believed to be met when it is not.
optional := [p.id |
	some p in lib.list("policies")
	p.typeId == "40e92b44-2fe1-4dd6-b3d8-74a9c21d0c6e"
	p.blocking == false
]

result := lib.change_na if {
	lib.change_not_applicable
} else := {
	"status": "MANUAL",
	"details": "The branch policies on the default branch could not be read, so whether pull requests must link a work item is unknown.",
} if {
	not lib.available("pullRequestSettings")
} else := {
	"status": "PASS",
	"details": sprintf("Pull requests into %s cannot complete without a linked work item.", [lib.default_branch_name]),
} if {
	required == true
} else := {
	"status": "FAIL",
	"details": sprintf("Pull requests into %s can complete without a linked work item, so a change need not say what it is for.", [lib.default_branch_name]),
	"evidence": evidence,
}

evidence := [sprintf("work item linking policy %d is optional, which only warns", [id]) | some id in optional] if {
	count(optional) > 0
} else := ["no required work item linking policy applies to the default branch"]
