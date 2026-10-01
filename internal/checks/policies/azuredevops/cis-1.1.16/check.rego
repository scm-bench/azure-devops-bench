package scmbench.rules.cis_1_1_16

import rego.v1

import data.scmbench.lib

# "fast-forward-only" is derived on every branch, because Azure Repos denies a
# force push unless it is granted; its exempt set is who holds the grant (and,
# with a required policy, the bypass a force push then also needs).
matching := lib.restrictions("fast-forward-only")

exempt := lib.restriction_set(matching[0])

result := lib.change_na if {
	lib.change_not_applicable
} else := {
	"status": "MANUAL",
	"details": "The branch policies could not be read, so force-push protection on the default branch is unknown.",
} if {
	not lib.available("branchRestrictions")
} else := {
	"status": "FAIL",
	"details": sprintf("%s can be force pushed: nothing restricts rewriting its history.", [lib.default_branch_name]),
	"evidence": ["no force-push restriction was derived for the default branch"],
} if {
	count(lib.any_restrictions("fast-forward-only")) == 0
} else := {
	"status": "MANUAL",
	"details": "The default branch could not be resolved, so who may force push it is unknown.",
} if {
	count(matching) == 0
} else := {
	"status": "FAIL",
	"details": sprintf("%s can force push %s, rewriting or erasing the history reviewers approved.", [lib.who(exempt), lib.default_branch_name]),
	"evidence": lib.bypass_evidence(exempt, "can force push"),
} if {
	lib.bypass_exceeded(exempt)
} else := {
	"status": "MANUAL",
	"details": sprintf("Who holds Force push on %s is not fully known (Git permissions unreadable, or a group could not be expanded), so whether history can be rewritten is unknown.", [lib.default_branch_name]),
} if {
	lib.bypass_undecidable(exempt)
} else := {
	"status": "PASS",
	"details": sprintf("Nobody beyond the allowed can force push %s%s.", [lib.default_branch_name, lib.allowed_note(exempt)]),
}
