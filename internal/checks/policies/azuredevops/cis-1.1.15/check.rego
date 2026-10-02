package scmbench.rules.cis_1_1_15

import rego.v1

import data.scmbench.lib

# "pull-request-only" is derived: present when a required branch policy
# applies, exempting holders of "Bypass policies when pushing".
matching := lib.restrictions("pull-request-only")

exempt := lib.restriction_set(matching[0])

result := lib.change_na if {
	lib.change_not_applicable
} else := {
	"status": "MANUAL",
	"details": "The branch policies could not be read, so whether pull requests are required on the default branch is unknown.",
} if {
	not lib.available("branchRestrictions")
} else := {
	# Conclusive even when the default branch could not be resolved: no
	# required branch policy covers any branch of this repository.
	"status": "FAIL",
	"details": sprintf("No required branch policy applies to %s, so Azure Repos lets anyone with Contribute push straight to it, bypassing pull request review entirely.", [lib.default_branch_name]),
	"evidence": ["no Required branch policy covers the default branch"],
} if {
	count(lib.any_restrictions("pull-request-only")) == 0
} else := {
	"status": "MANUAL",
	"details": "Required branch policies exist in this repository, but the default branch could not be resolved, so whether they cover it is unknown.",
} if {
	count(matching) == 0
} else := {
	"status": "FAIL",
	"details": sprintf("Pull requests are required on %s, but %s can push straight past its policies.", [lib.default_branch_name, lib.who(exempt)]),
	"evidence": lib.bypass_evidence(exempt, "holders of Bypass policies when pushing"),
} if {
	lib.bypass_exceeded(exempt)
} else := {
	"status": "MANUAL",
	"details": sprintf("Pull requests are required on %s, but who holds \"Bypass policies when pushing\" is not fully known (Git permissions unreadable, or a group could not be expanded), so whether the requirement binds everyone is unknown.", [lib.default_branch_name]),
} if {
	lib.bypass_undecidable(exempt)
} else := {
	"status": "PASS",
	"details": sprintf("Changes reach %s only through pull requests%s.", [lib.default_branch_name, lib.allowed_note(exempt)]),
}
