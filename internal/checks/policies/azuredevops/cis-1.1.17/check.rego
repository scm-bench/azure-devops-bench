package scmbench.rules.cis_1_1_17

import rego.v1

import data.scmbench.lib

# "no-deletes" is derived: present when a required branch policy applies,
# exempting holders of both Force push and "Bypass policies when pushing".
matching := lib.restrictions("no-deletes")

exempt := lib.restriction_set(matching[0])

result := lib.change_na if {
	lib.change_not_applicable
} else := {
	"status": "MANUAL",
	"details": "The branch policies could not be read, so deletion protection on the default branch is unknown.",
} if {
	not lib.available("branchRestrictions")
} else := {
	"status": "FAIL",
	"details": sprintf("No required branch policy applies to %s, so anyone holding Force push — its creator included — can delete it.", [lib.default_branch_name]),
	"evidence": ["no Required branch policy covers the default branch"],
} if {
	count(lib.any_restrictions("no-deletes")) == 0
} else := {
	"status": "MANUAL",
	"details": "Required branch policies exist in this repository, but the default branch could not be resolved, so whether they protect it from deletion is unknown.",
} if {
	count(matching) == 0
} else := {
	"status": "FAIL",
	"details": sprintf("Deleting %s is refused by its required policies, but %s can still delete it.", [lib.default_branch_name, lib.who(exempt)]),
	"evidence": lib.bypass_evidence(exempt, "hold Force push and Bypass policies when pushing"),
} if {
	lib.bypass_exceeded(exempt)
} else := {
	"status": "MANUAL",
	"details": sprintf("Deleting %s is refused by its required policies, but who holds both Force push and the push bypass is not fully known, so whether anyone can still delete it is unknown.", [lib.default_branch_name]),
} if {
	lib.bypass_undecidable(exempt)
} else := {
	"status": "PASS",
	"details": sprintf("%s cannot be deleted%s.", [lib.default_branch_name, lib.allowed_note(exempt)]),
}
