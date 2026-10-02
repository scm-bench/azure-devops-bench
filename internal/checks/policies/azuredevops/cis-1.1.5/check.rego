package scmbench.rules.cis_1_1_5

import rego.v1

import data.scmbench.lib

holders := object.get(lib.resource, ["bypass", "pullRequest"], {})

result := lib.change_na if {
	lib.change_not_applicable
} else := {
	"status": "MANUAL",
	"details": sprintf("Who may complete pull requests into %s past its policies could not be read; the token needs vso.security_manage to read Git permissions.", [lib.default_branch_name]),
} if {
	not lib.available("bypass")
} else := {
	"status": "FAIL",
	"details": sprintf("%s can complete pull requests into %s without the approvals and checks its policies require.", [lib.who(holders), lib.default_branch_name]),
	"evidence": lib.bypass_evidence(holders, "Bypass policies when completing pull requests"),
} if {
	lib.bypass_exceeded(holders)
} else := {
	"status": "MANUAL",
	"details": sprintf("A group holding \"Bypass policies when completing pull requests\" on %s could not be fully expanded, so whether anyone can skip review is unknown.", [lib.default_branch_name]),
	"evidence": lib.bypass_evidence(holders, "known holders"),
} if {
	lib.bypass_undecidable(holders)
} else := {
	"status": "PASS",
	"details": sprintf("Nobody beyond the allowed can complete a pull request into %s past its policies%s.", [lib.default_branch_name, lib.allowed_note(holders)]),
}
