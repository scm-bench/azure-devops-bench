package scmbench.rules.cis_1_1_14

import rego.v1

import data.scmbench.lib

# The administrators among the holders of either bypass, resolved by the
# fetcher: organization administrators, and holders of Manage permissions on
# the repository.
admins := object.get(lib.resource, ["bypass", "admins"], {})

holding := lib.bypassers(admins)

result := lib.change_na if {
	lib.change_not_applicable
} else := {
	"status": "MANUAL",
	"details": sprintf("Who may bypass the policies on %s could not be read; the token needs vso.security_manage to read Git permissions.", [lib.default_branch_name]),
} if {
	not lib.available("bypass")
} else := {
	"status": "FAIL",
	"details": sprintf("Administrators can bypass the policies on %s: %s.", [lib.default_branch_name, lib.who(admins)]),
	"evidence": lib.bypass_evidence(admins, "administrators holding a bypass"),
} if {
	lib.everyone(admins)
} else := {
	"status": "FAIL",
	"details": sprintf("Administrators can bypass the policies on %s: %s.", [lib.default_branch_name, lib.joined([n | some n in holding], 5)]),
	"evidence": lib.bypass_evidence(admins, "administrators holding a bypass"),
} if {
	count(holding) > 0
} else := {
	"status": "MANUAL",
	"details": sprintf("An administrator group or a bypass group on %s could not be fully expanded, so whether an administrator holds a bypass is unknown.", [lib.default_branch_name]),
} if {
	not lib.complete(admins)
} else := {
	"status": "PASS",
	"details": sprintf("No administrator holds a bypass of the policies on %s%s.", [lib.default_branch_name, lib.allowed_note(admins)]),
}
