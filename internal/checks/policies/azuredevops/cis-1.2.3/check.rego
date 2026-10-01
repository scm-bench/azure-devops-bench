package scmbench.rules.cis_1_2_3

import rego.v1

import data.scmbench.lib

deleters := object.get(lib.resource, "deleters", {})

admins := object.get(lib.resource, "admins", {})

# Deleters who do not also administer the repository.
outsiders := lib.principals(deleters) - lib.principals(admins)

# Whether a deleter is an administrator is only settled when the administrator
# set is complete and organization administrators were fully subtracted from
# both: otherwise someone left over might be an administrator nobody could see.
admins_settled if {
	lib.complete(admins)
	lib.available("orgAdminsExact")
}

result := {
	"status": "MANUAL",
	"details": "Who may delete or administer this repository could not be read; the token needs vso.security_manage to read Git permissions.",
} if {
	not lib.available("deleters")
} else := {
	"status": "MANUAL",
	"details": "Who may administer this repository could not be read, so whether deletion is limited to administrators is unknown.",
} if {
	not lib.available("admins")
} else := {
	"status": "FAIL",
	"details": "Every member of the organization or project can delete or disable this repository.",
	"evidence": lib.bypass_evidence(deleters, "can delete or disable"),
} if {
	lib.everyone(deleters)
} else := {
	"status": "FAIL",
	"details": sprintf("People who do not administer this repository can delete or disable it: %s.", [lib.joined([n | some n in outsiders], 5)]),
	"evidence": [sprintf("hold \"Delete or disable repository\" without Manage permissions: %s", [lib.joined([n | some n in outsiders], 10)])],
} if {
	count(outsiders) > 0
	admins_settled
} else := {
	"status": "MANUAL",
	"details": "Who may delete or administer this repository is not fully known (a group could not be expanded), so whether deletion is limited is unknown.",
} if {
	not lib.complete(deleters)
} else := {
	"status": "MANUAL",
	"details": "Some who may delete this repository could not be told apart from its administrators, because an administrator group could not be fully expanded.",
} if {
	count(outsiders) > 0
} else := {
	"status": "PASS",
	"details": sprintf("Only this repository's administrators can delete or disable it (%d people).", [count(lib.principals(deleters))]),
}
