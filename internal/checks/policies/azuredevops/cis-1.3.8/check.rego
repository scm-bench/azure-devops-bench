package scmbench.rules.cis_1_3_8

import rego.v1

import data.scmbench.lib

allowed := {p | some p in lib.as_list(object.get(lib.cfg, "everyoneAllowedPermissions", ["GenericRead"]))}

public := object.get(lib.resource, "public", false)

allow_public := object.get(lib.cfg, "allowPublicRepositories", false)

anonymous := ["the project is public, so anyone can read this repository without signing in"] if {
	lib.available("visibility")
	public == true
	allow_public != true
} else := []

blanket := [sprintf("%s holds %s", [g.name, g.permission]) |
	some g in lib.list(["permissions", "everyoneGrants"])
	not g.permission in allowed
]

violations := array.concat(anonymous, blanket)

# A violation already seen is conclusive whatever else is unknown: public
# visibility needs no access control list, and a blanket grant found is found.
result := {
	"status": "FAIL",
	"details": sprintf("Access to this repository is broader than intended: %s.", [concat("; ", violations)]),
	"evidence": violations,
} if {
	count(violations) > 0
} else := {
	"status": "MANUAL",
	"details": "The project did not report its visibility, so whether anyone can read this repository anonymously is unknown.",
} if {
	not lib.available("visibility")
} else := {
	"status": "MANUAL",
	"details": "The Git permissions of the groups every member belongs to could not be read (the token needs vso.security_manage), so blanket access is unknown.",
} if {
	not lib.available("permissions")
} else := {
	"status": "PASS",
	"details": sprintf("The repository is not public, and the groups every member belongs to hold nothing beyond %s.", [concat(", ", sort([p | some p in allowed]))]),
}
