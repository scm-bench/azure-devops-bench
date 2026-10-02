package scmbench.rules.cis_1_2_1

import rego.v1

import data.scmbench.lib

found := lib.list(["files", "securityPolicyPaths"])

probed := lib.list(["files", "probed"])

result := lib.change_na if {
	lib.change_not_applicable
} else := {
	"status": "MANUAL",
	"details": "The default branch could not be browsed, so the presence of a security policy is unknown.",
} if {
	not lib.available("files")
} else := {
	"status": "PASS",
	"details": sprintf("A security policy is published at %s.", [concat(", ", found)]),
} if {
	count(found) > 0
} else := {
	"status": "FAIL",
	"details": "No security policy file was found, so there is no documented way to report a vulnerability in this code.",
	"evidence": [sprintf("paths checked on the default branch: %s", [concat(", ", probed)])],
}
