package scmbench.rules.cis_1_5_1

import rego.v1

import data.scmbench.lib

ghas := object.get(lib.resource, "advancedSecurity", {})

unavailable_details := "GitHub Advanced Security for Azure DevOps exists only on Azure DevOps Services, so push protection for secrets cannot be read here; confirm by hand that a secret scanner gates changes." if {
	lib.server_deployment
} else := "Advanced Security enablement could not be read for this repository (the token needs vso.advsec), so secret push protection is unknown."

result := {
	"status": "NA",
	"details": "The repository is disabled, so Azure DevOps accepts no push to it; re-enabling it brings this control back.",
} if {
	lib.archived_repository
} else := {
	"status": "MANUAL",
	"details": unavailable_details,
} if {
	not lib.available("advancedSecurity")
} else := {
	"status": "FAIL",
	"details": "Secret scanning is off for this repository, so a pushed credential is neither stopped nor reported.",
	"evidence": ["Advanced Security secret protection is disabled"],
} if {
	object.get(ghas, "secretProtection", false) != true
} else := {
	"status": "MANUAL",
	"details": "Secret scanning is on, but whether pushes containing secrets are blocked was not reported.",
} if {
	object.get(ghas, "blockPushesKnown", false) != true
} else := {
	"status": "FAIL",
	"details": "Secrets are detected after they are pushed but not blocked, so they reach the repository's history before anyone acts.",
	"evidence": ["Advanced Security secret protection is on; \"Block secrets on push\" is off"],
} if {
	object.get(ghas, "blockPushes", false) != true
} else := {
	"status": "PASS",
	"details": "Pushes containing secrets are rejected by GitHub Advanced Security push protection.",
}
