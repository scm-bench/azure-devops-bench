package scmbench.rules.cis_1_1_12

import rego.v1

import data.scmbench.lib

# Which status verifies signatures is a fact about the deployment, so it comes
# from the config. Blank entries are dropped here as well as refused at
# startup: a caller building a Config in Go never passes through that check,
# and a blank name must never match a status that happens to have none.
configured := {lower(trim_space(c)) |
	some c in lib.as_list(object.get(lib.cfg, "signatureStatusChecks", []))
	trim_space(c) != ""
}

# "genre/name" matches exactly; a bare "name" matches whatever genre posts it.
names_status(name) if lower(name) in configured

names_status(name) if {
	parts := split(name, "/")
	count(parts) > 1
	lower(parts[count(parts) - 1]) in configured
}

# Only an unconditional status counts: a conditional one applies once posted,
# so a pull request the verifier never looks at completes without it.
verifying := [c.name |
	some c in lib.list("requiredBuilds")
	c.matchesDefaultBranch == true
	object.get(c, "kind", "") == "status"
	object.get(c, "conditional", false) == false
	names_status(object.get(c, "name", ""))
]

statuses := [c.name |
	some c in lib.list("requiredBuilds")
	c.matchesDefaultBranch == true
	object.get(c, "kind", "") == "status"
]

config_note := "signatureStatusChecks is empty, so no status is known to verify signatures" if {
	count(configured) == 0
} else := sprintf("signatureStatusChecks names: %s", [lib.joined([c | some c in configured], 5)])

result := lib.change_na if {
	lib.change_not_applicable
} else := {
	"status": "MANUAL",
	"details": "The branch policies on the default branch could not be read, so signature verification cannot be confirmed.",
} if {
	not lib.available("requiredBuilds")
} else := {
	"status": "PASS",
	"details": sprintf("Pull requests into %s wait for a required signature-verification status: %s.", [lib.default_branch_name, lib.joined(verifying, 3)]),
} if {
	count(verifying) > 0
} else := {
	"status": "FAIL",
	"details": sprintf("Nothing verifies commit signatures before changes reach %s: Azure Repos cannot verify them itself, and no required status check named in signatureStatusChecks applies.", [lib.default_branch_name]),
	"evidence": array.concat([config_note], [sprintf("required status checks on the branch: %s", [lib.joined(statuses, 5)]) | count(statuses) > 0]),
}
