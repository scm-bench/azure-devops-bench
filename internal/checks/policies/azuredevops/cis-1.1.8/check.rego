package scmbench.rules.cis_1_1_8

import rego.v1

import data.scmbench.lib

threshold := object.get(lib.cfg, ["thresholds", "staleBranchDays"], 90)

allowed := object.get(lib.cfg, ["thresholds", "maxStaleBranches"], 0)

# The default branch is excluded: a quiet default branch means a quiet project,
# not an abandoned branch that should be pruned.
candidates := [b |
	some b in lib.list(["branches"])
	object.get(b, "isDefault", false) == false
]

stale := [b.displayId |
	some b in candidates
	object.get(b, "ageDays", -1) >= threshold
]

# A branch whose age is unknown is not a fresh branch: ageDays is -1 when the
# commit date could not be read, and comparing that against the threshold
# would quietly answer "not stale".
unknown := [b.displayId |
	some b in candidates
	object.get(b, "ageDays", -1) < 0
]

decidable if {
	lib.available("branches")
	lib.available("branchAges")
}

result := lib.change_na if {
	lib.change_not_applicable
} else := {
	"status": "MANUAL",
	"details": "The branch list or commit dates could not be read, so branch staleness is unknown.",
} if {
	not decidable
} else := {
	# Already over the limit on the branches that could be dated, so the ones
	# that could not cannot change the answer.
	"status": "FAIL",
	"details": sprintf("%d branch(es) have had no commits for %d days or more: %s.", [count(stale), threshold, lib.joined(stale, 10)]),
	"evidence": sort(stale),
} if {
	count(stale) > allowed
} else := {
	"status": "MANUAL",
	"details": sprintf("%d branch(es) report no commit date, so it is unknown whether they are abandoned: %s.", [count(unknown), lib.joined(unknown, 10)]),
	"evidence": sort(unknown),
} if {
	count(unknown) > 0
} else := {
	"status": "PASS",
	"details": sprintf("No branch other than the default has been untouched for %d days or more.", [threshold]),
}
