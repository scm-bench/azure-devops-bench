package scmbench.rules.cis_1_1_16_test

import rego.v1

import data.scmbench.rules.cis_1_1_16
import data.scmbench.testdata

ffo(exempt) := testdata.repo_input({"branchRestrictions": [testdata.restriction("fast-forward-only", exempt)]})

test_passes_when_nobody_holds_force_push if {
	r := cis_1_1_16.result with input as ffo(testdata.nobody)
	r.status == "PASS"
}

# The branch's creator is granted Force push on it, and is the most common
# holder found.
test_fails_when_the_creator_can_still_force_push if {
	r := cis_1_1_16.result with input as ffo(testdata.people(["creator@fabrikam.com"]))
	r.status == "FAIL"
	contains(r.details, "creator@fabrikam.com")
}

test_manual_when_holders_are_unknown if {
	r := cis_1_1_16.result with input as ffo({"complete": false})
	r.status == "MANUAL"
}

test_unresolved_default_branch_is_manual if {
	r := cis_1_1_16.result with input as testdata.input_for({
		"available": testdata.without("defaultBranch"),
		"branchRestrictions": [testdata.unknown_restriction("fast-forward-only")],
	})
	r.status == "MANUAL"
}

# The fetcher always derives the restriction; its absence is a snapshot from
# some other producer, and nothing then denies a force push.
test_fails_without_a_restriction if {
	r := cis_1_1_16.result with input as testdata.repo_input({"branchRestrictions": []})
	r.status == "FAIL"
}

test_manual_when_policies_are_unreadable if {
	r := cis_1_1_16.result with input as testdata.repo_input({"available": testdata.without("branchRestrictions")})
	r.status == "MANUAL"
}

test_not_applicable_on_a_disabled_repository if {
	r := cis_1_1_16.result with input as testdata.input_for(testdata.disabled_repo)
	r.status == "NA"
}
