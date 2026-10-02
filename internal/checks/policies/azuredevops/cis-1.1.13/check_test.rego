package scmbench.rules.cis_1_1_13_test

import rego.v1

import data.scmbench.rules.cis_1_1_13
import data.scmbench.testdata

strategies(allowed) := testdata.repo_input({"pullRequestSettings": {"mergeStrategies": [
	{"id": "no-ff", "enabled": "no-ff" in allowed},
	{"id": "squash", "enabled": "squash" in allowed},
	{"id": "rebase-ff-only", "enabled": "rebase-ff-only" in allowed},
	{"id": "rebase-no-ff", "enabled": "rebase-no-ff" in allowed},
]}})

test_passes_with_squash_and_rebase_only if {
	r := cis_1_1_13.result with input as strategies({"squash", "rebase-ff-only"})
	r.status == "PASS"
}

# No merge-type policy means every type is allowed, basic merge included.
test_fails_when_every_type_is_allowed if {
	r := cis_1_1_13.result with input as strategies({"no-ff", "squash", "rebase-ff-only", "rebase-no-ff"})
	r.status == "FAIL"
	contains(r.details, "no-ff, rebase-no-ff")
}

test_the_semi_linear_merge_also_fails if {
	r := cis_1_1_13.result with input as strategies({"rebase-no-ff"})
	r.status == "FAIL"
}

test_manual_when_merge_types_are_unknown if {
	r := cis_1_1_13.result with input as testdata.repo_input({"available": testdata.without("mergeStrategies")})
	r.status == "MANUAL"
}

test_not_applicable_on_a_disabled_repository if {
	r := cis_1_1_13.result with input as testdata.input_for(testdata.disabled_repo)
	r.status == "NA"
}
