package scmbench.rules.cis_1_1_8_test

import rego.v1

import data.scmbench.rules.cis_1_1_8
import data.scmbench.testdata

branches(list) := testdata.repo_input({"branches": list})

test_passes_with_only_fresh_branches if {
	r := cis_1_1_8.result with input as branches([
		{"displayId": "main", "isDefault": true, "ageDays": 500},
		{"displayId": "feature/x", "ageDays": 3},
	])
	r.status == "PASS"
}

test_fails_with_an_abandoned_branch if {
	r := cis_1_1_8.result with input as branches([{"displayId": "old", "ageDays": 400}])
	r.status == "FAIL"
	r.evidence == ["old"]
}

test_unknown_ages_are_manual if {
	r := cis_1_1_8.result with input as branches([{"displayId": "mystery", "ageDays": -1}])
	r.status == "MANUAL"
	r.evidence == ["mystery"]
}

# Already over the limit, so the undated branch cannot change the answer.
test_a_known_failure_wins_over_unknown_ages if {
	r := cis_1_1_8.result with input as branches([
		{"displayId": "old", "ageDays": 400},
		{"displayId": "mystery", "ageDays": -1},
	])
	r.status == "FAIL"
}

test_manual_when_ages_are_unreadable if {
	r := cis_1_1_8.result with input as testdata.repo_input({"available": testdata.without("branchAges")})
	r.status == "MANUAL"
}

test_tolerates_a_null_branch_list if {
	r := cis_1_1_8.result with input as branches(null)
	r.status == "PASS"
}

test_not_applicable_on_an_empty_repository if {
	r := cis_1_1_8.result with input as testdata.input_for(testdata.empty_repo)
	r.status == "NA"
}
