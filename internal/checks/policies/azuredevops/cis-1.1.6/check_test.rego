package scmbench.rules.cis_1_1_6_test

import rego.v1

import data.scmbench.rules.cis_1_1_6
import data.scmbench.testdata

test_always_needs_a_person if {
	r := cis_1_1_6.result with input as testdata.repo_input({})
	r.status == "MANUAL"
	r.evidence == []
}

test_lists_the_configured_reviewer_policies if {
	r := cis_1_1_6.result with input as testdata.repo_input({"pullRequestSettings": {"requiredReviewers": [
		{"id": 17, "blocking": true, "pathFilters": ["/sql/*"]},
		{"id": 18, "blocking": false},
	]}})
	r.status == "MANUAL"
	r.evidence == ["policy 17: required, paths /sql/*", "policy 18: optional, paths all"]
}

test_not_applicable_on_a_disabled_repository if {
	r := cis_1_1_6.result with input as testdata.input_for(testdata.disabled_repo)
	r.status == "NA"
}
