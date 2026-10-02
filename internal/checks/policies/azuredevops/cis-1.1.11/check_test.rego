package scmbench.rules.cis_1_1_11_test

import rego.v1

import data.scmbench.rules.cis_1_1_11
import data.scmbench.testdata

test_passes_when_comments_must_be_resolved if {
	r := cis_1_1_11.result with input as testdata.repo_input({"pullRequestSettings": {"requiredAllTasksComplete": true}})
	r.status == "PASS"
}

test_fails_otherwise if {
	r := cis_1_1_11.result with input as testdata.repo_input({"pullRequestSettings": {}})
	r.status == "FAIL"
}

test_manual_when_policies_are_unreadable if {
	r := cis_1_1_11.result with input as testdata.repo_input({"available": testdata.without("pullRequestSettings")})
	r.status == "MANUAL"
}

test_not_applicable_on_a_disabled_repository if {
	r := cis_1_1_11.result with input as testdata.input_for(testdata.disabled_repo)
	r.status == "NA"
}
