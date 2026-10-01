package scmbench.rules.cis_1_1_2_test

import rego.v1

import data.scmbench.rules.cis_1_1_2
import data.scmbench.testdata

test_passes_when_a_required_policy_applies if {
	r := cis_1_1_2.result with input as testdata.repo_input({"pullRequestSettings": {"workItemLinkingRequired": true}})
	r.status == "PASS"
}

test_fails_without_a_policy if {
	r := cis_1_1_2.result with input as testdata.repo_input({"pullRequestSettings": {}})
	r.status == "FAIL"
	r.evidence == ["no required work item linking policy applies to the default branch"]
}

# Optional warns and completes anyway, so it is not the control.
test_an_optional_policy_still_fails_and_says_so if {
	r := cis_1_1_2.result with input as testdata.repo_input({
		"pullRequestSettings": {},
		"policies": [{"id": 7, "typeId": "40e92b44-2fe1-4dd6-b3d8-74a9c21d0c6e", "blocking": false}],
	})
	r.status == "FAIL"
	contains(r.evidence[0], "policy 7 is optional")
}

test_manual_when_policies_are_unreadable if {
	r := cis_1_1_2.result with input as testdata.repo_input({"available": testdata.without("pullRequestSettings")})
	r.status == "MANUAL"
}

test_not_applicable_on_a_disabled_repository if {
	r := cis_1_1_2.result with input as testdata.input_for(testdata.disabled_repo)
	r.status == "NA"
	contains(r.details, "disabled")
}

test_not_applicable_on_an_empty_repository if {
	r := cis_1_1_2.result with input as testdata.input_for(testdata.empty_repo)
	r.status == "NA"
	contains(r.details, "no branches")
}
