package scmbench.rules.cis_1_1_3_test

import rego.v1

import data.scmbench.rules.cis_1_1_3
import data.scmbench.testdata

test_passes_with_two_independent_approvals if {
	r := cis_1_1_3.result with input as testdata.repo_input({"pullRequestSettings": {"requiredApprovers": 2, "minimumApproverCount": 2}})
	r.status == "PASS"
}

test_fails_with_one_approval if {
	r := cis_1_1_3.result with input as testdata.repo_input({"pullRequestSettings": {"requiredApprovers": 1, "minimumApproverCount": 1}})
	r.status == "FAIL"
	contains(r.details, "at least 2")
}

# A minimum of two that counts the author's own vote is one reviewer and the
# author: the fetcher records one independent approval, and the evidence says
# why the number is lower than the setting.
test_the_authors_own_vote_does_not_count if {
	r := cis_1_1_3.result with input as testdata.repo_input({"pullRequestSettings": {
		"requiredApprovers": 1,
		"minimumApproverCount": 2,
		"authorApprovalCounts": true,
	}})
	r.status == "FAIL"
	contains(r.evidence[0], "minimumApproverCount 2")
	contains(r.evidence[1], "author's own vote")
}

test_fails_when_no_reviewer_policy_exists if {
	r := cis_1_1_3.result with input as testdata.repo_input({"pullRequestSettings": {}})
	r.status == "FAIL"
}

test_honours_the_configured_minimum if {
	r := cis_1_1_3.result with input as testdata.repo_input_with_config(
		{"pullRequestSettings": {"requiredApprovers": 1}},
		{"thresholds": object.union(testdata.config.thresholds, {"minApprovers": 1})},
	)
	r.status == "PASS"
}

test_manual_when_policies_are_unreadable if {
	r := cis_1_1_3.result with input as testdata.repo_input({"available": testdata.without("pullRequestSettings")})
	r.status == "MANUAL"
}

test_not_applicable_on_a_disabled_repository if {
	r := cis_1_1_3.result with input as testdata.input_for(testdata.disabled_repo)
	r.status == "NA"
}
