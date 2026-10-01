package scmbench.rules.cis_1_1_4_test

import rego.v1

import data.scmbench.rules.cis_1_1_4
import data.scmbench.testdata

test_passes_when_approvals_reset if {
	r := cis_1_1_4.result with input as testdata.repo_input({"pullRequestSettings": {"unapproveOnUpdate": true}})
	r.status == "PASS"
}

test_fails_when_approvals_survive if {
	r := cis_1_1_4.result with input as testdata.repo_input({"pullRequestSettings": {}})
	r.status == "FAIL"
	count(r.evidence) == 1
}

# Resetting rejections alone is the setting most often mistaken for this one.
test_resetting_only_rejections_is_named_as_a_near_miss if {
	r := cis_1_1_4.result with input as testdata.repo_input({"pullRequestSettings": {
		"resetRejectionsOnSourcePush": true,
		"requireVoteOnLastIteration": true,
	}})
	r.status == "FAIL"
	count(r.evidence) == 3
}

test_manual_when_the_setting_is_unknown if {
	r := cis_1_1_4.result with input as testdata.repo_input({"available": testdata.without("unapproveOnUpdate")})
	r.status == "MANUAL"
}

test_not_applicable_on_an_empty_repository if {
	r := cis_1_1_4.result with input as testdata.input_for(testdata.empty_repo)
	r.status == "NA"
}
