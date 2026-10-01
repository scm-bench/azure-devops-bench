package scmbench.rules.cis_1_1_12_test

import rego.v1

import data.scmbench.rules.cis_1_1_12
import data.scmbench.testdata

status(name, conditional) := {"kind": "status", "name": name, "conditional": conditional, "matchesDefaultBranch": true}

with_checks(builds, names) := testdata.repo_input_with_config({"requiredBuilds": builds}, {"signatureStatusChecks": names})

test_passes_with_a_named_required_status if {
	r := cis_1_1_12.result with input as with_checks([status("security/verify-signatures", false)], ["security/verify-signatures"])
	r.status == "PASS"
}

# A bare name in the config matches whichever genre posts it.
test_a_bare_name_matches_any_genre if {
	r := cis_1_1_12.result with input as with_checks([status("security/Verify-Signatures", false)], ["verify-signatures"])
	r.status == "PASS"
}

# Nothing on Azure Repos verifies signatures, so with nothing configured the
# control fails and says why.
test_fails_when_nothing_is_configured if {
	r := cis_1_1_12.result with input as testdata.repo_input({"requiredBuilds": [status("security/verify-signatures", false)]})
	r.status == "FAIL"
	contains(r.evidence[0], "signatureStatusChecks is empty")
	contains(r.evidence[1], "security/verify-signatures")
}

test_fails_when_the_named_status_is_not_required if {
	r := cis_1_1_12.result with input as with_checks([], ["verify-signatures"])
	r.status == "FAIL"
	count(r.evidence) == 1
}

# A conditional status applies only once posted, so it enforces nothing on a
# pull request the verifier never saw.
test_a_conditional_status_does_not_count if {
	r := cis_1_1_12.result with input as with_checks([status("security/verify-signatures", true)], ["verify-signatures"])
	r.status == "FAIL"
}

# A build with the same name is not a status anybody posts.
test_a_build_named_like_the_status_does_not_count if {
	r := cis_1_1_12.result with input as with_checks([{"kind": "build", "name": "verify-signatures", "matchesDefaultBranch": true}], ["verify-signatures"])
	r.status == "FAIL"
}

# config.Validate refuses a blank entry; this is the second lock on that door.
test_a_blank_configured_name_matches_nothing if {
	r := cis_1_1_12.result with input as with_checks([status("", false)], ["  "])
	r.status == "FAIL"
}

test_manual_when_policies_are_unreadable if {
	r := cis_1_1_12.result with input as testdata.repo_input({"available": testdata.without("requiredBuilds")})
	r.status == "MANUAL"
}

test_not_applicable_on_an_empty_repository if {
	r := cis_1_1_12.result with input as testdata.input_for(testdata.empty_repo)
	r.status == "NA"
}
