package scmbench.rules.cis_1_1_5_test

import rego.v1

import data.scmbench.rules.cis_1_1_5
import data.scmbench.testdata

test_passes_when_nobody_can_bypass if {
	r := cis_1_1_5.result with input as testdata.repo_input({"bypass": {"pullRequest": testdata.nobody}})
	r.status == "PASS"
}

test_fails_when_people_can_bypass if {
	r := cis_1_1_5.result with input as testdata.repo_input({"bypass": {"pullRequest": testdata.people(["alice@fabrikam.com"])}})
	r.status == "FAIL"
	contains(r.details, "alice@fabrikam.com")
}

# A grant to Project Valid Users reaches every member of the project.
test_fails_when_everyone_can_bypass if {
	r := cis_1_1_5.result with input as testdata.repo_input({"bypass": {"pullRequest": testdata.all_members}})
	r.status == "FAIL"
	contains(r.details, "every member")
}

# An over-threshold count from a lower bound is still conclusive.
test_a_partial_set_already_over_the_threshold_fails if {
	r := cis_1_1_5.result with input as testdata.repo_input({"bypass": {"pullRequest": testdata.partial(["bob@fabrikam.com"])}})
	r.status == "FAIL"
}

test_manual_when_an_entra_group_could_not_be_expanded if {
	r := cis_1_1_5.result with input as testdata.repo_input({"bypass": {"pullRequest": testdata.partial([])}})
	r.status == "MANUAL"
}

test_an_allowlisted_service_identity_still_passes if {
	r := cis_1_1_5.result with input as testdata.repo_input_with_config(
		{"bypass": {"pullRequest": {"serviceIdentities": ["Release Bot"], "complete": true, "count": 0}}},
		{"allowedBypassPrincipals": ["release bot"]},
	)
	r.status == "PASS"
	contains(r.details, "Release Bot")
}

test_manual_when_permissions_are_unreadable if {
	r := cis_1_1_5.result with input as testdata.repo_input({"available": testdata.without("bypass")})
	r.status == "MANUAL"
	contains(r.details, "vso.security_manage")
}

test_not_applicable_on_a_disabled_repository if {
	r := cis_1_1_5.result with input as testdata.input_for(testdata.disabled_repo)
	r.status == "NA"
}
