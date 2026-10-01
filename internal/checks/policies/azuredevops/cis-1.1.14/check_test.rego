package scmbench.rules.cis_1_1_14_test

import rego.v1

import data.scmbench.rules.cis_1_1_14
import data.scmbench.testdata

test_passes_when_no_administrator_holds_a_bypass if {
	r := cis_1_1_14.result with input as testdata.repo_input({"bypass": {"admins": testdata.nobody}})
	r.status == "PASS"
}

test_fails_when_an_administrator_holds_one if {
	r := cis_1_1_14.result with input as testdata.repo_input({"bypass": {"admins": testdata.people(["owner@fabrikam.com"])}})
	r.status == "FAIL"
	contains(r.details, "owner@fabrikam.com")
}

test_fails_when_everyone_holds_one if {
	r := cis_1_1_14.result with input as testdata.repo_input({"bypass": {"admins": testdata.all_members}})
	r.status == "FAIL"
	contains(r.details, "every member")
}

# One administrator already found is conclusive, whatever else is hidden.
test_a_partial_set_with_a_holder_still_fails if {
	r := cis_1_1_14.result with input as testdata.repo_input({"bypass": {"admins": testdata.partial(["owner@fabrikam.com"])}})
	r.status == "FAIL"
}

test_manual_when_a_group_could_not_be_expanded if {
	r := cis_1_1_14.result with input as testdata.repo_input({"bypass": {"admins": testdata.partial([])}})
	r.status == "MANUAL"
}

test_an_allowlisted_service_identity_passes if {
	r := cis_1_1_14.result with input as testdata.repo_input_with_config(
		{"bypass": {"admins": {"serviceIdentities": ["Release Bot"], "complete": true}}},
		{"allowedBypassPrincipals": ["Release Bot"]},
	)
	r.status == "PASS"
}

test_manual_when_permissions_are_unreadable if {
	r := cis_1_1_14.result with input as testdata.repo_input({"available": testdata.without("bypass")})
	r.status == "MANUAL"
}

test_not_applicable_on_a_disabled_repository if {
	r := cis_1_1_14.result with input as testdata.input_for(testdata.disabled_repo)
	r.status == "NA"
}
