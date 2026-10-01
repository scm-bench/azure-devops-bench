package scmbench.rules.cis_1_1_17_test

import rego.v1

import data.scmbench.rules.cis_1_1_17
import data.scmbench.testdata

no_deletes(exempt) := testdata.repo_input({"branchRestrictions": [testdata.restriction("no-deletes", exempt)]})

test_passes_when_required_and_nobody_is_exempt if {
	r := cis_1_1_17.result with input as no_deletes(testdata.nobody)
	r.status == "PASS"
}

test_fails_without_a_required_policy if {
	r := cis_1_1_17.result with input as testdata.repo_input({"branchRestrictions": []})
	r.status == "FAIL"
	contains(r.details, "can delete it")
}

test_fails_when_someone_holds_both_permissions if {
	r := cis_1_1_17.result with input as no_deletes(testdata.people(["alice@fabrikam.com"]))
	r.status == "FAIL"
}

test_manual_when_holders_are_unknown if {
	r := cis_1_1_17.result with input as no_deletes(testdata.partial([]))
	r.status == "MANUAL"
}

test_unresolved_default_branch_is_manual if {
	r := cis_1_1_17.result with input as testdata.input_for({
		"available": testdata.without("defaultBranch"),
		"branchRestrictions": [testdata.unknown_restriction("no-deletes")],
	})
	r.status == "MANUAL"
}

test_manual_when_policies_are_unreadable if {
	r := cis_1_1_17.result with input as testdata.repo_input({"available": testdata.without("branchRestrictions")})
	r.status == "MANUAL"
}

test_not_applicable_on_an_empty_repository if {
	r := cis_1_1_17.result with input as testdata.input_for(testdata.empty_repo)
	r.status == "NA"
}
