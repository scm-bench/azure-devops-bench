package scmbench.rules.cis_1_1_15_test

import rego.v1

import data.scmbench.rules.cis_1_1_15
import data.scmbench.testdata

pr_only(exempt) := testdata.repo_input({"branchRestrictions": [testdata.restriction("pull-request-only", exempt)]})

test_passes_when_required_and_nobody_bypasses if {
	r := cis_1_1_15.result with input as pr_only(testdata.nobody)
	r.status == "PASS"
}

test_fails_without_a_required_policy if {
	r := cis_1_1_15.result with input as testdata.repo_input({"branchRestrictions": [testdata.restriction("fast-forward-only", testdata.nobody)]})
	r.status == "FAIL"
	contains(r.details, "push straight to it")
}

# Even with the default branch unresolved: no required policy anywhere in the
# repository is conclusive.
test_no_required_policy_fails_even_without_a_default_branch if {
	r := cis_1_1_15.result with input as testdata.input_for({
		"available": testdata.without("defaultBranch"),
		"branchRestrictions": [testdata.unknown_restriction("fast-forward-only")],
	})
	r.status == "FAIL"
}

test_unknown_coverage_is_manual if {
	r := cis_1_1_15.result with input as testdata.input_for({
		"available": testdata.without("defaultBranch"),
		"branchRestrictions": [testdata.unknown_restriction("pull-request-only")],
	})
	r.status == "MANUAL"
}

test_fails_when_people_can_push_past_it if {
	r := cis_1_1_15.result with input as pr_only(testdata.people(["alice@fabrikam.com", "bob@fabrikam.com"]))
	r.status == "FAIL"
	contains(r.details, "alice@fabrikam.com")
}

# Git permissions unreadable: the requirement exists, its bypass is unknown.
test_manual_when_the_bypass_is_unknown if {
	r := cis_1_1_15.result with input as pr_only({"complete": false, "count": 0})
	r.status == "MANUAL"
}

test_an_allowlisted_build_service_still_passes if {
	r := cis_1_1_15.result with input as testdata.repo_input_with_config(
		{"branchRestrictions": [testdata.restriction("pull-request-only", {"serviceIdentities": ["Build Service (fabrikam)"], "complete": true, "count": 0})]},
		{"allowedBypassPrincipals": ["Build Service (fabrikam)"]},
	)
	r.status == "PASS"
	contains(r.details, "Build Service")
}

test_manual_when_policies_are_unreadable if {
	r := cis_1_1_15.result with input as testdata.repo_input({"available": testdata.without("branchRestrictions")})
	r.status == "MANUAL"
}

test_null_restrictions_do_not_break_the_rule if {
	r := cis_1_1_15.result with input as testdata.repo_input({"branchRestrictions": null})
	r.status == "FAIL"
}

test_not_applicable_on_an_empty_repository if {
	r := cis_1_1_15.result with input as testdata.input_for(testdata.empty_repo)
	r.status == "NA"
}
