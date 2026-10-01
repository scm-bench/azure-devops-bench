package scmbench.rules.cis_1_2_2_test

import rego.v1

import data.scmbench.rules.cis_1_2_2
import data.scmbench.testdata

org(projects, available) := testdata.input_for({
	"repositoryCreators": projects,
	"available": {"repositoryCreators": available},
})

project(name, principals, exact) := {"project": name, "principals": principals, "adminsExact": exact}

test_passes_when_only_administrators_create if {
	r := cis_1_2_2.result with input as org([project("Fabrikam", testdata.nobody, true)], true)
	r.status == "PASS"
}

test_fails_when_a_contributor_can_create if {
	r := cis_1_2_2.result with input as org([project("Fabrikam", testdata.people(["dev@fabrikam.com"]), true)], true)
	r.status == "FAIL"
	contains(r.evidence[0], "dev@fabrikam.com")
}

test_fails_when_everyone_can_create if {
	r := cis_1_2_2.result with input as org([project("Fabrikam", testdata.all_members, true)], true)
	r.status == "FAIL"
}

# A failure in one project is conclusive even when another could not be read.
test_a_known_failure_wins_over_an_unreadable_project if {
	r := cis_1_2_2.result with input as org([project("Fabrikam", testdata.people(["dev@fabrikam.com"]), true)], false)
	r.status == "FAIL"
}

# When organization administrators were not fully known, someone left in the
# set might be one of them, so a count over the limit is not proof.
test_an_inexact_subtraction_is_manual if {
	r := cis_1_2_2.result with input as org([project("Fabrikam", testdata.people(["dev@fabrikam.com"]), false)], true)
	r.status == "MANUAL"
}

test_a_partial_set_under_the_limit_is_manual if {
	r := cis_1_2_2.result with input as org([project("Fabrikam", testdata.partial([]), true)], true)
	r.status == "MANUAL"
}

test_manual_when_permissions_are_unreadable if {
	r := cis_1_2_2.result with input as org([], false)
	r.status == "MANUAL"
	contains(r.details, "vso.security_manage")
}

test_honours_the_configured_maximum if {
	r := cis_1_2_2.result with input as testdata.input_with_config(
		{"repositoryCreators": [project("Fabrikam", testdata.people(["dev@fabrikam.com"]), true)], "available": {"repositoryCreators": true}},
		{"thresholds": object.union(testdata.config.thresholds, {"maxRepositoryCreators": 1})},
	)
	r.status == "PASS"
}
