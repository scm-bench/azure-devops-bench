package scmbench.rules.cis_1_2_1_test

import rego.v1

import data.scmbench.rules.cis_1_2_1
import data.scmbench.testdata

test_passes_when_a_policy_is_found if {
	r := cis_1_2_1.result with input as testdata.repo_input({"files": {"securityPolicyPaths": [".github/SECURITY.md"], "probed": ["SECURITY.md", ".github/SECURITY.md"]}})
	r.status == "PASS"
	contains(r.details, ".github/SECURITY.md")
}

test_fails_when_none_is_found if {
	r := cis_1_2_1.result with input as testdata.repo_input({"files": {"probed": ["SECURITY.md", ".github/SECURITY.md"]}})
	r.status == "FAIL"
	contains(r.evidence[0], ".github/SECURITY.md")
}

test_manual_when_the_branch_could_not_be_browsed if {
	r := cis_1_2_1.result with input as testdata.repo_input({"available": testdata.without("files")})
	r.status == "MANUAL"
}

test_null_lists_do_not_break_the_rule if {
	r := cis_1_2_1.result with input as testdata.repo_input({"files": {"securityPolicyPaths": null, "probed": null}})
	r.status == "FAIL"
}

test_not_applicable_on_an_empty_repository if {
	r := cis_1_2_1.result with input as testdata.input_for(testdata.empty_repo)
	r.status == "NA"
}
