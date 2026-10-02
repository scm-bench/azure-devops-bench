package scmbench.rules.cis_1_1_9_test

import rego.v1

import data.scmbench.rules.cis_1_1_9
import data.scmbench.testdata

build(name, conditional) := {"kind": "build", "name": name, "conditional": conditional, "matchesDefaultBranch": true}

test_passes_with_a_required_build if {
	r := cis_1_1_9.result with input as testdata.repo_input({"requiredBuilds": [build("CI", false)]})
	r.status == "PASS"
	contains(r.details, "CI")
}

test_fails_without_any_check if {
	r := cis_1_1_9.result with input as testdata.repo_input({"requiredBuilds": []})
	r.status == "FAIL"
}

# A path-filtered build gates only the pull requests touching those paths.
test_fails_when_every_check_is_conditional if {
	r := cis_1_1_9.result with input as testdata.repo_input({"requiredBuilds": [build("docs", true)]})
	r.status == "FAIL"
	contains(r.evidence[1], "docs")
}

test_a_check_on_another_branch_does_not_count if {
	r := cis_1_1_9.result with input as testdata.repo_input({"requiredBuilds": [{"name": "CI", "matchesDefaultBranch": false}]})
	r.status == "FAIL"
}

test_manual_when_policies_are_unreadable if {
	r := cis_1_1_9.result with input as testdata.repo_input({"available": testdata.without("requiredBuilds")})
	r.status == "MANUAL"
}

test_not_applicable_on_an_empty_repository if {
	r := cis_1_1_9.result with input as testdata.input_for(testdata.empty_repo)
	r.status == "NA"
}
