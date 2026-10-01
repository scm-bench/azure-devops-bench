package scmbench.rules.cis_1_2_3_test

import rego.v1

import data.scmbench.rules.cis_1_2_3
import data.scmbench.testdata

repo(deleters, admins) := testdata.repo_input({"deleters": deleters, "admins": admins})

test_passes_when_only_administrators_can_delete if {
	r := cis_1_2_3.result with input as repo(testdata.people(["lead@fabrikam.com"]), testdata.people(["lead@fabrikam.com", "dev@fabrikam.com"]))
	r.status == "PASS"
}

test_fails_when_a_non_administrator_can_delete if {
	r := cis_1_2_3.result with input as repo(testdata.people(["dev@fabrikam.com"]), testdata.people(["lead@fabrikam.com"]))
	r.status == "FAIL"
	contains(r.details, "dev@fabrikam.com")
}

test_fails_when_everyone_can_delete if {
	r := cis_1_2_3.result with input as repo(testdata.all_members, testdata.people(["lead@fabrikam.com"]))
	r.status == "FAIL"
}

test_manual_when_deleters_are_partly_known if {
	r := cis_1_2_3.result with input as repo(testdata.partial([]), testdata.people(["lead@fabrikam.com"]))
	r.status == "MANUAL"
}

# The outsider might be an administrator hidden in an unexpanded group.
test_manual_when_administrators_are_partly_known if {
	r := cis_1_2_3.result with input as repo(testdata.people(["dev@fabrikam.com"]), testdata.partial(["lead@fabrikam.com"]))
	r.status == "MANUAL"
}

test_manual_when_permissions_are_unreadable if {
	r := cis_1_2_3.result with input as testdata.repo_input({"available": testdata.without("deleters")})
	r.status == "MANUAL"
}

test_manual_when_administrators_are_unreadable if {
	r := cis_1_2_3.result with input as testdata.repo_input({"available": testdata.without("admins")})
	r.status == "MANUAL"
}

# Access controls still matter on a disabled repository: it can be re-enabled,
# and deleting it is still possible.
test_evaluated_on_a_disabled_repository if {
	r := cis_1_2_3.result with input as testdata.input_for(object.union(testdata.disabled_repo, {
		"deleters": testdata.people(["lead@fabrikam.com"]),
		"admins": testdata.people(["lead@fabrikam.com"]),
	}))
	r.status == "PASS"
}
