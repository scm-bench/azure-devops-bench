package scmbench.rules.cis_1_3_7_test

import rego.v1

import data.scmbench.rules.cis_1_3_7
import data.scmbench.testdata

repo(set) := testdata.repo_input({"admins": set})

test_passes_with_two_administrators if {
	r := cis_1_3_7.result with input as repo(testdata.people(["alice", "bob"]))
	r.status == "PASS"
}

test_fails_with_one if {
	r := cis_1_3_7.result with input as repo(testdata.people(["alice"]))
	r.status == "FAIL"
}

# A lower bound that already meets the minimum is conclusive.
test_a_partial_set_meeting_the_minimum_passes if {
	r := cis_1_3_7.result with input as repo(testdata.partial(["alice", "bob"]))
	r.status == "PASS"
}

test_a_partial_set_under_the_minimum_is_manual if {
	r := cis_1_3_7.result with input as repo(testdata.partial(["alice"]))
	r.status == "MANUAL"
}

# With organization administrators only partly known, a repository
# administrator might be one of them, so the count may be inflated.
test_an_inexact_subtraction_cannot_pass if {
	r := cis_1_3_7.result with input as testdata.repo_input({
		"admins": testdata.people(["alice", "bob"]),
		"available": testdata.without("orgAdminsExact"),
	})
	r.status == "MANUAL"
}

# ...but too few is still too few: removing hidden organization
# administrators could only lower the count further.
test_an_inexact_subtraction_can_still_fail if {
	r := cis_1_3_7.result with input as testdata.repo_input({
		"admins": testdata.people(["alice"]),
		"available": testdata.without("orgAdminsExact"),
	})
	r.status == "FAIL"
}

test_everyone_as_administrator_passes_here if {
	r := cis_1_3_7.result with input as repo(testdata.all_members)
	r.status == "PASS"
	contains(r.details, "CIS-1.3.8")
}

test_manual_when_permissions_are_unreadable if {
	r := cis_1_3_7.result with input as testdata.repo_input({"available": testdata.without("admins")})
	r.status == "MANUAL"
}
