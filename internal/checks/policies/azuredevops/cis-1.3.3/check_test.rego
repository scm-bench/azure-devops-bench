package scmbench.rules.cis_1_3_3_test

import rego.v1

import data.scmbench.rules.cis_1_3_3
import data.scmbench.testdata

org(admins, complete) := testdata.input_for({
	"effectiveAdmins": {"users": admins, "count": count(admins), "complete": complete},
	"available": {"admins": true},
})

test_passes_inside_the_range if {
	r := cis_1_3_3.result with input as org(["alice", "bob", "carol"], true)
	r.status == "PASS"
}

test_fails_below_the_minimum if {
	r := cis_1_3_3.result with input as org(["alice"], true)
	r.status == "FAIL"
	contains(r.details, "at least 2")
}

test_fails_above_the_maximum if {
	r := cis_1_3_3.result with input as org(["a", "b", "c", "d", "e", "f"], true)
	r.status == "FAIL"
	contains(r.details, "at most 5")
}

# Expanding the group that failed could only add administrators.
test_an_over_count_is_conclusive_even_when_incomplete if {
	r := cis_1_3_3.result with input as org(["a", "b", "c", "d", "e", "f"], false)
	r.status == "FAIL"
}

test_an_under_count_from_an_incomplete_set_is_manual if {
	r := cis_1_3_3.result with input as org(["alice"], false)
	r.status == "MANUAL"
}

# Build services are listed, not counted: a count of administrators is a count
# of people.
test_service_identities_are_listed_not_counted if {
	r := cis_1_3_3.result with input as testdata.input_for({
		"effectiveAdmins": {"users": ["alice"], "serviceIdentities": ["Project Collection Build Service (fabrikam)"], "count": 1, "complete": true},
		"available": {"admins": true},
	})
	r.status == "FAIL"
	contains(r.evidence[1], "Build Service")
}

test_manual_when_the_group_is_unreadable if {
	r := cis_1_3_3.result with input as testdata.input_for({"available": {"admins": false}})
	r.status == "MANUAL"
}

test_zero_maximum_means_no_upper_limit if {
	r := cis_1_3_3.result with input as testdata.input_with_config(
		{"effectiveAdmins": {"users": ["a", "b", "c", "d", "e", "f", "g"], "complete": true}, "available": {"admins": true}},
		{"thresholds": object.union(testdata.config.thresholds, {"maxOrgAdmins": 0})},
	)
	r.status == "PASS"
	contains(r.details, "no upper limit")
}
