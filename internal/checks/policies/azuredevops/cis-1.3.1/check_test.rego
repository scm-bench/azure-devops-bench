package scmbench.rules.cis_1_3_1_test

import rego.v1

import data.scmbench.rules.cis_1_3_1
import data.scmbench.testdata

org(users) := testdata.input_for({
	"users": users,
	"available": {"users": true, "userActivity": true, "licensedUsers": true},
})

user(name, days) := {"name": name, "active": true, "licensed": true, "inactiveDays": days, "lastActivityEpoch": 1}

test_passes_with_only_active_users if {
	r := cis_1_3_1.result with input as org([user("alice", 1), user("bob", 30)])
	r.status == "PASS"
}

test_fails_with_a_dormant_user if {
	r := cis_1_3_1.result with input as org([user("alice", 1), user("ghost", 400)])
	r.status == "FAIL"
	r.evidence == ["ghost"]
}

# Invited long ago and never signed in: dormant by the platform's own word.
test_never_signed_in_and_old_is_dormant if {
	r := cis_1_3_1.result with input as org([{"name": "invitee", "active": true, "licensed": true, "neverSignedIn": true, "ageDays": 200, "inactiveDays": -1}])
	r.status == "FAIL"
}

# Invited last week: not dormant yet.
test_never_signed_in_and_recent_is_not_dormant if {
	r := cis_1_3_1.result with input as org([{"name": "newcomer", "active": true, "licensed": true, "neverSignedIn": true, "ageDays": 10, "inactiveDays": -1}])
	r.status == "PASS"
}

test_never_signed_in_with_unknown_age_is_manual if {
	r := cis_1_3_1.result with input as org([{"name": "invitee", "active": true, "licensed": true, "neverSignedIn": true, "ageDays": -1, "inactiveDays": -1}])
	r.status == "MANUAL"
}

test_unknown_activity_is_manual_not_fresh if {
	r := cis_1_3_1.result with input as org([user("alice", 1), {"name": "mystery", "active": true, "licensed": true, "inactiveDays": -1}])
	r.status == "MANUAL"
	r.evidence == ["mystery"]
}

# The dormant users the scan did see are real findings whatever it missed.
test_a_dormant_user_wins_over_unknown_ones if {
	r := cis_1_3_1.result with input as org([user("ghost", 400), {"name": "mystery", "active": true, "licensed": true, "inactiveDays": -1}])
	r.status == "FAIL"
}

test_unlicensed_and_deactivated_users_are_outside_the_population if {
	r := cis_1_3_1.result with input as org([
		{"name": "stale-but-disabled", "active": false, "licensed": false, "inactiveDays": 900},
		{"name": "no-access-level", "active": true, "licensed": false, "inactiveDays": 900},
	])
	r.status == "PASS"
}

test_manual_when_entitlements_are_unreadable if {
	r := cis_1_3_1.result with input as testdata.input_for({"available": {"users": false}})
	r.status == "MANUAL"
	contains(r.details, "vso.memberentitlementmanagement")
}

test_names_the_server_limitation if {
	r := cis_1_3_1.result with input as {"resource": {"available": {}}, "config": testdata.config, "metadata": {"deployment": "server"}}
	r.status == "MANUAL"
	contains(r.details, "Azure DevOps Server")
}
