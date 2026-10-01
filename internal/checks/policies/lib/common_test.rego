# Tests for the helpers every control leans on.
#
# They are exercised indirectly by the control tests, but the branches that
# only appear at the edges — a list long enough to be truncated, a null where a
# list should be, an allowlisted service identity — are reached from here,
# where the case can be stated plainly.
package scmbench.lib_test

import rego.v1

import data.scmbench.lib
import data.scmbench.testdata

# default_branch_name falls back rather than rendering an empty string, so a
# message never reads "pushes to  are blocked".
test_default_branch_name_falls_back_when_unnamed if {
	name := lib.default_branch_name with input as testdata.input_for({"defaultBranch": "refs/heads/main"})
	name == "the default branch"
}

test_default_branch_name_uses_the_display_name if {
	name := lib.default_branch_name with input as testdata.input_for({"defaultBranchDisplay": "trunk"})
	name == "trunk"
}

test_has_default_branch if {
	lib.has_default_branch with input as testdata.repo_input({})
	not lib.has_default_branch with input as testdata.input_for({})
}

test_joined_truncates_past_the_limit if {
	lib.joined(["a", "b", "c", "d", "e"], 3) == "a, b, c and 2 more"
}

test_joined_leaves_a_short_list_alone if {
	lib.joined(["b", "a"], 3) == "a, b"
}

# A nil Go slice marshals to null, and null reaching concat or sort makes the
# calling rule undefined — which the engine reports as a control that produced
# no verdict at all.
test_joined_tolerates_null if {
	lib.joined(null, 3) == ""
}

test_list_substitutes_an_empty_list_for_null if {
	got := lib.list(["branches"]) with input as testdata.input_for({"branches": null})
	got == []
}

test_list_substitutes_an_empty_list_for_a_missing_key if {
	got := lib.list(["branches"]) with input as testdata.input_for({})
	got == []
}

test_as_list_treats_null_and_non_lists_as_empty if {
	lib.as_list(null) == []
	lib.as_list("x") == []
	lib.as_list(["x"]) == ["x"]
}

# A key present and false means "this fetch failed", which is not the same as
# a key that was never written — but both mean unavailable.
test_available_treats_a_missing_key_as_unavailable if {
	not lib.available("files") with input as testdata.input_for({"available": {}})
}

test_available_reads_a_successful_fetch if {
	lib.available("files") with input as testdata.input_for({"available": {"files": true}})
}

# Service identities can push past review too, so they are principals.
test_principals_include_service_identities if {
	got := lib.principals({"users": ["alice@fabrikam.com"], "serviceIdentities": ["Build Service (fabrikam)"]})
	got == {"alice@fabrikam.com", "Build Service (fabrikam)"}
}

test_principals_tolerate_null_lists if {
	lib.principals({"users": null, "serviceIdentities": null}) == set()
}

# The allowlist is compared case-insensitively against the names the report
# prints, so a config written from the report's output always matches.
test_allowlisted_principals_are_not_bypassers if {
	set := {"users": ["alice@fabrikam.com"], "serviceIdentities": ["Build Service (fabrikam)"], "complete": true}
	got := lib.bypassers(set) with input as testdata.input_with_config({}, {"allowedBypassPrincipals": ["build service (FABRIKAM)"]})
	got == {"alice@fabrikam.com"}
	note := lib.allowed_note(set) with input as testdata.input_with_config({}, {"allowedBypassPrincipals": ["build service (FABRIKAM)"]})
	contains(note, "Build Service (fabrikam)")
}

test_allowed_note_is_empty_without_allowlisted_holders if {
	lib.allowed_note(testdata.nobody) == ""
}

test_a_set_reaching_everyone_exceeds_any_threshold if {
	lib.bypass_exceeded(testdata.all_members) with input as testdata.input_for({})
	lib.who(testdata.all_members) == "every member of the organization or project"
}

# -1 turns the bypass check off: nothing exceeds it and nothing is undecidable.
test_minus_one_disables_the_bypass_check if {
	cfg := {"thresholds": object.union(testdata.config.thresholds, {"maxBypassPrincipals": -1})}
	not lib.bypass_exceeded(testdata.people(["a", "b"])) with input as testdata.input_with_config({}, cfg)
	not lib.bypass_undecidable(testdata.partial([])) with input as testdata.input_with_config({}, cfg)
}

test_a_partial_set_under_the_threshold_is_undecidable if {
	lib.bypass_undecidable(testdata.partial([])) with input as testdata.input_for({})
}

test_bypass_evidence_names_the_groups if {
	ev := lib.bypass_evidence(testdata.partial(["alice"]), "holders") with input as testdata.input_for({})
	count(ev) == 3
	contains(ev[2], "Contractors")
}

test_bypass_evidence_without_groups if {
	ev := lib.bypass_evidence(testdata.people(["alice"]), "holders") with input as testdata.input_for({})
	count(ev) == 2
}

test_max_bypass_falls_back_when_not_a_number if {
	n := lib.max_bypass with input as testdata.input_with_config({}, {"thresholds": {"maxBypassPrincipals": "many"}})
	n == 0
}

test_server_deployment_is_read_from_metadata if {
	lib.server_deployment with input as {"resource": {}, "config": testdata.config, "metadata": {"deployment": "server"}}
	not lib.server_deployment with input as testdata.input_for({})
}

test_people_counts_read_as_english if {
	lib.people(1) == "1 person"
	lib.people(0) == "0 people"
	lib.people(3) == "3 people"
}
