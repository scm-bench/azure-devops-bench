package scmbench.rules.cis_1_3_8_test

import rego.v1

import data.scmbench.rules.cis_1_3_8
import data.scmbench.testdata

grant(permission) := {"name": "[Fabrikam]\\Project Valid Users", "type": "group", "permission": permission}

test_passes_for_a_private_repository_with_read_only_defaults if {
	r := cis_1_3_8.result with input as testdata.repo_input({"permissions": {"everyoneGrants": [grant("GenericRead")]}})
	r.status == "PASS"
}

test_fails_for_a_public_project if {
	r := cis_1_3_8.result with input as testdata.repo_input({"public": true})
	r.status == "FAIL"
	contains(r.details, "public")
}

# Visibility needs no access control list, so the FAIL survives unreadable
# Git permissions.
test_public_fails_even_without_permissions if {
	r := cis_1_3_8.result with input as testdata.repo_input({"public": true, "available": testdata.without("permissions")})
	r.status == "FAIL"
}

test_allow_public_relaxes_the_visibility_check if {
	r := cis_1_3_8.result with input as testdata.repo_input_with_config({"public": true}, {"allowPublicRepositories": true})
	r.status == "PASS"
}

test_fails_when_every_member_can_contribute if {
	r := cis_1_3_8.result with input as testdata.repo_input({"permissions": {"everyoneGrants": [grant("GenericRead"), grant("GenericContribute")]}})
	r.status == "FAIL"
	r.evidence == ["[Fabrikam]\\Project Valid Users holds GenericContribute"]
}

test_everyone_allowed_permissions_widens_the_ceiling if {
	r := cis_1_3_8.result with input as testdata.repo_input_with_config(
		{"permissions": {"everyoneGrants": [grant("PullRequestContribute")]}},
		{"everyoneAllowedPermissions": ["GenericRead", "PullRequestContribute"]},
	)
	r.status == "PASS"
}

test_manual_when_visibility_is_unknown if {
	r := cis_1_3_8.result with input as testdata.repo_input({"available": testdata.without("visibility")})
	r.status == "MANUAL"
}

test_manual_when_permissions_are_unreadable if {
	r := cis_1_3_8.result with input as testdata.repo_input({"available": testdata.without("permissions")})
	r.status == "MANUAL"
}

test_null_grants_do_not_break_the_rule if {
	r := cis_1_3_8.result with input as testdata.repo_input({"permissions": {"everyoneGrants": null}})
	r.status == "PASS"
}
