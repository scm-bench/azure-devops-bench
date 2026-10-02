package scmbench.rules.cis_1_5_1_test

import rego.v1

import data.scmbench.rules.cis_1_5_1
import data.scmbench.testdata

ghas(fields) := testdata.repo_input({"advancedSecurity": fields})

test_passes_when_pushes_with_secrets_are_blocked if {
	r := cis_1_5_1.result with input as ghas({"secretProtection": true, "blockPushes": true, "blockPushesKnown": true})
	r.status == "PASS"
}

test_fails_when_secret_scanning_is_off if {
	r := cis_1_5_1.result with input as ghas({"secretProtection": false})
	r.status == "FAIL"
}

test_fails_when_detection_does_not_block if {
	r := cis_1_5_1.result with input as ghas({"secretProtection": true, "blockPushes": false, "blockPushesKnown": true})
	r.status == "FAIL"
	contains(r.details, "not blocked")
}

# The platform returns null for blockPushes unless asked for every property;
# null is not "off".
test_an_unreported_block_setting_is_manual if {
	r := cis_1_5_1.result with input as ghas({"secretProtection": true})
	r.status == "MANUAL"
}

test_manual_when_enablement_is_unreadable if {
	r := cis_1_5_1.result with input as testdata.repo_input({"available": testdata.without("advancedSecurity")})
	r.status == "MANUAL"
	contains(r.details, "vso.advsec")
}

test_names_the_server_limitation if {
	r := cis_1_5_1.result with input as {
		"resource": testdata.repo({"available": testdata.without("advancedSecurity")}),
		"config": testdata.config,
		"metadata": {"deployment": "server"},
	}
	r.status == "MANUAL"
	contains(r.details, "Azure DevOps Services")
}

test_not_applicable_on_a_disabled_repository if {
	r := cis_1_5_1.result with input as testdata.input_for(testdata.disabled_repo)
	r.status == "NA"
}
