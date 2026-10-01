package scmbench.rules.cis_1_3_5_test

import rego.v1

import data.scmbench.rules.cis_1_3_5
import data.scmbench.testdata

test_always_needs_a_person if {
	r := cis_1_3_5.result with input as testdata.input_for({})
	r.status == "MANUAL"
}
