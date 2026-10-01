package scmbench.rules.cis_1_3_9_test

import rego.v1

import data.scmbench.rules.cis_1_3_9
import data.scmbench.testdata

test_is_not_applicable if {
	r := cis_1_3_9.result with input as testdata.input_for({})
	r.status == "NA"
}
