package scmbench.rules.cis_1_3_9

import rego.v1

# Verification badges are a feature of hosted platforms with a public
# organization identity; Azure DevOps has none. Carried as an explicit NA so a
# reader can see it was considered and dismissed.
result := {
	"status": "NA",
	"details": "Organization verification badges do not exist on Azure DevOps, so there is nothing to verify.",
}
