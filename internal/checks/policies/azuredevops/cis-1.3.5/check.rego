package scmbench.rules.cis_1_3_5

import rego.v1

# Multi-factor enforcement lives in Microsoft Entra Conditional Access (or the
# directory in front of Azure DevOps Server), which the Azure DevOps API does
# not expose. Reporting PASS or FAIL from Azure DevOps data would be a
# fabrication either way.
result := {
	"status": "MANUAL",
	"details": "Multi-factor authentication is enforced by Microsoft Entra ID Conditional Access (or the directory in front of Azure DevOps Server), which the Azure DevOps API does not expose. Verify enforcement there.",
}
