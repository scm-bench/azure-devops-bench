# Shared fixtures for the control unit tests.
#
# The configuration here mirrors config.Default() in internal/config. It is
# restated rather than derived because that is the point: if someone changes a
# default in Go without meaning to change what the rules assert, the tests that
# pin the behaviour keep asserting the old numbers and the difference shows up
# as a failure rather than as a quietly different verdict.
package scmbench.testdata

import rego.v1

config := {
	"thresholds": {
		"minApprovers": 2,
		"minRepositoryAdmins": 2,
		"minOrgAdmins": 2,
		"maxOrgAdmins": 5,
		"staleBranchDays": 90,
		"maxStaleBranches": 0,
		"inactiveUserDays": 90,
		"maxBypassPrincipals": 0,
		"maxRepositoryCreators": 0,
	},
	"signatureStatusChecks": [],
	"nonLinearMergeStrategies": ["no-ff", "rebase-no-ff", "ff"],
	"securityPolicyPaths": ["SECURITY.md", ".github/SECURITY.md", "docs/SECURITY.md"],
	"everyoneAllowedPermissions": ["GenericRead"],
	"allowedBypassPrincipals": [],
	"allowPublicRepositories": false,
	"skipArchivedRepositories": true,
}

metadata := {"deployment": "services", "generatedAt": "2026-10-01T00:00:00Z"}

# every_available lists the per-repository fetches a rule may ask about. Tests
# start from all of them succeeding and switch off the one under examination,
# so a MANUAL case says which fetch failed rather than which twelve did not.
every_available := {
	"visibility": true,
	"defaultBranch": true,
	"branches": true,
	"branchAges": true,
	"pullRequestSettings": true,
	"mergeStrategies": true,
	"unapproveOnUpdate": true,
	"requiredBuilds": true,
	"branchRestrictions": true,
	"files": true,
	"permissions": true,
	"admins": true,
	"orgAdminsExact": true,
	"deleters": true,
	"bypass": true,
	"advancedSecurity": true,
}

# people renders a complete principal set naming the given people.
people(names) := {"users": names, "count": count(names), "complete": true}

# nobody is a complete, empty set.
nobody := people([])

# partial is a lower bound: an Entra group the scan could not see into.
partial(names) := {"users": names, "groups": ["[fabrikam]\\Contractors"], "count": count(names), "complete": false}

# all_members is a set that reaches every member of the organization.
all_members := {"groups": ["[fabrikam]\\Project Collection Valid Users"], "count": 0, "complete": true, "everyone": true}

# repo builds a repository with a resolved default branch, everything readable,
# and the given fields merged over the top.
repo(fields) := object.union(
	{
		"fullName": "Fabrikam/app",
		"defaultBranch": "refs/heads/main",
		"defaultBranchDisplay": "main",
		"available": every_available,
	},
	fields,
)

# input_for wraps a resource as the engine does.
input_for(resource) := {"resource": resource, "config": config, "metadata": metadata}

# repo_input is the common case: a repository, wrapped.
repo_input(fields) := input_for(repo(fields))

# without marks one availability key as failed, leaving the rest readable.
without(key) := object.union(every_available, {key: false})

# input_with_config is input_for with config keys overridden.
input_with_config(resource, overrides) := {
	"resource": resource,
	"config": object.union(config, overrides),
	"metadata": metadata,
}

repo_input_with_config(fields, overrides) := input_with_config(repo(fields), overrides)

# restriction builds a derived restriction covering the default branch, with
# the given exempt set.
restriction(kind, exempt) := {
	"type": kind,
	"matchesDefaultBranch": true,
	"derived": true,
	"exemptPrincipals": exempt,
}

# unknown_restriction is one the fetcher could not attribute to the default
# branch.
unknown_restriction(kind) := {
	"type": kind,
	"matchesDefaultBranch": false,
	"matchUnknown": true,
	"exemptPrincipals": {"complete": false, "count": 0},
}

# disabled and empty repositories, for the NA branches.
disabled_repo := repo({"archived": true, "disabled": true})

empty_repo := object.union(
	repo({"empty": true}),
	{"defaultBranch": "", "defaultBranchDisplay": ""},
)
