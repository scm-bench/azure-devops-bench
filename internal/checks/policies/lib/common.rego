# Helpers shared by every control.
#
# The contract each control implements is a single `result` document:
#
#   result := {"status": "PASS"|"FAIL"|"MANUAL"|"NA", "details": "...", "evidence": [...]}
#
# MANUAL means the organization did not expose enough data to decide — never a
# guess dressed up as a verdict. NA means the control does not apply to this
# resource at all. Only PASS and FAIL affect the score.
package scmbench.lib

import rego.v1

# resource is the repository or organization under evaluation.
resource := input.resource

# cfg holds the thresholds, so no control hard-codes a number.
cfg := input.config

# available reports whether a given part of the snapshot was fetched
# successfully. A missing key is treated as unavailable.
available(key) if {
	object.get(resource, ["available", key], false) == true
}

# list reads a list-valued field, treating an explicit JSON null exactly like a
# missing one.
#
# This is load-bearing. Go marshals a nil slice to null rather than [], and
# object.get only substitutes its default when the key is *absent* — a key
# present with a null value comes back as null. Passing that null to concat or
# sort raises a type error, which makes the whole rule undefined and the control
# report nothing at all. Always read lists through this.
list(path) := value if {
	value := object.get(resource, path, [])
	is_array(value)
} else := []

# as_list reads a list already in hand the way list() reads one by path.
as_list(x) := x if {
	is_array(x)
} else := []

# empty_repository is true for a repository with no branches yet.
empty_repository if {
	object.get(resource, "empty", false) == true
}

# archived_repository is true for a disabled repository: Azure DevOps refuses
# every Git request to one, so no change can reach it.
archived_repository if {
	object.get(resource, "archived", false) == true
}

# has_default_branch is false for empty repositories and for any repository
# whose default branch could not be resolved.
has_default_branch if {
	object.get(resource, "defaultBranch", "") != ""
}

# default_branch_name is the short branch name, for use in messages.
default_branch_name := name if {
	name := object.get(resource, "defaultBranchDisplay", "")
	name != ""
} else := "the default branch"

# change_na is the shared "no change can happen here" outcome for the
# controls about how changes land. It comes first in those rules: neither a
# disabled nor an empty repository has its settings read, and reporting their
# absence as MANUAL would ask a person to review a branch that does not exist.
change_na := {
	"status": "NA",
	"details": "The repository is disabled, so Azure DevOps accepts no change to it; re-enabling it brings this control back.",
} if {
	archived_repository
} else := {
	"status": "NA",
	"details": "The repository has no branches yet, so there is no default branch to protect.",
} if {
	empty_repository
}

change_not_applicable if archived_repository

change_not_applicable if empty_repository

# pr_setting reads one pull request setting with a default.
pr_setting(key, fallback) := object.get(resource, ["pullRequestSettings", key], fallback)

# merge_strategies is the merge strategy list.
merge_strategies := list(["pullRequestSettings", "mergeStrategies"])

enabled_merge_strategies := [s.id |
	some s in merge_strategies
	s.enabled == true
]

# restrictions returns every branch restriction of the given type that covers
# the default branch. Azure DevOps declares none; the fetcher derives them from
# the required policies and the branch's permissions and resolves coverage, so
# controls only read the resolved boolean.
restrictions(kind) := [r |
	some r in list("branchRestrictions")
	r.type == kind
	r.matchesDefaultBranch == true
]

# any_restrictions returns every restriction of the type, whether or not it is
# known to cover the default branch. None at all is conclusive even when the
# default branch could not be resolved.
any_restrictions(kind) := [r |
	some r in list("branchRestrictions")
	r.type == kind
]

# ---------------------------------------------------------------------------
# Principal sets.
#
# Every set the fetcher hands over is an EffectivePrincipals: people in users,
# build services and service principals in serviceIdentities, the groups
# behind them, a completeness flag, and an everyone flag for a set that
# includes a group every member belongs to. A set that is not complete is a
# lower bound: it can prove a FAIL ("at least these people"), never a PASS.
# ---------------------------------------------------------------------------

# allowed_bypass names the service identities a bypass is expected on, so they
# do not count against the threshold. Compared case-insensitively.
allowed_bypass := {lower(p) | some p in as_list(object.get(cfg, "allowedBypassPrincipals", []))}

# max_bypass is how many principals may hold a bypass; -1 turns the check off.
max_bypass := n if {
	n := object.get(cfg, ["thresholds", "maxBypassPrincipals"], 0)
	is_number(n)
} else := 0

# principals is everyone named in a set: people and service identities. A
# build service that can push past review is a bypass exactly as a person is.
principals(set) := {n |
	some n in array.concat(
		as_list(object.get(set, "users", [])),
		as_list(object.get(set, "serviceIdentities", [])),
	)
}

complete(set) if object.get(set, "complete", false) == true

everyone(set) if object.get(set, "everyone", false) == true

# bypassers is a set's principals less the allowlisted service identities.
bypassers(set) := {n |
	some n in principals(set)
	not lower(n) in allowed_bypass
}

# bypass_exceeded is true when more principals hold a bypass than the
# configuration allows. A set reaching every member always exceeds it.
bypass_exceeded(set) if {
	max_bypass >= 0
	everyone(set)
}

bypass_exceeded(set) if {
	max_bypass >= 0
	count(bypassers(set)) > max_bypass
}

# bypass_undecidable is true when the set has not crossed the threshold but is
# only a lower bound, so this scan cannot tell whether it would. A group the
# token could not expand is not evidence that nobody is in it.
bypass_undecidable(set) if {
	max_bypass >= 0
	not bypass_exceeded(set)
	not complete(set)
}

bypass_list(set) := [n | some n in bypassers(set)]

# who renders a set for a message.
who(set) := "every member of the organization or project" if {
	everyone(set)
} else := joined(bypass_list(set), 4)

# bypass_evidence states the count and the threshold it was judged against, so
# the verdict can be checked rather than taken on faith.
bypass_evidence(set, what) := array.concat(
	[sprintf("%s: %s", [what, who(set)])],
	array.concat(
		[sprintf("%d in total; thresholds.maxBypassPrincipals is %d", [count(bypassers(set)), max_bypass])],
		groups_evidence(set),
	),
)

groups_evidence(set) := [sprintf("through groups: %s", [joined(as_list(object.get(set, "groups", [])), 6)])] if {
	count(as_list(object.get(set, "groups", []))) > 0
} else := []

# allowed_note names the allowlisted holders a passing verdict still has, so
# the report keeps showing who holds a bypass.
allowed_note(set) := sprintf(" (allowed: %s)", [joined(allowed_holders(set), 4)]) if {
	count(allowed_holders(set)) > 0
} else := ""

allowed_holders(set) := [n |
	some n in principals(set)
	lower(n) in allowed_bypass
]

# restriction_set is a restriction's exempt principals.
restriction_set(r) := object.get(r, "exemptPrincipals", {})

# joined renders a list for a message, capping the length so a repository with
# hundreds of stale branches does not produce an unreadable line. The is_array
# guards keep a null from erroring the rule that calls it.
joined(items, limit) := msg if {
	is_array(items)
	count(items) > limit
	shown := array.slice(sort(items), 0, limit)
	msg := sprintf("%s and %d more", [concat(", ", shown), count(items) - limit])
} else := msg if {
	is_array(items)
	msg := concat(", ", sort(items))
} else := ""

# server_deployment is true for a scan of Azure DevOps Server, where some
# APIs (Graph, user entitlements, Advanced Security) do not exist.
server_deployment if {
	object.get(input, ["metadata", "deployment"], "") == "server"
}

# people renders a head count for a sentence: "1 person", "3 people".
people(n) := "1 person" if n == 1

people(n) := sprintf("%d people", [n]) if n != 1
