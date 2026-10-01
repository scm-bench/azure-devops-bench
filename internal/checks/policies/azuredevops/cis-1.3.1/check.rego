package scmbench.rules.cis_1_3_1

import rego.v1

import data.scmbench.lib

threshold := object.get(lib.cfg, ["thresholds", "inactiveUserDays"], 90)

# The population is the active, licensed users: accounts that can sign in and
# that the organization pays for. A deactivated account has nothing left to
# review.
population := [u |
	some u in lib.list(["users"])
	object.get(u, "active", false) == true
	object.get(u, "licensed", false) == true
]

# How old an account is, for one that never signed in: ageDays is computed at
# capture time, so a snapshot evaluated next year judges the organization as
# it was when captured. -1 is unknown.
age_days(u) := object.get(u, "ageDays", -1)

never_signed_in(u) if object.get(u, "neverSignedIn", false) == true

dormant(u) if object.get(u, "inactiveDays", -1) >= threshold

dormant(u) if {
	never_signed_in(u)
	age_days(u) >= 0
	age_days(u) >= threshold
}

# A user whose last activity is unknown is not a fresh user: lastActivityEpoch
# 0 without neverSignedIn is "the platform did not say", never "never".
unknown(u) if {
	not never_signed_in(u)
	object.get(u, "inactiveDays", -1) < 0
}

unknown(u) if {
	never_signed_in(u)
	age_days(u) < 0
}

dormant_names := [u.name |
	some u in population
	dormant(u)
]

unknown_names := [u.name |
	some u in population
	not dormant(u)
	unknown(u)
]

decidable if {
	lib.available("users")
	lib.available("userActivity")
	lib.available("licensedUsers")
}

unreadable_details := "Azure DevOps Server reports no last access for its users, so dormant accounts cannot be found automatically. Review users who have not signed in recently by hand." if {
	lib.server_deployment
} else := "User entitlements could not be read (the token needs vso.memberentitlementmanagement), so dormant accounts cannot be found automatically. Review Organization settings -> Users by hand."

result := {
	"status": "MANUAL",
	"details": unreadable_details,
} if {
	not decidable
} else := {
	"status": "FAIL",
	"details": sprintf("%d active user(s) with an access level have not accessed the organization for %d days or more, or never signed in since being invited that long ago: %s.", [count(dormant_names), threshold, lib.joined(dormant_names, 10)]),
	"evidence": sort(dormant_names),
} if {
	count(dormant_names) > 0
} else := {
	"status": "MANUAL",
	"details": sprintf("%d active user(s) report no last access, so their dormancy cannot be assessed: %s. Check them at Organization settings -> Users.", [count(unknown_names), lib.joined(unknown_names, 10)]),
	"evidence": sort(unknown_names),
} if {
	count(unknown_names) > 0
} else := {
	"status": "PASS",
	"details": sprintf("No active user with an access level has been dormant for %d days or more (%d checked).", [threshold, count(population)]),
}
