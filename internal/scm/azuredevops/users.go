package azuredevops

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/scm-bench/azure-devops-bench/internal/scm"
)

// fetchUsers reads the organization's users with their access level and last
// access, from the user entitlement API. Services only: Azure DevOps Server
// has no equivalent, and no other API reports when a user last signed in.
func (f *Fetcher) fetchUsers(ctx context.Context, org *scm.Organization) {
	unavailable := func() {
		org.Available["users"] = false
		org.Available["userActivity"] = false
		org.Available["licensedUsers"] = false
	}
	if !f.client.Endpoint().Has(ServiceEntitlements) {
		unavailable()
		f.warn("Azure DevOps Server has no user entitlement API, so last access dates are unknown and CIS-1.3.1 reports MANUAL")
		return
	}
	f.logf("reading user entitlements")
	entitlements, err := getAll[apiUserEntitlement](ctx, f.client, ServiceEntitlements, "/_apis/userentitlements",
		url.Values{"api-version": []string{"7.1"}}, pageOptions{})
	if err != nil {
		unavailable()
		org.Errors = append(org.Errors, fmt.Sprintf("user entitlements: %s", describe(err)))
		f.warn("user entitlements are not readable (%v); the token needs vso.memberentitlementmanagement, and CIS-1.3.1 reports MANUAL", err)
		return
	}
	for _, e := range entitlements {
		org.Users = append(org.Users, f.toUser(e))
	}
	sort.Slice(org.Users, func(i, j int) bool { return org.Users[i].Name < org.Users[j].Name })
	org.Available["users"] = true
	org.Available["licensedUsers"] = true
	// Services reports a last access date for every entitlement, with a
	// documented sentinel for "never"; a user whose date is missing or
	// unreadable is unknown individually, which the rule handles.
	org.Available["userActivity"] = true
}

// neverAccessed is the sentinel Azure DevOps uses for a user who has never
// signed in: the zero DateTime of .NET.
const neverAccessedYear = 1

// toUser maps a user entitlement onto the family's user.
func (f *Fetcher) toUser(e apiUserEntitlement) scm.User {
	status := strings.ToLower(strings.TrimSpace(e.AccessLevel.Status))
	name := e.User.PrincipalName
	if name == "" {
		name = e.User.MailAddress
	}
	if name == "" {
		name = e.User.DisplayName
	}
	u := scm.User{
		Name:         name,
		DisplayName:  e.User.DisplayName,
		EmailAddress: e.User.MailAddress,
		AccessLevel:  strings.ToLower(e.AccessLevel.AccountLicenseType),
		Guest:        strings.EqualFold(e.User.MetaType, "guest"),
		InactiveDays: -1,
		AgeDays:      -1,
	}
	switch status {
	case "disabled", "deleted", "pendingdisabled":
		// The account cannot sign in. Removed from the population rather
		// than called dormant: there is nothing left to review.
		u.Active, u.Licensed = false, false
	case "none":
		u.Active, u.Licensed = true, false
	default:
		// active, pending, expired (a grace period during which the user
		// can still sign in).
		u.Active, u.Licensed = true, true
	}
	if created, ok := parseTime(e.DateCreated); ok && created.Year() > neverAccessedYear {
		u.CreatedEpoch = created.Unix()
		u.AgeDays = f.daysSince(created)
	}
	if status == "pending" {
		// Invited, never signed in: the platform says so in as many words.
		u.NeverSignedIn = true
	}
	if last, ok := parseTime(e.LastAccessedDate); ok {
		if last.Year() <= neverAccessedYear {
			u.NeverSignedIn = true
		} else {
			u.LastActivityEpoch = last.Unix()
			u.InactiveDays = f.daysSince(last)
		}
	}
	return u
}

func parseTime(raw string) (time.Time, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, false
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05"} {
		if t, err := time.Parse(layout, raw); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}
