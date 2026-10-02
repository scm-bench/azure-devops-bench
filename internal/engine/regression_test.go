package engine_test

import (
	"context"
	"testing"

	"github.com/scm-bench/azure-devops-bench/internal/checks"
	"github.com/scm-bench/azure-devops-bench/internal/config"
	"github.com/scm-bench/azure-devops-bench/internal/engine"
	"github.com/scm-bench/azure-devops-bench/internal/scm"
)

// Every list in the snapshot can legitimately be empty, and a nil Go slice
// marshals to JSON null rather than []. Rego's object.get only substitutes its
// default for an *absent* key, so a null reaching a builtin raises a type
// error, the rule becomes undefined, and the control silently produces no
// verdict at all.
//
// This is the guard for that whole class of bug: it exercises every control
// against snapshots where nothing is populated — every availability key true
// and every value zero, and no availability map at all. Any future field that
// forgets omitempty, or any policy that reads a list without lib.list, fails
// here.
func TestZeroValuedSnapshotProducesAVerdictForEveryControl(t *testing.T) {
	ctx := context.Background()
	for _, cfg := range []config.Config{config.Default(), func() config.Config {
		c := config.Default()
		c.SkipArchivedRepositories = false
		return c
	}()} {
		eng, err := engine.New(ctx, cfg, scm.PlatformAzureDevOps)
		if err != nil {
			t.Fatalf("build engine: %v", err)
		}
		snapshot := &scm.Snapshot{
			SchemaVersion: scm.SchemaVersion,
			Metadata:      scm.Metadata{Platform: scm.PlatformAzureDevOps},
			Organization: scm.Organization{
				Available: map[string]bool{
					"admins": true, "users": true, "userActivity": true, "licensedUsers": true, "repositoryCreators": true,
				},
			},
			Projects: []scm.Project{{
				Key: "Fabrikam",
				Repositories: []scm.Repository{
					{FullName: "Fabrikam/bare", Available: allAvailable(true)},
					// No Available map at all: every key reads as unknown, which
					// must degrade to MANUAL rather than error.
					{FullName: "Fabrikam/opaque"},
					{FullName: "Fabrikam/disabled", Archived: true, Disabled: true},
					{FullName: "Fabrikam/empty", Empty: true},
				},
			}},
		}
		rep, err := eng.Evaluate(ctx, snapshot)
		if err != nil {
			t.Fatalf("evaluate: %v", err)
		}
		for _, e := range rep.Errors {
			t.Errorf("policy error on a zero-valued snapshot: %s", e)
		}
		bundle, err := checks.Load()
		if err != nil {
			t.Fatalf("load bundle: %v", err)
		}
		seen := map[string]map[string]bool{}
		for _, f := range rep.Findings {
			if seen[f.CheckID] == nil {
				seen[f.CheckID] = map[string]bool{}
			}
			seen[f.CheckID][f.Resource] = true
		}
		for _, c := range bundle.Checks {
			if !cfg.Selects(c.ID) {
				continue
			}
			if c.Scope == checks.ScopeOrganization {
				if !seen[c.ID][engine.InstanceResourceName] {
					t.Errorf("check %s produced no finding for the organization", c.ID)
				}
				continue
			}
			for _, repo := range []string{"Fabrikam/bare", "Fabrikam/opaque", "Fabrikam/empty"} {
				if !seen[c.ID][repo] {
					t.Errorf("check %s produced no finding for %s on a zero-valued snapshot", c.ID, repo)
				}
			}
		}
	}
}

// A zero-valued repository with every fetch reported successful must not pass
// anything that needs a value: zeros are not settings.
func TestZeroValuesDoNotPassPolicyControls(t *testing.T) {
	got := evaluate(t, snapshotWith([]scm.Repository{{FullName: "Fabrikam/bare", Available: allAvailable(true)}}, healthyOrg()))
	for _, id := range []string{"CIS-1.1.2", "CIS-1.1.3", "CIS-1.1.4", "CIS-1.1.9", "CIS-1.1.11", "CIS-1.1.12", "CIS-1.1.15", "CIS-1.1.16", "CIS-1.1.17", "CIS-1.2.1", "CIS-1.3.7", "CIS-1.5.1"} {
		if got[id]["Fabrikam/bare"] == engine.StatusPass {
			t.Errorf("%s passed on a repository with nothing in it", id)
		}
	}
}

// An empty administrator list is a real state, not a broken one: it must reach
// a FAIL rather than erroring the rule out of existence.
func TestEmptyAdminListStillFails(t *testing.T) {
	org := healthyOrg()
	org.EffectiveAdmins = scm.EffectivePrincipals{Users: nil, Count: 0, Complete: true}
	got := evaluate(t, snapshotWith([]scm.Repository{hardenedRepo()}, org))
	assertStatuses(t, got, engine.InstanceResourceName, map[string]engine.Status{"CIS-1.3.3": engine.StatusFail})

	repo := hardenedRepo()
	repo.Admins = scm.EffectivePrincipals{Users: nil, Count: 0, Complete: true}
	got = evaluate(t, snapshotWith([]scm.Repository{repo}, healthyOrg()))
	assertStatuses(t, got, "Fabrikam/hardened", map[string]engine.Status{"CIS-1.3.7": engine.StatusFail})
}

// A repository whose default branch could not be resolved was never browsed,
// so reporting "no security policy found" would be a verdict about a search
// that never happened.
func TestUnresolvedDefaultBranchDoesNotFailSecurityPolicy(t *testing.T) {
	repo := hardenedRepo()
	repo.DefaultBranch, repo.DefaultBranchDisplay = "", ""
	repo.Files = scm.Files{}
	repo.Available["files"] = false
	got := evaluate(t, snapshotWith([]scm.Repository{repo}, healthyOrg()))
	assertStatuses(t, got, "Fabrikam/hardened", map[string]engine.Status{"CIS-1.2.1": engine.StatusManual})
}

// A restriction the fetcher could not attribute to the default branch is
// never credited.
func TestUnknownCoverageIsNeverAPass(t *testing.T) {
	repo := hardenedRepo()
	for i := range repo.BranchRestrictions {
		repo.BranchRestrictions[i].MatchesDefaultBranch = false
		repo.BranchRestrictions[i].MatchUnknown = true
	}
	got := evaluate(t, snapshotWith([]scm.Repository{repo}, healthyOrg()))
	assertStatuses(t, got, "Fabrikam/hardened", map[string]engine.Status{
		"CIS-1.1.15": engine.StatusManual,
		"CIS-1.1.16": engine.StatusManual,
		"CIS-1.1.17": engine.StatusManual,
	})
}

// A service identity holding a bypass is a bypass; naming it in
// allowedBypassPrincipals is how an expected one is accepted.
func TestServiceIdentityBypassNeedsTheAllowlist(t *testing.T) {
	repo := hardenedRepo()
	build := scm.EffectivePrincipals{ServiceIdentities: []string{"Fabrikam Build Service (fabrikam)"}, Complete: true}
	repo.BranchRestrictions[0].ExemptPrincipals = build
	got := evaluate(t, snapshotWith([]scm.Repository{repo}, healthyOrg()))
	assertStatuses(t, got, "Fabrikam/hardened", map[string]engine.Status{"CIS-1.1.15": engine.StatusFail})

	cfg := signingConfig()
	cfg.AllowedBypassPrincipals = []string{"Fabrikam Build Service (fabrikam)"}
	got = evaluateWith(t, cfg, snapshotWith([]scm.Repository{repo}, healthyOrg()))
	assertStatuses(t, got, "Fabrikam/hardened", map[string]engine.Status{"CIS-1.1.15": engine.StatusPass})
}

// Public visibility fails CIS-1.3.8 without any permission data, and unknown
// visibility never passes it.
func TestVisibility(t *testing.T) {
	repo := hardenedRepo()
	repo.Public = true
	repo.Available["permissions"] = false
	got := evaluate(t, snapshotWith([]scm.Repository{repo}, healthyOrg()))
	assertStatuses(t, got, "Fabrikam/hardened", map[string]engine.Status{"CIS-1.3.8": engine.StatusFail})

	repo = hardenedRepo()
	repo.Available["visibility"] = false
	got = evaluate(t, snapshotWith([]scm.Repository{repo}, healthyOrg()))
	assertStatuses(t, got, "Fabrikam/hardened", map[string]engine.Status{"CIS-1.3.8": engine.StatusManual})
}
