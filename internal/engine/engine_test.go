package engine_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/scm-bench/azure-devops-bench/internal/checks"
	"github.com/scm-bench/azure-devops-bench/internal/config"
	"github.com/scm-bench/azure-devops-bench/internal/engine"
	"github.com/scm-bench/azure-devops-bench/internal/scm"
)

// signingConfig names the status check the hardened repository requires, the
// one CIS-1.1.12 needs a deployment to name before it can pass.
func signingConfig() config.Config {
	cfg := config.Default()
	cfg.SignatureStatusChecks = []string{"security/verify-signatures"}
	return cfg
}

// evaluate runs the whole bundle against a snapshot and indexes the results by
// check ID and resource, so a test can assert on one control at a time.
func evaluate(t *testing.T, snapshot *scm.Snapshot) map[string]map[string]engine.Status {
	t.Helper()
	return evaluateWith(t, signingConfig(), snapshot)
}

func evaluateWith(t *testing.T, cfg config.Config, snapshot *scm.Snapshot) map[string]map[string]engine.Status {
	t.Helper()
	ctx := context.Background()
	eng, err := engine.New(ctx, cfg, scm.PlatformAzureDevOps)
	if err != nil {
		t.Fatalf("build engine: %v", err)
	}
	rep, err := eng.Evaluate(ctx, snapshot)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if len(rep.Errors) > 0 {
		t.Fatalf("policies reported errors: %v", rep.Errors)
	}
	out := map[string]map[string]engine.Status{}
	for _, f := range rep.Findings {
		if out[f.CheckID] == nil {
			out[f.CheckID] = map[string]engine.Status{}
		}
		if _, dup := out[f.CheckID][f.Resource]; dup {
			t.Fatalf("check %s produced two findings for %s", f.CheckID, f.Resource)
		}
		out[f.CheckID][f.Resource] = f.Status
		if f.Details == "" {
			t.Errorf("check %s on %s has an empty details string", f.CheckID, f.Resource)
		}
	}
	return out
}

func assertStatuses(t *testing.T, got map[string]map[string]engine.Status, resource string, want map[string]engine.Status) {
	t.Helper()
	for checkID, wantStatus := range want {
		byResource, ok := got[checkID]
		if !ok {
			t.Errorf("%s: check %s produced no finding at all", resource, checkID)
			continue
		}
		gotStatus, ok := byResource[resource]
		if !ok {
			t.Errorf("%s: check %s produced no finding for this resource", resource, checkID)
			continue
		}
		if gotStatus != wantStatus {
			t.Errorf("%s: check %s = %s, want %s", resource, checkID, gotStatus, wantStatus)
		}
	}
}

func snapshotWith(repos []scm.Repository, org scm.Organization) *scm.Snapshot {
	return &scm.Snapshot{
		SchemaVersion: scm.SchemaVersion,
		Metadata: scm.Metadata{
			Tool:        "azure-devops-bench",
			Platform:    scm.PlatformAzureDevOps,
			BaseURL:     "https://dev.azure.com/fabrikam",
			GeneratedAt: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC),
			Deployment:  scm.DeploymentServices,
		},
		Organization: org,
		Projects: []scm.Project{{
			Key:          "Fabrikam",
			Name:         "Fabrikam",
			Repositories: repos,
		}},
	}
}

var repoKeys = []string{
	"visibility", "defaultBranch", "branches", "branchAges", "pullRequestSettings", "mergeStrategies",
	"unapproveOnUpdate", "requiredBuilds", "branchRestrictions", "files", "permissions", "admins",
	"orgAdminsExact", "deleters", "bypass", "advancedSecurity",
}

func allAvailable(v bool) map[string]bool {
	out := make(map[string]bool, len(repoKeys))
	for _, k := range repoKeys {
		out[k] = v
	}
	return out
}

func people(names ...string) scm.EffectivePrincipals {
	return scm.EffectivePrincipals{Users: names, Count: len(names), Complete: true}
}

func derived(kind string, exempt scm.EffectivePrincipals) scm.BranchRestriction {
	return scm.BranchRestriction{
		Type: kind, MatcherID: "refs/heads/main", MatcherType: "BRANCH", MatchesDefaultBranch: true,
		ExemptPrincipals: exempt, Derived: true, DerivedFrom: []string{"policy 1 Minimum number of reviewers (required)"},
	}
}

func strategies(allowed ...string) []scm.MergeStrategy {
	var out []scm.MergeStrategy
	for _, id := range []string{"no-ff", "rebase-ff-only", "rebase-no-ff", "squash"} {
		enabled := false
		for _, a := range allowed {
			enabled = enabled || a == id
		}
		out = append(out, scm.MergeStrategy{ID: id, Enabled: enabled})
	}
	return out
}

// hardenedRepo satisfies every automatable repository control.
func hardenedRepo() scm.Repository {
	return scm.Repository{
		Slug: "hardened", Name: "hardened", ProjectKey: "Fabrikam", FullName: "Fabrikam/hardened",
		DefaultBranch: "refs/heads/main", DefaultBranchDisplay: "main",
		PullRequestSettings: scm.PullRequestSettings{
			RequiredApprovers: 2, MinimumApproverCount: 2, UnapproveOnUpdate: true,
			RequiredAllTasksComplete: true, WorkItemLinkingRequired: true,
			MergeStrategies: strategies("squash", "rebase-ff-only"),
		},
		BranchRestrictions: []scm.BranchRestriction{
			derived(scm.RestrictionPullRequestOnly, people()),
			derived(scm.RestrictionNoDeletes, people()),
			derived(scm.RestrictionFastForwardOnly, people()),
		},
		RequiredBuilds: []scm.RequiredBuild{
			{Kind: "build", Name: "CI", MatcherID: "refs/heads/main", MatchesDefaultBranch: true},
			{Kind: "status", Name: "security/verify-signatures", MatcherID: "refs/heads/main", MatchesDefaultBranch: true},
		},
		Branches: []scm.Branch{
			{ID: "refs/heads/main", DisplayID: "main", IsDefault: true, AgeDays: 2},
			{ID: "refs/heads/feature/x", DisplayID: "feature/x", AgeDays: 10},
		},
		Files:            scm.Files{SecurityPolicyPaths: []string{"SECURITY.md"}, Probed: []string{"SECURITY.md"}},
		Permissions:      scm.Permissions{DefaultPermissionKnown: true, EveryoneGrants: []scm.PrincipalPermission{{Name: `[Fabrikam]\Project Valid Users`, Type: "group", Permission: "GenericRead"}}},
		Admins:           people("alice@fabrikam.com", "bob@fabrikam.com"),
		Deleters:         people("alice@fabrikam.com"),
		Bypass:           scm.Bypass{Push: people(), PullRequest: people(), Admins: people()},
		AdvancedSecurity: scm.AdvancedSecurity{SecretProtection: true, BlockPushes: true, BlockPushesKnown: true},
		Available:        allAvailable(true),
	}
}

// openRepo fails every automatable repository control.
func openRepo() scm.Repository {
	return scm.Repository{
		Slug: "open", Name: "open", ProjectKey: "Fabrikam", FullName: "Fabrikam/open", Public: true,
		DefaultBranch: "refs/heads/main", DefaultBranchDisplay: "main",
		PullRequestSettings: scm.PullRequestSettings{
			RequiredApprovers: 0, MergeStrategies: strategies("no-ff", "rebase-ff-only", "rebase-no-ff", "squash"),
		},
		// No required policy: only the force-push restriction, and the
		// branch's creator still holds Force push.
		BranchRestrictions: []scm.BranchRestriction{derived(scm.RestrictionFastForwardOnly, people("creator@fabrikam.com"))},
		Branches: []scm.Branch{
			{ID: "refs/heads/main", DisplayID: "main", IsDefault: true, AgeDays: 3},
			{ID: "refs/heads/abandoned", DisplayID: "abandoned", AgeDays: 400},
		},
		Files: scm.Files{Probed: []string{"SECURITY.md", ".github/SECURITY.md"}},
		Permissions: scm.Permissions{DefaultPermissionKnown: true, EveryoneGrants: []scm.PrincipalPermission{
			{Name: `[Fabrikam]\Project Valid Users`, Type: "group", Permission: "GenericContribute"},
		}},
		Admins:   people("alice@fabrikam.com"),
		Deleters: people("alice@fabrikam.com", "intern@fabrikam.com"),
		Bypass: scm.Bypass{
			Push:        people("alice@fabrikam.com"),
			PullRequest: people("bob@fabrikam.com"),
			Admins:      people("alice@fabrikam.com"),
		},
		AdvancedSecurity: scm.AdvancedSecurity{SecretProtection: false},
		Available:        allAvailable(true),
	}
}

// unknownRepo is a repository whose settings could not be read at all.
func unknownRepo() scm.Repository {
	return scm.Repository{
		Slug: "unknown", Name: "unknown", ProjectKey: "Fabrikam", FullName: "Fabrikam/unknown",
		DefaultBranch: "refs/heads/main", DefaultBranchDisplay: "main",
		Available: allAvailable(false),
	}
}

func emptyRepo() scm.Repository {
	available := allAvailable(true)
	available["bypass"] = false
	return scm.Repository{
		Slug: "empty", Name: "empty", FullName: "Fabrikam/empty", Empty: true,
		Permissions: scm.Permissions{DefaultPermissionKnown: true},
		Admins:      people("alice@fabrikam.com", "bob@fabrikam.com"),
		Deleters:    people("alice@fabrikam.com"),
		Available:   available,
	}
}

func disabledRepo() scm.Repository {
	r := hardenedRepo()
	r.Slug, r.Name, r.FullName = "archive", "archive", "Fabrikam/archive"
	r.Archived, r.Disabled = true, true
	r.Admins = people("alice@fabrikam.com")
	return r
}

func healthyOrg() scm.Organization {
	return scm.Organization{
		Admins: []scm.PrincipalPermission{
			{Name: "alice@fabrikam.com", Type: "user", Permission: "Project Collection Administrators"},
			{Name: "bob@fabrikam.com", Type: "user", Permission: "Project Collection Administrators"},
		},
		EffectiveAdmins: scm.EffectivePrincipals{Users: []string{"alice@fabrikam.com", "bob@fabrikam.com"}, Count: 2, Complete: true,
			ServiceIdentities: []string{"Project Collection Build Service (fabrikam)"}},
		Users: []scm.User{
			{Name: "alice@fabrikam.com", Active: true, Licensed: true, InactiveDays: 1, LastActivityEpoch: 1},
			{Name: "bob@fabrikam.com", Active: true, Licensed: true, InactiveDays: 20, LastActivityEpoch: 1},
		},
		RepositoryCreators: []scm.ProjectPrincipals{{Project: "Fabrikam", Principals: people(), AdminsExact: true}},
		Available:          map[string]bool{"admins": true, "users": true, "userActivity": true, "licensedUsers": true, "repositoryCreators": true},
	}
}

func badOrg() scm.Organization {
	org := healthyOrg()
	org.EffectiveAdmins = people("alice@fabrikam.com")
	org.Users = append(org.Users, scm.User{Name: "ghost@fabrikam.com", Active: true, Licensed: true, InactiveDays: 400, LastActivityEpoch: 1})
	org.RepositoryCreators = []scm.ProjectPrincipals{{Project: "Fabrikam", Principals: people("dev@fabrikam.com"), AdminsExact: true}}
	return org
}

var repoChecks = []string{
	"CIS-1.1.2", "CIS-1.1.3", "CIS-1.1.4", "CIS-1.1.5", "CIS-1.1.8", "CIS-1.1.9", "CIS-1.1.11", "CIS-1.1.12",
	"CIS-1.1.13", "CIS-1.1.14", "CIS-1.1.15", "CIS-1.1.16", "CIS-1.1.17", "CIS-1.2.1", "CIS-1.2.3",
	"CIS-1.3.7", "CIS-1.3.8", "CIS-1.5.1",
}

func every(status engine.Status, ids []string) map[string]engine.Status {
	out := map[string]engine.Status{}
	for _, id := range ids {
		out[id] = status
	}
	return out
}

func TestHardenedRepositoryPassesEveryAutomatableControl(t *testing.T) {
	got := evaluate(t, snapshotWith([]scm.Repository{hardenedRepo()}, healthyOrg()))
	want := every(engine.StatusPass, repoChecks)
	want["CIS-1.1.6"] = engine.StatusManual // documented as not answerable
	assertStatuses(t, got, "Fabrikam/hardened", want)
	assertStatuses(t, got, engine.InstanceResourceName, map[string]engine.Status{
		"CIS-1.2.2": engine.StatusPass,
		"CIS-1.3.1": engine.StatusPass,
		"CIS-1.3.3": engine.StatusPass,
		"CIS-1.3.5": engine.StatusManual,
		"CIS-1.3.9": engine.StatusNA,
	})
}

func TestOpenRepositoryFailsEveryAutomatableControl(t *testing.T) {
	got := evaluate(t, snapshotWith([]scm.Repository{openRepo()}, badOrg()))
	assertStatuses(t, got, "Fabrikam/open", every(engine.StatusFail, repoChecks))
	assertStatuses(t, got, engine.InstanceResourceName, map[string]engine.Status{
		"CIS-1.2.2": engine.StatusFail,
		"CIS-1.3.1": engine.StatusFail,
		"CIS-1.3.3": engine.StatusFail,
	})
}

// An unreadable organization must never look compliant, and must never look
// broken either: every affected control has to say so out loud.
func TestUnreadableSettingsReportManualNotFail(t *testing.T) {
	got := evaluate(t, snapshotWith([]scm.Repository{unknownRepo()}, scm.Organization{Available: map[string]bool{}}))
	assertStatuses(t, got, "Fabrikam/unknown", every(engine.StatusManual, repoChecks))
	assertStatuses(t, got, engine.InstanceResourceName, map[string]engine.Status{
		"CIS-1.2.2": engine.StatusManual,
		"CIS-1.3.1": engine.StatusManual,
		"CIS-1.3.3": engine.StatusManual,
	})
}

// Without access control lists, what needs them is MANUAL — and what does
// not still decides: no required policy is a FAIL whoever may bypass it.
func TestUnreadablePermissionsKeepTheFailuresThatDoNotNeedThem(t *testing.T) {
	repo := openRepo()
	for _, k := range []string{"bypass", "admins", "deleters", "permissions"} {
		repo.Available[k] = false
	}
	repo.BranchRestrictions = []scm.BranchRestriction{derived(scm.RestrictionFastForwardOnly, scm.EffectivePrincipals{Complete: false})}
	got := evaluate(t, snapshotWith([]scm.Repository{repo}, healthyOrg()))
	assertStatuses(t, got, "Fabrikam/open", map[string]engine.Status{
		"CIS-1.1.15": engine.StatusFail, // no required policy
		"CIS-1.1.17": engine.StatusFail, // no required policy
		"CIS-1.3.8":  engine.StatusFail, // public project
		"CIS-1.1.16": engine.StatusManual,
		"CIS-1.1.5":  engine.StatusManual,
		"CIS-1.1.14": engine.StatusManual,
		"CIS-1.2.3":  engine.StatusManual,
		"CIS-1.3.7":  engine.StatusManual,
	})

	hardened := hardenedRepo()
	for _, k := range []string{"bypass", "admins", "deleters", "permissions"} {
		hardened.Available[k] = false
	}
	for i := range hardened.BranchRestrictions {
		hardened.BranchRestrictions[i].ExemptPrincipals = scm.EffectivePrincipals{Complete: false}
	}
	got = evaluate(t, snapshotWith([]scm.Repository{hardened}, healthyOrg()))
	// The PASS sides need the permissions, so they wait for a person.
	assertStatuses(t, got, "Fabrikam/hardened", map[string]engine.Status{
		"CIS-1.1.15": engine.StatusManual,
		"CIS-1.1.16": engine.StatusManual,
		"CIS-1.1.17": engine.StatusManual,
		"CIS-1.3.8":  engine.StatusManual,
		"CIS-1.1.3":  engine.StatusPass,
	})
}

func TestEmptyRepositorySkipsChangeControls(t *testing.T) {
	got := evaluate(t, snapshotWith([]scm.Repository{emptyRepo()}, healthyOrg()))
	assertStatuses(t, got, "Fabrikam/empty", map[string]engine.Status{
		"CIS-1.1.2": engine.StatusNA, "CIS-1.1.3": engine.StatusNA, "CIS-1.1.4": engine.StatusNA,
		"CIS-1.1.5": engine.StatusNA, "CIS-1.1.8": engine.StatusNA, "CIS-1.1.9": engine.StatusNA,
		"CIS-1.1.11": engine.StatusNA, "CIS-1.1.12": engine.StatusNA, "CIS-1.1.13": engine.StatusNA,
		"CIS-1.1.14": engine.StatusNA, "CIS-1.1.15": engine.StatusNA, "CIS-1.1.16": engine.StatusNA,
		"CIS-1.1.17": engine.StatusNA, "CIS-1.2.1": engine.StatusNA,
		// Access is still evaluated on an empty repository.
		"CIS-1.3.7": engine.StatusPass, "CIS-1.2.3": engine.StatusPass,
	})
}

// A disabled repository is Azure DevOps's archive: change controls do not
// apply, access controls still do, and by default it is not scanned at all.
func TestDisabledRepository(t *testing.T) {
	cfg := signingConfig()
	cfg.SkipArchivedRepositories = false
	got := evaluateWith(t, cfg, snapshotWith([]scm.Repository{disabledRepo()}, healthyOrg()))
	want := map[string]engine.Status{"CIS-1.3.7": engine.StatusFail, "CIS-1.3.8": engine.StatusPass, "CIS-1.2.3": engine.StatusPass}
	for _, id := range []string{"CIS-1.1.2", "CIS-1.1.3", "CIS-1.1.5", "CIS-1.1.6", "CIS-1.1.15", "CIS-1.1.16", "CIS-1.2.1", "CIS-1.5.1"} {
		want[id] = engine.StatusNA
	}
	assertStatuses(t, got, "Fabrikam/archive", want)

	got = evaluate(t, snapshotWith([]scm.Repository{disabledRepo(), hardenedRepo()}, healthyOrg()))
	if _, ok := got["CIS-1.3.7"]["Fabrikam/archive"]; ok {
		t.Error("skipArchivedRepositories should leave the disabled repository out")
	}
}

// With nothing configured, CIS-1.1.12 fails even on a hardened repository:
// Azure Repos cannot verify a signature, and no status is known to.
func TestSignatureVerificationNeedsANamedStatus(t *testing.T) {
	got := evaluateWith(t, config.Default(), snapshotWith([]scm.Repository{hardenedRepo()}, healthyOrg()))
	assertStatuses(t, got, "Fabrikam/hardened", map[string]engine.Status{"CIS-1.1.12": engine.StatusFail})
}

func TestOrganizationAdministratorBounds(t *testing.T) {
	for _, tc := range []struct {
		name  string
		users []string
		want  engine.Status
	}{
		{"too few", []string{"a"}, engine.StatusFail},
		{"within range", []string{"a", "b", "c"}, engine.StatusPass},
		{"too many", []string{"a", "b", "c", "d", "e", "f"}, engine.StatusFail},
	} {
		t.Run(tc.name, func(t *testing.T) {
			org := healthyOrg()
			org.EffectiveAdmins = people(tc.users...)
			got := evaluate(t, snapshotWith([]scm.Repository{hardenedRepo()}, org))
			assertStatuses(t, got, engine.InstanceResourceName, map[string]engine.Status{"CIS-1.3.3": tc.want})
		})
	}
}

// An over-count is conclusive even through an Entra group; an under-count is
// not.
func TestOrganizationAdminLowerBounds(t *testing.T) {
	org := healthyOrg()
	org.EffectiveAdmins = scm.EffectivePrincipals{Users: []string{"a", "b", "c", "d", "e", "f"}, Count: 6, Complete: false}
	got := evaluate(t, snapshotWith([]scm.Repository{hardenedRepo()}, org))
	assertStatuses(t, got, engine.InstanceResourceName, map[string]engine.Status{"CIS-1.3.3": engine.StatusFail})

	org.EffectiveAdmins = scm.EffectivePrincipals{Users: []string{"a"}, Count: 1, Complete: false}
	got = evaluate(t, snapshotWith([]scm.Repository{hardenedRepo()}, org))
	assertStatuses(t, got, engine.InstanceResourceName, map[string]engine.Status{"CIS-1.3.3": engine.StatusManual})
}

// Dormancy, schema 2: the population is active, licensed users; a user who
// never signed in counts from account creation.
func TestDormantUserDetection(t *testing.T) {
	for _, tc := range []struct {
		name string
		user scm.User
		want engine.Status
	}{
		{"dormant", scm.User{Name: "ghost", Active: true, Licensed: true, InactiveDays: 400, LastActivityEpoch: 1}, engine.StatusFail},
		{"never signed in since March", scm.User{Name: "invitee", Active: true, Licensed: true, NeverSignedIn: true, AgeDays: 214, InactiveDays: -1}, engine.StatusFail},
		{"never signed in, invited this week", scm.User{Name: "newcomer", Active: true, Licensed: true, NeverSignedIn: true, AgeDays: 3, InactiveDays: -1}, engine.StatusPass},
		{"unlicensed", scm.User{Name: "stakeholder-less", Active: true, Licensed: false, InactiveDays: 400}, engine.StatusPass},
		{"unknown activity", scm.User{Name: "mystery", Active: true, Licensed: true, InactiveDays: -1}, engine.StatusManual},
	} {
		t.Run(tc.name, func(t *testing.T) {
			org := healthyOrg()
			org.Users = append(org.Users, tc.user)
			got := evaluate(t, snapshotWith([]scm.Repository{hardenedRepo()}, org))
			assertStatuses(t, got, engine.InstanceResourceName, map[string]engine.Status{"CIS-1.3.1": tc.want})
		})
	}
}

func TestConfigThresholdsAreHonoured(t *testing.T) {
	cfg := signingConfig()
	cfg.Thresholds.MinApprovers = 0
	cfg.Thresholds.MaxBypassPrincipals = -1
	got := evaluateWith(t, cfg, snapshotWith([]scm.Repository{openRepo()}, healthyOrg()))
	assertStatuses(t, got, "Fabrikam/open", map[string]engine.Status{
		"CIS-1.1.3":  engine.StatusPass,
		"CIS-1.1.16": engine.StatusPass, // the bypass check is off
	})
}

func TestExcludedChecksDoNotRun(t *testing.T) {
	cfg := config.Default()
	cfg.Exclude = []string{"CIS-1.1.3"}
	eng, err := engine.New(context.Background(), cfg, scm.PlatformAzureDevOps)
	if err != nil {
		t.Fatalf("build engine: %v", err)
	}
	for _, c := range eng.Checks() {
		if c.ID == "CIS-1.1.3" {
			t.Fatal("CIS-1.1.3 was excluded but is still selected")
		}
	}
}

// An ID that names no control is a typo, and reading it silently is what makes
// it dangerous.
func TestUnknownCheckIDIsRejected(t *testing.T) {
	for name, mutate := range map[string]func(*config.Config){
		"exclude": func(c *config.Config) { c.Exclude = []string{"CIS-9.9.9"} },
		"include": func(c *config.Config) { c.Include = []string{"CIS-1.1.3", "CIS-0.0.0"} },
		"exception": func(c *config.Config) {
			c.Exceptions = []config.Exception{{Control: "CIS-1.1.31", Resources: []string{"*/*"}, Reason: "typo", Expires: "2099-01-01"}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := config.Default()
			mutate(&cfg)
			if _, err := engine.New(context.Background(), cfg, scm.PlatformAzureDevOps); err == nil {
				t.Error("engine.New accepted a check ID that is not in the bundle")
			} else if !strings.Contains(err.Error(), "azure-devops-bench list-checks") {
				t.Errorf("error = %v", err)
			} else if name == "exception" && !strings.Contains(err.Error(), "exceptions[0]: control CIS-1.1.31") {
				t.Errorf("the error does not name the exception entry: %v", err)
			}
		})
	}
}

// IDs are matched as include and exclude match them, ignoring case and
// surrounding space, and the exceptions themselves are applied the same way:
// validation and application must agree about what is known.
func TestKnownCheckIDsAreAcceptedWhateverTheirSpelling(t *testing.T) {
	cfg := config.Default()
	cfg.Exclude = []string{"  cis-1.1.3  "}
	cfg.Exceptions = []config.Exception{{Control: " cis-1.1.13 ", Resources: []string{"*/*"}, Reason: "migration", Expires: "2099-01-01"}}
	if _, err := engine.New(context.Background(), cfg, scm.PlatformAzureDevOps); err != nil {
		t.Errorf("a valid ID with different case and padding was rejected: %v", err)
	}
}

func TestAnUnknownPlatformSelectsNothing(t *testing.T) {
	if _, err := engine.New(context.Background(), config.Default(), "bitbucket-dc"); err == nil {
		t.Error("no control here applies to another platform")
	}
}

func TestEveryBundledCheckIsExercised(t *testing.T) {
	bundle, err := checks.Load()
	if err != nil {
		t.Fatalf("load bundle: %v", err)
	}
	got := evaluate(t, snapshotWith([]scm.Repository{hardenedRepo(), openRepo(), unknownRepo(), emptyRepo()}, healthyOrg()))
	for _, c := range bundle.Checks {
		if _, ok := got[c.ID]; !ok {
			t.Errorf("check %s produced no findings; is its Rego package %q correct?", c.ID, c.Package)
		}
	}
	if len(bundle.Checks) != len(got) {
		t.Errorf("bundle has %d checks but %d produced findings", len(bundle.Checks), len(got))
	}
	if len(bundle.Checks) != 24 {
		t.Errorf("bundle has %d controls; v0.1 ships 24", len(bundle.Checks))
	}
}

// The report says how many repositories its repository controls covered,
// counting what was evaluated rather than what the snapshot holds: the CLI's
// "audited nothing" exit and the machine formats' coverage failure both read
// it, and a disabled repository skipped by configuration was audited by
// nothing.
func TestReportCountsTheRepositoriesItEvaluated(t *testing.T) {
	ctx := context.Background()
	disabled := hardenedRepo()
	disabled.Slug, disabled.Name, disabled.FullName = "old", "old", "Fabrikam/old"
	disabled.Archived, disabled.Disabled = true, true
	snapshot := snapshotWith([]scm.Repository{hardenedRepo(), openRepo(), disabled}, healthyOrg())

	for _, tc := range []struct {
		skip bool
		want int
	}{{false, 3}, {true, 2}} {
		cfg := config.Default()
		cfg.SkipArchivedRepositories = tc.skip
		eng, err := engine.New(ctx, cfg, scm.PlatformAzureDevOps)
		if err != nil {
			t.Fatal(err)
		}
		rep, err := eng.Evaluate(ctx, snapshot)
		if err != nil {
			t.Fatal(err)
		}
		if rep.Repositories != tc.want {
			t.Errorf("skipArchivedRepositories=%v: Repositories = %d, want %d", tc.skip, rep.Repositories, tc.want)
		}
	}

	// Whatever controls are selected: an organization-only selection still
	// evaluated the repositories it was given.
	cfg := config.Default()
	cfg.Include = []string{"CIS-1.3.3"}
	eng, err := engine.New(ctx, cfg, scm.PlatformAzureDevOps)
	if err != nil {
		t.Fatal(err)
	}
	rep, _ := eng.Evaluate(ctx, snapshotWith([]scm.Repository{hardenedRepo()}, healthyOrg()))
	if rep.Repositories != 1 {
		t.Errorf("an organization-only selection counted %d repositories", rep.Repositories)
	}
	rep, _ = eng.Evaluate(ctx, snapshotWith(nil, healthyOrg()))
	if rep.Repositories != 0 {
		t.Errorf("an organization with no repositories counted %d", rep.Repositories)
	}
}

// A repository's input holds the repository and nothing of its siblings; the
// organization is evaluated on its own.
func TestRepositoryInputCarriesOnlyItsOwnScope(t *testing.T) {
	a, b := hardenedRepo(), openRepo()
	got := evaluate(t, snapshotWith([]scm.Repository{a, b}, healthyOrg()))
	if got["CIS-1.1.3"]["Fabrikam/hardened"] != engine.StatusPass || got["CIS-1.1.3"]["Fabrikam/open"] != engine.StatusFail {
		t.Errorf("verdicts leaked between repositories: %v", got["CIS-1.1.3"])
	}
}

// Conventions: a 10,000-repository snapshot evaluates in well under a minute.
// A smaller one keeps the suite fast; the per-repository cost is what the
// test bounds, with room for the race detector.
func TestEvaluationScalesWithRepositories(t *testing.T) {
	if testing.Short() {
		t.Skip("scale test")
	}
	const n = 1000
	repos := make([]scm.Repository, n)
	for i := range repos {
		r := hardenedRepo()
		r.FullName = fmt.Sprintf("Fabrikam/r%04d", i)
		repos[i] = r
	}
	ctx := context.Background()
	eng, err := engine.New(ctx, signingConfig(), scm.PlatformAzureDevOps)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	rep, err := eng.Evaluate(ctx, snapshotWith(repos, healthyOrg()))
	if err != nil {
		t.Fatal(err)
	}
	took := time.Since(start)
	if rep.Repositories != n {
		t.Fatalf("evaluated %d", rep.Repositories)
	}
	// 1,000 repositories in under 30s, race detector included, is 10,000 in
	// well under a minute without it.
	if took > 30*time.Second {
		t.Errorf("%d repositories took %s", n, took)
	}
	t.Logf("%d repositories evaluated in %s", n, took)
}
