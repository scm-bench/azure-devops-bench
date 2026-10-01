package scm_test

import (
	"encoding/json"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/scm-bench/azure-devops-bench/internal/scm"
)

// The JSON field names are the contract between the fetcher and every rule.
//
// Nothing in Go enforces it. Rego reads `resource.branchRestrictions` as a
// string, so renaming the tag on BranchRestrictions compiles cleanly, passes
// vet, and turns every branch protection control into MANUAL on every
// repository — a silent, total loss of coverage that looks like an instance
// nobody can read. A snapshot is also meant to be captured once and evaluated
// later, so a rename breaks archives that were valid when they were written.
//
// The shape is shared with bitbucket-bench by copy, so this list is also the
// one place a reader can compare the two benches' schema 2 field for field.
// It is deliberately a list of strings rather than anything clever: changing
// it means changing the schema, which means bumping SchemaVersion, updating
// the rules, and telling the other bench.
func TestSnapshotJSONContract(t *testing.T) {
	for _, tc := range []struct {
		value any
		want  []string
	}{
		{scm.Snapshot{}, []string{"schemaVersion", "metadata", "organization", "projects"}},
		{scm.Metadata{}, []string{
			"tool", "toolVersion", "platform", "baseUrl", "generatedAt", "warnings", "unlisted",
			"deployment", "apiVersion", "authMethod",
		}},
		{scm.Organization{}, []string{"admins", "effectiveAdmins", "users", "available", "errors", "repositoryCreators"}},
		// hasRepositoryAccess is gone in schema 2: CIS-1.3.1's population is
		// the active, licensed users, which is something a token can read.
		{scm.User{}, []string{
			"name", "displayName", "emailAddress", "active", "licensed", "createdEpoch", "ageDays", "neverSignedIn",
			"lastActivityEpoch", "inactiveDays", "accessLevel", "guest",
		}},
		{scm.Project{}, []string{"key", "name", "type", "public", "permissions", "repositories", "id", "visibility"}},
		{scm.Repository{}, []string{
			"slug", "name", "projectKey", "fullName", "public", "archived", "forkable", "empty",
			"defaultBranch", "defaultBranchDisplay", "pullRequestSettings", "branchRestrictions",
			"requiredBuilds", "hooks", "branches", "files", "permissions", "admins", "available", "errors",
			"id", "fork", "parentRepository", "disabled", "bypass", "forcePushers", "deleters",
			"advancedSecurity", "policies",
		}},
		{scm.PullRequestSettings{}, []string{
			"requiredApprovers", "requiredAllApprovers", "requiredAllTasksComplete", "requiredSuccessfulBuilds",
			"unapproveOnUpdate", "mergeStrategies", "defaultStrategy",
			"minimumApproverCount", "authorApprovalCounts", "lastPusherCannotApprove",
			"resetRejectionsOnSourcePush", "requireVoteOnLastIteration", "allowDownvotes",
			"workItemLinkingRequired", "requiredReviewers",
		}},
		{scm.BranchRestriction{}, []string{
			"id", "type", "matcherId", "matcherText", "matcherType", "scope",
			"matchesDefaultBranch", "matchUnknown", "exemptUsers", "exemptGroups", "exemptAccessKeys",
			"exemptPrincipals", "exemptAccessKeyIds", "derived", "derivedFrom",
		}},
		{scm.RequiredBuild{}, []string{
			"id", "buildParentKeys", "matcherId", "matcherType", "matcherText", "exemptMatcherId",
			"matchesDefaultBranch", "matchUnknown", "kind", "name", "conditional", "pathFilters",
			"expiresOnTargetUpdate",
		}},
		{scm.EffectivePrincipals{}, []string{"users", "groups", "count", "complete", "serviceIdentities", "everyone"}},
		{scm.Permissions{}, []string{"users", "groups", "defaultPermission", "defaultPermissionKnown", "publicAccess", "everyoneGrants"}},
		{scm.Branch{}, []string{"id", "displayId", "isDefault", "latestCommit", "latestCommitEpoch", "ageDays"}},
		{scm.Hook{}, []string{"key", "name", "type", "enabled", "configured", "scope"}},
		{scm.Bypass{}, []string{"push", "pullRequest", "admins"}},
		{scm.ProjectPrincipals{}, []string{"project", "principals", "adminsExact"}},
		{scm.Policy{}, []string{"id", "type", "typeId", "blocking", "scope", "matchKind"}},
		{scm.RequiredReviewer{}, []string{"id", "blocking", "minimumApprovers", "pathFilters", "reviewers"}},
		{scm.AdvancedSecurity{}, []string{
			"secretProtection", "blockPushes", "blockPushesKnown", "codeSecurity", "codeQL", "dependencyScanning",
		}},
	} {
		typ := reflect.TypeOf(tc.value)
		t.Run(typ.Name(), func(t *testing.T) {
			got := jsonFieldNames(t, typ)
			sort.Strings(got)
			want := append([]string(nil), tc.want...)
			sort.Strings(want)
			if !reflect.DeepEqual(got, want) {
				t.Errorf("JSON field names changed.\n got: %v\nwant: %v\n\n"+
					"Rego reads these by name, so a rename silently turns controls into MANUAL "+
					"and invalidates archived snapshots. If this is deliberate, bump scm.SchemaVersion, "+
					"update the rules, and edit this list.", got, want)
			}
		})
	}
}

// A version bump is what tells an old snapshot it can no longer be read, so it
// is worth one assertion of its own rather than living only in a struct tag.
func TestSchemaVersionIsPinned(t *testing.T) {
	if scm.SchemaVersion != "2" {
		t.Errorf("SchemaVersion = %q; changing it is a breaking change for archived snapshots, "+
			"so update this test only alongside the rules that read them", scm.SchemaVersion)
	}
}

// Round-tripping catches the other half: a field that marshals but cannot be
// read back, which is exactly what `scan --snapshot-in` does with a file
// written by `--snapshot-out` weeks earlier.
func TestSnapshotRoundTrips(t *testing.T) {
	original := scm.Snapshot{
		SchemaVersion: scm.SchemaVersion,
		Metadata: scm.Metadata{
			Tool: "azure-devops-bench", Platform: scm.PlatformAzureDevOps,
			BaseURL: "https://dev.azure.com/fabrikam", Warnings: []string{"a group could not be expanded"},
			Deployment: scm.DeploymentServices, APIVersion: "7.1", AuthMethod: "pat",
			Unlisted: []string{"Fabrikam-Fiber-Git"},
		},
		Organization: scm.Organization{
			EffectiveAdmins: scm.EffectivePrincipals{
				Users: []string{"alice@fabrikam.com"}, Count: 1, Complete: true,
				ServiceIdentities: []string{"Project Collection Build Service (fabrikam)"},
			},
			Users: []scm.User{{
				Name: "alice@fabrikam.com", Active: true, Licensed: true, InactiveDays: -1,
				NeverSignedIn: true, CreatedEpoch: 1767225600, AgeDays: 273, AccessLevel: "express",
			}},
			Available: map[string]bool{"users": true},
			RepositoryCreators: []scm.ProjectPrincipals{{
				Project:    "Fabrikam-Fiber-Git",
				Principals: scm.EffectivePrincipals{Users: []string{"bob@fabrikam.com"}, Count: 1, Complete: true},
			}},
		},
		Projects: []scm.Project{{Key: "Fabrikam-Fiber-Git", ID: "6ce954b1", Visibility: "private", Repositories: []scm.Repository{{
			FullName: "Fabrikam-Fiber-Git/app",
			BranchRestrictions: []scm.BranchRestriction{{
				Type: "pull-request-only", MatchesDefaultBranch: true, Derived: true,
				DerivedFrom: []string{"policy 18 Minimum number of reviewers"},
			}},
			RequiredBuilds:   []scm.RequiredBuild{{Kind: "status", Name: "security/signed-commits", MatchesDefaultBranch: true}},
			Bypass:           scm.Bypass{Push: scm.EffectivePrincipals{Users: []string{"carol@fabrikam.com"}, Count: 1, Complete: true}},
			AdvancedSecurity: scm.AdvancedSecurity{SecretProtection: true, BlockPushes: true, BlockPushesKnown: true},
			Available:        map[string]bool{"branchRestrictions": true},
		}}}},
	}

	raw, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back scm.Snapshot
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !reflect.DeepEqual(original, back) {
		t.Errorf("snapshot did not survive a round trip\n got: %+v\nwant: %+v", back, original)
	}
}

func jsonFieldNames(t *testing.T, typ reflect.Type) []string {
	t.Helper()
	var out []string
	for _, f := range reflect.VisibleFields(typ) {
		tag := f.Tag.Get("json")
		if tag == "-" {
			continue
		}
		name := strings.Split(tag, ",")[0]
		if name == "" {
			t.Errorf("%s.%s has no json tag; the rules read this struct by name", typ.Name(), f.Name)
			continue
		}
		out = append(out, name)
	}
	return out
}
