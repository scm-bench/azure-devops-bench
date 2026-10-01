package azuredevops

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/scm-bench/azure-devops-bench/internal/config"
	"github.com/scm-bench/azure-devops-bench/internal/scm"
)

var testNow = time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)

type fetchSetup struct {
	cfg      config.Config
	opts     FetchOptions
	endpoint *Endpoint
	token    string
}

func fetchWith(t *testing.T, f *fakeOrg, mutate func(*fetchSetup)) (*scm.Snapshot, error) {
	t.Helper()
	setup := &fetchSetup{
		cfg:      config.Default(),
		opts:     FetchOptions{ToolVersion: "test", Now: testNow, Concurrency: 2},
		endpoint: f.endpoint(),
		token:    "pat-secret-value",
	}
	if mutate != nil {
		mutate(setup)
	}
	client, err := NewClient(Options{Endpoint: setup.endpoint, Token: setup.token, Timeout: 5 * time.Second, MaxRetries: 1})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	client.sleep = func(context.Context, time.Duration) error { return nil }
	return NewFetcher(client, setup.cfg).Fetch(context.Background(), setup.opts)
}

func mustFetch(t *testing.T, f *fakeOrg, mutate func(*fetchSetup)) *scm.Snapshot {
	t.Helper()
	snapshot, err := fetchWith(t, f, mutate)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	return snapshot
}

func findRepo(t *testing.T, s *scm.Snapshot, fullName string) scm.Repository {
	t.Helper()
	for _, p := range s.Projects {
		for _, r := range p.Repositories {
			if r.FullName == fullName {
				return r
			}
		}
	}
	t.Fatalf("repository %s not in snapshot", fullName)
	return scm.Repository{}
}

func restrictionOf(r scm.Repository, kind string) (scm.BranchRestriction, bool) {
	for _, br := range r.BranchRestrictions {
		if br.Type == kind {
			return br, true
		}
	}
	return scm.BranchRestriction{}, false
}

func TestFetchBuildsTheServicesSnapshot(t *testing.T) {
	f := newFakeOrg(t)
	s := mustFetch(t, f, nil)

	if s.SchemaVersion != scm.SchemaVersion || s.Metadata.Platform != scm.PlatformAzureDevOps {
		t.Fatalf("metadata = %+v", s.Metadata)
	}
	if s.Metadata.Deployment != scm.DeploymentServices || s.Metadata.APIVersion != "7.1" || s.Metadata.AuthMethod != AuthPAT {
		t.Errorf("deployment/apiVersion/authMethod = %q/%q/%q", s.Metadata.Deployment, s.Metadata.APIVersion, s.Metadata.AuthMethod)
	}
	if len(s.Projects) != 3 {
		t.Fatalf("projects = %d, want the three in Microsoft's sample", len(s.Projects))
	}

	repo := findRepo(t, s, "Fabrikam-Fiber-Git/Fabrikam-Fiber-Git")
	if repo.DefaultBranch != "refs/heads/master" || repo.DefaultBranchDisplay != "master" || repo.Empty {
		t.Errorf("default branch = %q/%q empty=%v", repo.DefaultBranch, repo.DefaultBranchDisplay, repo.Empty)
	}

	// Policy projection: the project-wide DefaultBranch minimum (2, reset on
	// push) binds; the optional minimum of 1 from the sample does not count.
	pr := repo.PullRequestSettings
	if pr.RequiredApprovers != 2 || pr.MinimumApproverCount != 2 || !pr.UnapproveOnUpdate || !pr.LastPusherCannotApprove {
		t.Errorf("pull request settings = %+v", pr)
	}
	if !pr.RequiredAllTasksComplete {
		t.Error("the prefix-scoped comment policy covers master and must count")
	}
	if pr.WorkItemLinkingRequired {
		t.Error("deleted and disabled work item policies must not count")
	}
	allowed := map[string]bool{}
	for _, m := range pr.MergeStrategies {
		allowed[m.ID] = m.Enabled
	}
	if !allowed["squash"] || !allowed["rebase-ff-only"] || allowed["no-ff"] || allowed["rebase-no-ff"] {
		t.Errorf("merge strategies = %+v", pr.MergeStrategies)
	}
	if len(pr.RequiredReviewers) != 1 || pr.RequiredReviewers[0].ID != 17 || len(pr.RequiredReviewers[0].PathFilters) != 2 {
		t.Errorf("required reviewers = %+v", pr.RequiredReviewers)
	}

	// Checks: CI and the signature status count; the path-filtered docs
	// build is recorded as conditional.
	var names []string
	for _, b := range repo.RequiredBuilds {
		names = append(names, b.Name)
		switch b.Name {
		case "CI":
			if b.Kind != "build" || b.Conditional || !b.ExpiresOnTargetUpdate {
				t.Errorf("CI = %+v", b)
			}
		case "security/verify-signatures":
			if b.Kind != "status" || b.Conditional {
				t.Errorf("status = %+v", b)
			}
		case "docs":
			if !b.Conditional || len(b.PathFilters) != 1 {
				t.Errorf("docs build = %+v", b)
			}
		}
	}
	if len(repo.RequiredBuilds) != 3 {
		t.Errorf("required builds = %v", names)
	}

	// Derived restrictions: a required policy applies, so pull requests are
	// required and deletion refused; force push is held only by the branch's
	// creator, who lacks the push bypass, so nobody can actually rewrite it.
	for _, kind := range []string{scm.RestrictionPullRequestOnly, scm.RestrictionNoDeletes, scm.RestrictionFastForwardOnly} {
		br, ok := restrictionOf(repo, kind)
		if !ok {
			t.Errorf("no %s restriction derived", kind)
			continue
		}
		if !br.Derived || !br.MatchesDefaultBranch || len(br.DerivedFrom) == 0 || br.Scope != "PROJECT" {
			t.Errorf("%s = %+v", kind, br)
		}
		if br.ExemptPrincipals.Count != 0 || !br.ExemptPrincipals.Complete {
			t.Errorf("%s exempt = %+v, want nobody, complete", kind, br.ExemptPrincipals)
		}
	}
	if repo.ForcePushers.Count != 1 || repo.ForcePushers.Users[0] != "dev@mailserver.com" {
		t.Errorf("force pushers = %+v, want the branch's creator", repo.ForcePushers)
	}

	// Administrators: Project Administrators' members, less the organization
	// administrator, less the deactivated account.
	if !slices.Equal(repo.Admins.Users, []string{"bob@fabrikam.com", "carol@fabrikam.com"}) || !repo.Admins.Complete {
		t.Errorf("admins = %+v", repo.Admins)
	}
	if !repo.Available["admins"] || !repo.Available["orgAdminsExact"] {
		t.Errorf("admin availability = %v", repo.Available)
	}
	if !slices.Equal(repo.Deleters.Users, []string{"bob@fabrikam.com", "carol@fabrikam.com"}) {
		t.Errorf("deleters = %+v", repo.Deleters)
	}
	if len(repo.Permissions.EveryoneGrants) != 1 || repo.Permissions.EveryoneGrants[0].Permission != "GenericRead" {
		t.Errorf("everyone grants = %+v", repo.Permissions.EveryoneGrants)
	}
	if repo.Bypass.Push.Count != 0 || !repo.Bypass.Admins.Complete {
		t.Errorf("bypass = %+v", repo.Bypass)
	}

	if !slices.Equal(repo.Files.SecurityPolicyPaths, []string{"SECURITY.md"}) || !repo.Available["files"] {
		t.Errorf("security policy = %+v (available %v)", repo.Files, repo.Available["files"])
	}
	if len(repo.Branches) != 3 || !repo.Available["branchAges"] {
		t.Errorf("branches = %+v", repo.Branches)
	}
	if !repo.AdvancedSecurity.SecretProtection || !repo.AdvancedSecurity.BlockPushes || !repo.AdvancedSecurity.BlockPushesKnown {
		t.Errorf("advanced security = %+v", repo.AdvancedSecurity)
	}

	// Microsoft's project list sample carries no visibility. Unknown is not
	// private: the field stays unavailable and a warning says why.
	if repo.Available["visibility"] {
		t.Error("visibility must be unavailable when the project list omits it")
	}
	if !warned(s, "did not report its visibility") {
		t.Errorf("warnings = %v", s.Metadata.Warnings)
	}
}

func warned(s *scm.Snapshot, fragment string) bool {
	for _, w := range s.Metadata.Warnings {
		if strings.Contains(w, fragment) {
			return true
		}
	}
	return false
}

func TestOrganizationAdministratorsAndUsers(t *testing.T) {
	s := mustFetch(t, newFakeOrg(t), nil)
	org := s.Organization

	// Project Collection Administrators: alice directly, the build service
	// through Project Collection Service Accounts — listed, not counted.
	if !slices.Equal(org.EffectiveAdmins.Users, []string{"alice@fabrikam.com"}) || org.EffectiveAdmins.Count != 1 {
		t.Errorf("effective admins = %+v", org.EffectiveAdmins)
	}
	if !slices.Equal(org.EffectiveAdmins.ServiceIdentities, []string{"Project Collection Build Service (fabrikam)"}) {
		t.Errorf("service identities = %v", org.EffectiveAdmins.ServiceIdentities)
	}
	if !org.EffectiveAdmins.Complete || !org.Available["admins"] {
		t.Errorf("admins complete=%v available=%v", org.EffectiveAdmins.Complete, org.Available["admins"])
	}
	if len(org.Admins) != 2 {
		t.Errorf("direct members = %+v", org.Admins)
	}

	// Entitlements came in two pages, the second reached through the body's
	// continuationToken.
	if len(org.Users) != 4 {
		t.Fatalf("users = %+v", org.Users)
	}
	byName := map[string]scm.User{}
	for _, u := range org.Users {
		byName[u.Name] = u
	}
	if u := byName["bob@fabrikam.com"]; !u.Active || !u.Licensed || u.InactiveDays != 303 {
		t.Errorf("bob = %+v", u)
	}
	if u := byName["invitee@partner.example"]; !u.NeverSignedIn || u.LastActivityEpoch != 0 || u.InactiveDays != -1 || !u.Guest || u.CreatedEpoch == 0 || u.AgeDays != 259 {
		t.Errorf("invitee = %+v; the 0001-01-01 sentinel and pending status both mean never signed in", u)
	}
	if u := byName["former@fabrikam.com"]; u.Active || u.Licensed {
		t.Errorf("former = %+v; a disabled entitlement is outside the population", u)
	}
	for _, key := range []string{"users", "userActivity", "licensedUsers", "repositoryCreators"} {
		if !org.Available[key] {
			t.Errorf("organization availability %s = false", key)
		}
	}
	if len(org.RepositoryCreators) == 0 {
		t.Fatal("no repository creators recorded")
	}
	for _, c := range org.RepositoryCreators {
		if c.Principals.Count != 0 || !c.AdminsExact {
			t.Errorf("creators in %s = %+v", c.Project, c)
		}
	}
}

// The read-only property is a test, not a promise: every request the scan
// sent is a GET.
func TestOnlyGETRequestsAreIssued(t *testing.T) {
	f := newFakeOrg(t)
	mustFetch(t, f, nil)
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.requests) < 20 {
		t.Fatalf("only %d requests recorded; the scan did not run", len(f.requests))
	}
	for _, r := range f.requests {
		if r.Method != http.MethodGet {
			t.Errorf("%s %s: the scan must only read", r.Method, r.URL.Path)
		}
		if r.Header.Get("X-TFS-FedAuthRedirect") != "Suppress" {
			t.Errorf("%s: X-TFS-FedAuthRedirect not sent", r.URL.Path)
		}
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Basic ") {
			t.Errorf("%s: a PAT goes out as Basic", r.URL.Path)
		}
	}
}

func TestThePATIsSentAsBasicWithAnEmptyUserName(t *testing.T) {
	f := newFakeOrg(t)
	mustFetch(t, f, nil)
	got := f.requestsTo("/_apis/projects")[0].Header.Get("Authorization")
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte(":pat-secret-value"))
	if got != want {
		t.Errorf("Authorization = %q, want %q", got, want)
	}
}

// An Entra access token is a JWT, and goes out as a bearer token.
func TestAJWTIsSentAsABearerToken(t *testing.T) {
	f := newFakeOrg(t)
	jwt := "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJhdWQiOiI0OTliODRhYyJ9.c2lnbmF0dXJl"
	s := mustFetch(t, f, func(s *fetchSetup) { s.token = jwt })
	if got := f.requestsTo("/_apis/projects")[0].Header.Get("Authorization"); got != "Bearer "+jwt {
		t.Errorf("Authorization = %q", got)
	}
	if s.Metadata.AuthMethod != AuthEntra {
		t.Errorf("authMethod = %q", s.Metadata.AuthMethod)
	}
}

// The credential must not reach the snapshot in any form.
func TestTheTokenNeverReachesTheSnapshot(t *testing.T) {
	s := mustFetch(t, newFakeOrg(t), nil)
	raw, _ := json.Marshal(s)
	for _, secret := range []string{"pat-secret-value", base64.StdEncoding.EncodeToString([]byte(":pat-secret-value"))} {
		if strings.Contains(string(raw), secret) {
			t.Errorf("the snapshot contains the credential (%q)", secret)
		}
	}
}

// A rejected credential is answered with 203 and an HTML sign-in page when
// redirect suppression is not honoured — a success status. Reading it as data
// would produce a report of nothing; it is a rejected credential.
func TestA203SignInPageIsARejectedCredential(t *testing.T) {
	f := newFakeOrg(t)
	f.handle("/fabrikam/_apis/projects", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusNonAuthoritativeInfo)
		w.Write([]byte("<html><body>Sign In</body></html>"))
	})
	_, err := fetchWith(t, f, nil)
	if err == nil || !strings.Contains(err.Error(), "credential rejected") {
		t.Fatalf("err = %v, want a rejected credential", err)
	}
	if strings.Contains(err.Error(), "pat-secret-value") {
		t.Error("the error message contains the token")
	}
}

func TestA401AtThePreflightIsARejectedCredential(t *testing.T) {
	f := newFakeOrg(t)
	f.fail("/fabrikam/_apis/projects", http.StatusUnauthorized, "TF400813: The user is not authorized to access this resource.")
	_, err := fetchWith(t, f, nil)
	if err == nil || !strings.Contains(err.Error(), "credential rejected") || !strings.Contains(err.Error(), "1 December 2026") {
		t.Fatalf("err = %v", err)
	}
}

// A 200 that is not JSON is a sign-in or proxy page.
func TestANonJSON200AtThePreflightIsARejectedCredential(t *testing.T) {
	f := newFakeOrg(t)
	f.handle("/fabrikam/_apis/projects", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html>please sign in</html>"))
	})
	if _, err := fetchWith(t, f, nil); err == nil || !strings.Contains(err.Error(), "not JSON") {
		t.Fatalf("err = %v", err)
	}
}

// A redirect is never followed: following one hands the Authorization header
// to wherever it points.
func TestARedirectIsNotFollowed(t *testing.T) {
	f := newFakeOrg(t)
	f.handle("/fabrikam/_apis/projects", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://login.microsoftonline.com/common/oauth2/authorize", http.StatusFound)
	})
	_, err := fetchWith(t, f, nil)
	if err == nil || !strings.Contains(err.Error(), "sign-in page") {
		t.Fatalf("err = %v", err)
	}
	if n := len(f.requestsTo("/_apis/projects")); n != 1 {
		t.Errorf("%d requests to the projects endpoint; the redirect was followed", n)
	}
}

func TestAForbiddenProjectListNamesTheScopes(t *testing.T) {
	f := newFakeOrg(t)
	f.fail("/fabrikam/_apis/projects", http.StatusForbidden, "TF401027: You need the permission.")
	if _, err := fetchWith(t, f, nil); err == nil || !strings.Contains(err.Error(), "vso.project") {
		t.Fatalf("err = %v", err)
	}
}

func TestANotFoundOrganizationSaysSo(t *testing.T) {
	f := newFakeOrg(t)
	f.fail("/fabrikam/_apis/projects", http.StatusNotFound, "TF400898: no organization")
	if _, err := fetchWith(t, f, nil); err == nil || !strings.Contains(err.Error(), "no Azure DevOps organization") {
		t.Fatalf("err = %v", err)
	}
}

// Without vso.security_manage the access control lists answer 401 or 403.
// What needs them becomes unknown; what does not still decides.
func TestUnreadableAccessControlListsMakeExemptionsUnknown(t *testing.T) {
	f := newFakeOrg(t)
	f.fail("/fabrikam/_apis/accesscontrollists/2e9eb7ed-3c0a-47d4-87c1-0ffdd275fd87", http.StatusUnauthorized,
		"TF400813: The user is not authorized to access this resource.")
	s := mustFetch(t, f, nil)

	repo := findRepo(t, s, "Fabrikam-Fiber-Git/Fabrikam-Fiber-Git")
	pr, ok := restrictionOf(repo, scm.RestrictionPullRequestOnly)
	if !ok || pr.ExemptPrincipals.Complete {
		t.Errorf("pull-request-only = %+v; it exists (a required policy applies) and its exemptions are unknown", pr)
	}
	for _, key := range []string{"bypass", "admins", "deleters", "permissions"} {
		if repo.Available[key] {
			t.Errorf("%s available without access control lists", key)
		}
	}
	if !repo.Available["pullRequestSettings"] {
		t.Error("policy-based settings do not need access control lists")
	}
	if s.Organization.Available["repositoryCreators"] {
		t.Error("repository creators cannot be known without access control lists")
	}
	if !warned(s, "vso.security_manage") {
		t.Errorf("warnings = %v", s.Metadata.Warnings)
	}
	// One failed probe, not one per repository and project.
	if n := len(f.requestsTo("accesscontrollists")); n != 1 {
		t.Errorf("%d ACL requests after the first was refused", n)
	}
}

// 404 TF401019 conflates "does not exist" with "you may not see it". On a
// repository the scan just listed, it means access.
func TestTF401019OnARepositoryIsUnreadable(t *testing.T) {
	f := newFakeOrg(t)
	f.fail("/fabrikam/"+projectID+"/_apis/git/repositories/"+repoMainID+"/refs", http.StatusNotFound,
		"TF401019: The Git repository with name or identifier Fabrikam-Fiber-Git does not exist or you do not have permissions for the operation you are attempting.")
	s := mustFetch(t, f, nil)
	repo := findRepo(t, s, "Fabrikam-Fiber-Git/Fabrikam-Fiber-Git")
	if repo.Available["branches"] || repo.Available["defaultBranch"] || repo.Empty {
		t.Errorf("availability = %v empty=%v; a TF401019 is not an empty repository", repo.Available, repo.Empty)
	}
	if len(repo.Errors) == 0 || !strings.Contains(strings.Join(repo.Errors, " "), "TF401019") {
		t.Errorf("errors = %v", repo.Errors)
	}
}

// A folder that is not there (TF401174) settles its paths as absent; a 404
// that is about access does not.
func TestSecurityPolicyProbeDistinguishesAbsentFromUnreadable(t *testing.T) {
	f := newFakeOrg(t)
	s := mustFetch(t, f, nil)
	test := findRepo(t, s, "TestGit/TestGit")
	if !test.Available["files"] || len(test.Files.SecurityPolicyPaths) != 0 || len(test.Files.Probed) != 6 {
		t.Errorf("TestGit files = %+v (available %v)", test.Files, test.Available["files"])
	}
	// Three folders for six paths: /, /.github, /docs.
	if n := len(f.requestsTo(repoTestID + "/items")); n != 3 {
		t.Errorf("%d item requests, want one per folder", n)
	}

	f2 := newFakeOrg(t)
	f2.fail("/fabrikam/"+project2ID+"/_apis/git/repositories/"+repoTestID+"/items", http.StatusNotFound,
		"TF401019: The Git repository with name or identifier TestGit does not exist or you do not have permissions for the operation you are attempting.")
	s2 := mustFetch(t, f2, nil)
	if test := findRepo(t, s2, "TestGit/TestGit"); test.Available["files"] {
		t.Error("a TF401019 while browsing must make the probe unavailable, not empty")
	}
}

// Retry-After on a successful response still holds the next request back:
// Azure DevOps sends it with 200 once an identity is over budget.
func TestRetryAfterOnA200DelaysTheNextRequest(t *testing.T) {
	f := newFakeOrg(t)
	f.handle("/fabrikam/_apis/projects", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "7")
		w.Header().Set("X-RateLimit-Remaining", "12")
		w.Header().Set("Content-Type", "application/json")
		w.Write(learnSample(t, "projects-list.json"))
	})
	client, err := NewClient(Options{Endpoint: f.endpoint(), Token: "pat", MaxRetries: 1})
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var slept []time.Duration
	client.sleep = func(_ context.Context, d time.Duration) error {
		mu.Lock()
		slept = append(slept, d)
		mu.Unlock()
		return nil
	}
	var events []RequestEvent
	client.onRequest = func(e RequestEvent) {
		mu.Lock()
		events = append(events, e)
		mu.Unlock()
	}
	if _, err := NewFetcher(client, config.Default()).Fetch(context.Background(), FetchOptions{Now: testNow, Concurrency: 1}); err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if len(slept) == 0 || slept[0] < 6*time.Second || slept[0] > 7*time.Second {
		t.Errorf("slept %v, want about 7s before the request after the 200", slept)
	}
	if events[0].RetryAfter != 7*time.Second || events[0].RateLimitRemaining != "12" {
		t.Errorf("first event = %+v; the trace should see the throttling headers", events[0])
	}
}

// 429 is retried, honouring Retry-After, and then succeeds.
func TestA429IsRetried(t *testing.T) {
	f := newFakeOrg(t)
	var calls int
	f.handle("/fabrikam/_apis/securitynamespaces/2e9eb7ed-3c0a-47d4-87c1-0ffdd275fd87", func(w http.ResponseWriter, _ *http.Request) {
		calls++
		if calls == 1 {
			w.Header().Set("Retry-After", "1")
			writeError(w, http.StatusTooManyRequests, "TF400733: The request has been blocked due to exceeding usage of resource.")
			return
		}
		writeJSON(w, http.StatusOK, collection([]any{}))
	})
	mustFetch(t, f, nil)
	if calls != 2 {
		t.Errorf("calls = %d, want a retry after the 429", calls)
	}
}

// An Entra group's members are visible only once they have signed in, so a
// set reaching through one is a lower bound — never complete.
func TestAnEntraGroupMakesASetALowerBound(t *testing.T) {
	f := newFakeOrg(t)
	f.acls["repoV2/"+projectID][descContrib] = fakeACE{allow: contributorBits | bitPolicyExempt}
	s := mustFetch(t, f, nil)
	repo := findRepo(t, s, "Fabrikam-Fiber-Git/Fabrikam-Fiber-Git")

	push := repo.Bypass.Push
	if push.Complete {
		t.Errorf("push bypass = %+v; Contributors contains an Entra group", push)
	}
	if !slices.Contains(push.Users, "erin@fabrikam.com") || !slices.Contains(push.Users, "dev@mailserver.com") {
		t.Errorf("push bypass users = %v; the visible members still count", push.Users)
	}
	if !slices.Contains(push.Groups, `[fabrikam]\Platform Engineers`) {
		t.Errorf("groups = %v", push.Groups)
	}
	pr, _ := restrictionOf(repo, scm.RestrictionPullRequestOnly)
	if pr.ExemptPrincipals.Complete || pr.ExemptPrincipals.Count < 2 {
		t.Errorf("pull-request-only exempt = %+v", pr.ExemptPrincipals)
	}
	// Dave now holds Force push and the push bypass: he can rewrite master.
	ffo, _ := restrictionOf(repo, scm.RestrictionFastForwardOnly)
	if !slices.Contains(ffo.ExemptPrincipals.Users, "dev@mailserver.com") {
		t.Errorf("fast-forward-only exempt = %+v", ffo.ExemptPrincipals)
	}
}

// A deny on the person beats an allow through any group.
func TestAPersonalDenyRemovesThemFromAGroupsGrant(t *testing.T) {
	f := newFakeOrg(t)
	f.acls["repoV2/"+projectID][descContrib] = fakeACE{allow: contributorBits | bitPolicyExempt}
	f.acls["repoV2/"+projectID][descErin] = fakeACE{deny: bitPolicyExempt}
	s := mustFetch(t, f, nil)
	repo := findRepo(t, s, "Fabrikam-Fiber-Git/Fabrikam-Fiber-Git")
	if slices.Contains(repo.Bypass.Push.Users, "erin@fabrikam.com") {
		t.Errorf("push bypass = %v; erin is denied it", repo.Bypass.Push.Users)
	}
}

// A grant to a group every member belongs to is a grant to everyone, which
// is not expanded and must never read as a small set.
func TestAnEveryoneGroupHoldingABypassIsEveryone(t *testing.T) {
	f := newFakeOrg(t)
	f.acls["repoV2/"+projectID][descPVU] = fakeACE{allow: 2 | 4 | bitPullRequestBypassPolicy}
	s := mustFetch(t, f, nil)
	repo := findRepo(t, s, "Fabrikam-Fiber-Git/Fabrikam-Fiber-Git")
	if !repo.Bypass.PullRequest.Everyone {
		t.Errorf("pull request bypass = %+v", repo.Bypass.PullRequest)
	}
	// Every administrator is a member, so every administrator holds it.
	if !slices.Equal(repo.Bypass.Admins.Users, []string{"alice@fabrikam.com", "bob@fabrikam.com", "carol@fabrikam.com"}) {
		t.Errorf("administrators holding a bypass = %+v", repo.Bypass.Admins)
	}
	var perms []string
	for _, g := range repo.Permissions.EveryoneGrants {
		perms = append(perms, g.Permission)
	}
	if !slices.Contains(perms, "GenericContribute") || !slices.Contains(perms, "PullRequestBypassPolicy") {
		t.Errorf("everyone grants = %v", perms)
	}
	// Project Valid Users is never expanded through Graph.
	if n := len(f.requestsTo("Memberships/vssgp.PVU")); n != 0 {
		t.Errorf("%d expansion requests for an everyone group", n)
	}
}

// The server says which policies apply; the bench checks the answer against
// the documented scope semantics and refuses to decide on a contradiction.
func TestAPolicyReturnedOutsideItsScopeMakesPoliciesUnknown(t *testing.T) {
	f := newFakeOrg(t)
	key := repoMainID + "|refs/heads/master"
	f.branchPol[key] = append(f.branchPol[key], policyObject(40, typeMinReviewers, "Minimum number of reviewers", true, map[string]any{
		"minimumApproverCount": 4, "scope": []any{scope(nil, "refs/heads/release", "Exact")},
	}))
	s := mustFetch(t, f, nil)
	repo := findRepo(t, s, "Fabrikam-Fiber-Git/Fabrikam-Fiber-Git")
	for _, k := range []string{"pullRequestSettings", "branchRestrictions", "requiredBuilds", "mergeStrategies", "unapproveOnUpdate"} {
		if repo.Available[k] {
			t.Errorf("%s available despite a contradiction", k)
		}
	}
	if !strings.Contains(strings.Join(repo.Errors, " "), "policy 40") {
		t.Errorf("errors = %v", repo.Errors)
	}
}

// The other direction: a policy in the project whose scope covers the branch
// but that the per-branch answer left out — the case where "Protect the
// default branch of each repository" might not be resolved by the server.
func TestAPolicyMissingFromTheBranchAnswerMakesPoliciesUnknown(t *testing.T) {
	f := newFakeOrg(t)
	key := repoMainID + "|refs/heads/master"
	var kept []map[string]any
	for _, p := range f.branchPol[key] {
		if idOf(p) != 25 {
			kept = append(kept, p)
		}
	}
	f.branchPol[key] = kept
	s := mustFetch(t, f, nil)
	repo := findRepo(t, s, "Fabrikam-Fiber-Git/Fabrikam-Fiber-Git")
	if repo.Available["pullRequestSettings"] {
		t.Error("a DefaultBranch policy left out of the answer must not let the settings read as complete")
	}
}

// A disabled repository refuses Git requests; none is sent. Access is still
// read, because who may delete or re-enable it still matters.
func TestADisabledRepositoryIsArchivedWithoutGitRequests(t *testing.T) {
	f := newFakeOrg(t)
	s := mustFetch(t, f, func(s *fetchSetup) { s.cfg.SkipArchivedRepositories = false })
	repo := findRepo(t, s, "Fabrikam-Fiber-Git/Archive-2019")
	if !repo.Archived || !repo.Disabled {
		t.Errorf("archived=%v disabled=%v", repo.Archived, repo.Disabled)
	}
	for _, fragment := range []string{repoArchID + "/refs", repoArchID + "/stats", repoArchID + "/items"} {
		if n := len(f.requestsTo(fragment)); n != 0 {
			t.Errorf("%d requests to %s for a disabled repository", n, fragment)
		}
	}
	if q := f.requestsTo("/git/policy/configurations"); len(q) > 0 {
		for _, r := range q {
			if r.URL.Query().Get("repositoryId") == repoArchID {
				t.Error("branch policies requested for a disabled repository")
			}
		}
	}
	if !repo.Available["admins"] {
		t.Error("access to a disabled repository is still evaluated")
	}

	// And by default it is skipped entirely.
	s2 := mustFetch(t, newFakeOrg(t), nil)
	for _, p := range s2.Projects {
		for _, r := range p.Repositories {
			if r.ID == repoArchID {
				t.Error("skipArchivedRepositories should drop disabled repositories")
			}
		}
	}
}

// The repository list sample omits defaultBranch for AnotherRepository, and
// its branch list is empty: an empty repository, decided from the branches.
func TestAnEmptyRepositoryIsDecidedFromItsBranches(t *testing.T) {
	s := mustFetch(t, newFakeOrg(t), nil)
	repo := findRepo(t, s, "Fabrikam-Fiber-Git/AnotherRepository")
	if !repo.Empty || repo.DefaultBranch != "" || !repo.Available["defaultBranch"] || !repo.Available["files"] {
		t.Errorf("empty repository = %+v", repo)
	}
	if !repo.Available["admins"] {
		t.Error("an empty repository's administrators are still evaluated")
	}
}

// A configured default branch that does not exist is reported, and a
// repository with no required policy anywhere still fails the controls that do
// not depend on which branch is the default.
func TestAMissingDefaultBranchFallsBackToRepositoryPolicies(t *testing.T) {
	f := newFakeOrg(t)
	f.json("/fabrikam/"+project2ID+"/_apis/git/repositories", collection([]any{
		map[string]any{"id": repoTestID, "name": "TestGit", "defaultBranch": "refs/heads/main", "project": map[string]any{"id": project2ID, "name": "TestGit"}},
	}))
	s := mustFetch(t, f, nil)
	repo := findRepo(t, s, "TestGit/TestGit")
	if repo.Available["defaultBranch"] || repo.DefaultBranch != "" {
		t.Errorf("default branch = %q available=%v", repo.DefaultBranch, repo.Available["defaultBranch"])
	}
	if !strings.Contains(strings.Join(repo.Errors, " "), "configured default branch refs/heads/main does not exist") {
		t.Errorf("errors = %v", repo.Errors)
	}
	if !repo.Available["branchRestrictions"] {
		t.Fatal("whether any required policy exists can still be answered")
	}
	if _, ok := restrictionOf(repo, scm.RestrictionPullRequestOnly); ok {
		t.Error("no required policy exists in TestGit, so no pull-request-only restriction")
	}
	ffo, ok := restrictionOf(repo, scm.RestrictionFastForwardOnly)
	if !ok || !ffo.MatchUnknown || ffo.MatchesDefaultBranch {
		t.Errorf("fast-forward-only = %+v; its holders on an unknown branch are unknown", ffo)
	}
	if repo.Available["files"] {
		t.Error("nothing was browsed, so the security policy probe is unavailable")
	}
}

// Azure DevOps Server: api-version negotiated down to 7.0, groups expanded
// through IMS because Graph does not exist, and the Services-only APIs
// reported as such rather than tried.
func TestServerDeployment(t *testing.T) {
	f := newFakeOrg(t)
	f.handle("/fabrikam/_apis/projects", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("api-version") == "7.1" {
			writeError(w, http.StatusBadRequest, "The requested REST API version of 7.1 is out of range for this server. The latest REST API version this server supports is 7.0.")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(learnSample(t, "projects-list.json"))
	})
	s := mustFetch(t, f, func(s *fetchSetup) { s.endpoint = f.serverEndpoint() })

	if s.Metadata.Deployment != scm.DeploymentServer || s.Metadata.APIVersion != "7.0" {
		t.Errorf("deployment=%q apiVersion=%q", s.Metadata.Deployment, s.Metadata.APIVersion)
	}
	if n := len(f.requestsTo("/graph/")); n != 0 {
		t.Errorf("%d Graph requests on Azure DevOps Server", n)
	}
	if len(f.requestsTo("vsaex")) != 0 || len(f.requestsTo("advsec")) != 0 {
		t.Error("Services-only APIs were called on Server")
	}
	if s.Organization.Available["users"] {
		t.Error("users cannot be available on Server")
	}
	if !warned(s, "Azure DevOps Server has no user entitlement API") {
		t.Errorf("warnings = %v", s.Metadata.Warnings)
	}
	if !slices.Equal(s.Organization.EffectiveAdmins.Users, []string{"alice@fabrikam.com"}) || !s.Organization.EffectiveAdmins.Complete {
		t.Errorf("admins through IMS = %+v", s.Organization.EffectiveAdmins)
	}
	repo := findRepo(t, s, "Fabrikam-Fiber-Git/Fabrikam-Fiber-Git")
	if !slices.Equal(repo.Admins.Users, []string{"bob@fabrikam.com", "carol@fabrikam.com"}) {
		t.Errorf("repository admins through IMS = %+v", repo.Admins)
	}
	if repo.Available["advancedSecurity"] {
		t.Error("Advanced Security cannot be available on Server")
	}
	for _, r := range f.requestsTo("/_apis/") {
		if v := r.URL.Query().Get("api-version"); v == "7.1" && !strings.Contains(r.URL.Path, "/_apis/projects") {
			t.Errorf("%s used api-version 7.1 after negotiating 7.0", r.URL.Path)
		}
	}
}

func TestServerTooOldForTheAPIVersionsFails(t *testing.T) {
	f := newFakeOrg(t)
	f.fail("/fabrikam/_apis/projects", http.StatusBadRequest, "The requested REST API version of 7.0 is out of range for this server.")
	_, err := fetchWith(t, f, func(s *fetchSetup) { s.endpoint = f.serverEndpoint() })
	if err == nil || !strings.Contains(err.Error(), "Server 2022 or later") {
		t.Fatalf("err = %v", err)
	}
}

func TestNamedTargetsAreResolvedOrRefused(t *testing.T) {
	f := newFakeOrg(t)
	s := mustFetch(t, f, func(s *fetchSetup) {
		s.opts.Repositories = []string{"Fabrikam-Fiber-Git/Fabrikam-Fiber-Git"}
	})
	if len(s.Projects) != 1 || len(s.Projects[0].Repositories) != 1 {
		t.Fatalf("projects = %+v", s.Projects)
	}
	// A targeted project read reports its visibility, unlike the list.
	if s.Projects[0].Visibility != "private" || !s.Projects[0].Repositories[0].Available["visibility"] {
		t.Errorf("visibility = %q", s.Projects[0].Visibility)
	}

	for _, tc := range []struct {
		name string
		opts FetchOptions
		want string
	}{
		{"unknown project", FetchOptions{Projects: []string{"Nope"}}, `project "Nope" not found`},
		{"unknown repository", FetchOptions{Repositories: []string{"Fabrikam-Fiber-Git/nope"}}, `repository "nope" not found`},
		{"malformed repository", FetchOptions{Repositories: []string{"just-a-name"}}, "PROJECT/REPOSITORY"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := fetchWith(t, newFakeOrg(t), func(s *fetchSetup) { s.opts.Projects, s.opts.Repositories = tc.opts.Projects, tc.opts.Repositories })
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

// A project whose repositories cannot be listed is recorded as not audited,
// and the rest of the organization is still scanned.
func TestAnUnlistableProjectMarksTheScanIncomplete(t *testing.T) {
	f := newFakeOrg(t)
	f.fail("/fabrikam/"+project2ID+"/_apis/git/repositories", http.StatusInternalServerError, "TF400898: An Internal Error Occurred.")
	s := mustFetch(t, f, nil)
	if !slices.Equal(s.Metadata.Unlisted, []string{"TestGit"}) {
		t.Errorf("unlisted = %v", s.Metadata.Unlisted)
	}
	findRepo(t, s, "Fabrikam-Fiber-Git/Fabrikam-Fiber-Git")
}

// Microsoft's Graph membership sample uses bare base64 identity descriptors
// instead of prefixed subject descriptors. Reading that as "no members" would
// make a group look empty; the members are resolved either way.
func TestBareBase64MemberDescriptorsAreResolved(t *testing.T) {
	f := newFakeOrg(t)
	encoded := base64.RawStdEncoding.EncodeToString([]byte(descAlice))
	f.handle("/vssps/fabrikam/_apis/graph/Memberships/vssgp.PCA", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, collection([]any{map[string]any{"containerDescriptor": "vssgp.PCA", "memberDescriptor": encoded}}))
	})
	s := mustFetch(t, f, nil)
	if !slices.Equal(s.Organization.EffectiveAdmins.Users, []string{"alice@fabrikam.com"}) {
		t.Errorf("admins = %+v", s.Organization.EffectiveAdmins)
	}

	// The sample itself decodes.
	var doc struct {
		Value []apiMembership `json:"value"`
	}
	if err := json.Unmarshal(learnSample(t, "graph-memberships-down.json"), &doc); err != nil || len(doc.Value) != 1 {
		t.Fatalf("decode sample: %v", err)
	}
	got, ok := decodeBareDescriptor(doc.Value[0].MemberDescriptor)
	if !ok || !strings.HasPrefix(got, "Microsoft.IdentityModel.Claims.ClaimsIdentity;") {
		t.Errorf("sample member descriptor decodes to %q, %v", got, ok)
	}
}

// A group that cannot be expanded leaves the set a lower bound and says so.
func TestAGroupThatCannotBeExpandedIsALowerBound(t *testing.T) {
	f := newFakeOrg(t)
	f.fail("/vssps/fabrikam/_apis/graph/Memberships/vssgp.PA", http.StatusForbidden, "TF50309: The following account does not have sufficient permissions.")
	s := mustFetch(t, f, nil)
	repo := findRepo(t, s, "Fabrikam-Fiber-Git/Fabrikam-Fiber-Git")
	if repo.Admins.Complete {
		t.Errorf("admins = %+v; Project Administrators could not be expanded", repo.Admins)
	}
	if !warned(s, "could not be expanded") {
		t.Errorf("warnings = %v", s.Metadata.Warnings)
	}
}

// Without Project Collection Administrators the organization administrators
// cannot be subtracted, so repository administrator sets are unknown.
func TestUnreadableOrganizationAdministrators(t *testing.T) {
	f := newFakeOrg(t)
	f.identities = append(f.identities, fakeIdentity{Descriptor: "Microsoft.TeamFoundation.Identity;S-1-9-dup", Subject: "vssgp.DUP",
		Name: `[other]\Project Collection Administrators`, Account: "Project Collection Administrators", Group: true, ScopeType: "ServiceHost"})
	s := mustFetch(t, f, nil)
	if s.Organization.Available["admins"] {
		t.Error("an ambiguous Project Collection Administrators search must not be guessed between")
	}
	repo := findRepo(t, s, "Fabrikam-Fiber-Git/Fabrikam-Fiber-Git")
	if repo.Available["admins"] || repo.Available["deleters"] {
		t.Errorf("availability = %v", repo.Available)
	}
}

// Missing entitlements (no vso.memberentitlementmanagement) leave users
// unknown, never an empty directory.
func TestUnreadableEntitlements(t *testing.T) {
	f := newFakeOrg(t)
	f.fail("/vsaex/fabrikam/_apis/userentitlements", http.StatusUnauthorized, "TF400813: The user is not authorized to access this resource.")
	s := mustFetch(t, f, nil)
	if s.Organization.Available["users"] || len(s.Organization.Users) != 0 {
		t.Errorf("users = %v available=%v", s.Organization.Users, s.Organization.Available["users"])
	}
}

// Advanced Security unreadable (no vso.advsec): unknown, not "disabled".
func TestUnreadableAdvancedSecurity(t *testing.T) {
	f := newFakeOrg(t)
	f.fail("/advsec/fabrikam/_apis/management/enablement", http.StatusForbidden, "Access denied")
	s := mustFetch(t, f, nil)
	repo := findRepo(t, s, "Fabrikam-Fiber-Git/Fabrikam-Fiber-Git")
	if repo.Available["advancedSecurity"] || repo.AdvancedSecurity.SecretProtection {
		t.Errorf("advanced security = %+v", repo.AdvancedSecurity)
	}
	// blockPushes is null in TestGit's answer: unknown, not off.
	s2 := mustFetch(t, newFakeOrg(t), nil)
	test := findRepo(t, s2, "TestGit/TestGit")
	if !test.Available["advancedSecurity"] || test.AdvancedSecurity.BlockPushesKnown {
		t.Errorf("TestGit advanced security = %+v", test.AdvancedSecurity)
	}
}

// A branch the dates could not be found for is unknown, not fresh.
func TestBranchesWithoutADateMakeAgesUnknown(t *testing.T) {
	f := newFakeOrg(t)
	// The verbatim stats sample names develop and npaulk/feature, branches
	// the refs sample does not have: two of the three dates are missing.
	f.learn("/fabrikam/"+projectID+"/_apis/git/repositories/"+repoMainID+"/stats/branches", "stats-branches.json")
	s := mustFetch(t, f, nil)
	repo := findRepo(t, s, "Fabrikam-Fiber-Git/Fabrikam-Fiber-Git")
	if repo.Available["branchAges"] {
		t.Error("branch ages must be unavailable when some branches have no date")
	}
	for _, b := range repo.Branches {
		if b.ID == "refs/heads/master" && b.AgeDays <= 0 {
			t.Errorf("master = %+v; its date from the sample is in 2014", b)
		}
	}
}

// The forks list sample names TestGit's parent.
func TestForkParentIsRecorded(t *testing.T) {
	s := mustFetch(t, newFakeOrg(t), nil)
	repo := findRepo(t, s, "TestGit/TestGit")
	if !repo.Fork || repo.ParentRepository != "Fabrikam-Fiber-Git/Upstream" {
		t.Errorf("fork=%v parent=%q", repo.Fork, repo.ParentRepository)
	}
}

func TestProgressAndRepositoryDoneCallbacks(t *testing.T) {
	var mu sync.Mutex
	var lines, done []string
	mustFetch(t, newFakeOrg(t), func(s *fetchSetup) {
		s.opts.Progress = func(l string) { mu.Lock(); lines = append(lines, l); mu.Unlock() }
		s.opts.OnRepositoryDone = func(n string) { mu.Lock(); done = append(done, n); mu.Unlock() }
	})
	if len(lines) == 0 || !strings.Contains(lines[len(lines)-1], "repositories") {
		t.Errorf("progress = %v", lines)
	}
	if !slices.Contains(done, "Fabrikam-Fiber-Git/Fabrikam-Fiber-Git") {
		t.Errorf("done = %v", done)
	}
}

func TestACancelledScanReturnsTheContextError(t *testing.T) {
	f := newFakeOrg(t)
	client, _ := NewClient(Options{Endpoint: f.endpoint(), Token: "pat"})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := NewFetcher(client, config.Default()).Fetch(ctx, FetchOptions{Now: testNow}); err == nil {
		t.Error("a cancelled scan must not return a snapshot")
	}
}

// Identities that cannot be resolved — a token without vso.identity — leave
// every principal set that needed them a lower bound, and the scan says so
// once rather than once per batch.
func TestUnresolvableIdentitiesMakeSetsLowerBounds(t *testing.T) {
	f := newFakeOrg(t)
	f.handle("/vssps/fabrikam/_apis/identities", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("searchFilter") != "" {
			f.identityHandler(w, r)
			return
		}
		writeError(w, http.StatusUnauthorized, "TF400813: The user is not authorized to access this resource.")
	})
	s := mustFetch(t, f, nil)
	repo := findRepo(t, s, "Fabrikam-Fiber-Git/Fabrikam-Fiber-Git")
	if repo.Admins.Complete || repo.ForcePushers.Complete {
		t.Errorf("admins = %+v, force pushers = %+v; neither could be resolved", repo.Admins, repo.ForcePushers)
	}
	// Nobody's ACE carries a bypass bit, so that set needed no identity and
	// is still exactly known: empty.
	if !repo.Bypass.Push.Complete || repo.Bypass.Push.Count != 0 {
		t.Errorf("push bypass = %+v", repo.Bypass.Push)
	}
	n := 0
	for _, w := range s.Metadata.Warnings {
		if strings.Contains(w, "identities could not be resolved") {
			n++
		}
	}
	if n != 1 {
		t.Errorf("the identity warning appears %d times, want once: %v", n, s.Metadata.Warnings)
	}
}

// An organization of many one-repository projects used to be scanned one
// repository at a time whatever scan.concurrency said, because projects ran
// one after another. Repositories of different projects now share one bound,
// and the snapshot keeps the listing's order.
func TestRepositoriesOfDifferentProjectsAreFetchedConcurrently(t *testing.T) {
	f := newFakeOrg(t)
	const projects, bound = 6, 3
	var listing []any
	var inFlight, peak atomic.Int64
	slow := func(w http.ResponseWriter, _ *http.Request) {
		n := inFlight.Add(1)
		for p := peak.Load(); n > p && !peak.CompareAndSwap(p, n); p = peak.Load() {
		}
		time.Sleep(40 * time.Millisecond)
		inFlight.Add(-1)
		writeJSON(w, http.StatusOK, collection([]any{map[string]any{"name": "refs/heads/main", "objectId": "23d0bc5b"}}))
	}
	for i := 0; i < projects; i++ {
		pid := fmt.Sprintf("00000000-0000-0000-0000-%012d", i)
		rid := fmt.Sprintf("10000000-0000-0000-0000-%012d", i)
		name := fmt.Sprintf("P%d", i)
		listing = append(listing, map[string]any{"id": pid, "name": name, "state": "wellFormed", "visibility": "private"})
		f.json("/fabrikam/"+pid+"/_apis/git/repositories", collection([]any{
			map[string]any{"id": rid, "name": "app", "defaultBranch": "refs/heads/main", "project": map[string]any{"id": pid, "name": name}},
		}))
		f.handle("/fabrikam/"+pid+"/_apis/git/repositories/"+rid+"/refs", slow)
		f.json("/fabrikam/"+pid+"/_apis/git/repositories/"+rid+"/stats/branches", collection([]any{branchStat("main", "2026-09-30T10:00:00Z")}))
		f.policies[pid] = []map[string]any{}
		f.handle("/fabrikam/"+pid+"/_apis/policy/configurations", f.policyList(pid))
		f.handle("/fabrikam/"+pid+"/_apis/git/policy/configurations", f.branchPolicyList())
	}
	f.json("/fabrikam/_apis/projects", collection(listing))

	s := mustFetch(t, f, func(s *fetchSetup) { s.opts.Concurrency = bound })
	if len(s.Projects) != projects {
		t.Fatalf("fetched %d projects, want %d", len(s.Projects), projects)
	}
	for i, p := range s.Projects {
		if p.Name != fmt.Sprintf("P%d", i) || len(p.Repositories) != 1 {
			t.Errorf("project %d = %s with %d repositories; order must follow the listing", i, p.Name, len(p.Repositories))
		}
	}
	if got := peak.Load(); got < 2 || got > bound {
		t.Errorf("peak repository fetches in flight = %d, want between 2 and %d", got, bound)
	}
}

// A project whose Git permissions come back empty is one the credential was
// not shown in full — every project starts with entries for its default
// groups. Reading it as "nobody holds anything" would let a project-level
// Force push grant vanish, so the project's permission-based facts become
// unknown instead.
func TestAnEmptyProjectACLIsUnreadableNotPermissive(t *testing.T) {
	f := newFakeOrg(t)
	f.mu.Lock()
	delete(f.acls, "repoV2/"+project2ID)
	f.mu.Unlock()
	s := mustFetch(t, f, nil)
	repo := findRepo(t, s, "TestGit/TestGit")
	for _, key := range []string{"bypass", "admins", "deleters", "permissions"} {
		if repo.Available[key] {
			t.Errorf("%s is available on a project whose permissions came back empty", key)
		}
	}
	if s.Organization.Available["repositoryCreators"] {
		t.Error("repository creators cannot be known for every project")
	}
	if !warned(s, "no entries at all") {
		t.Errorf("warnings = %v", s.Metadata.Warnings)
	}
	// The other project is unaffected.
	if main := findRepo(t, s, "Fabrikam-Fiber-Git/Fabrikam-Fiber-Git"); !main.Available["bypass"] {
		t.Error("an empty ACL in one project must not blind the others")
	}
}
