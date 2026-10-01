package azuredevops

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
)

// fakeOrg is a stand-in Azure DevOps organization.
//
// Every service lives on the one test server under its own path prefix — core
// at /fabrikam, identities and Graph at /vssps/fabrikam, entitlements at
// /vsaex/fabrikam, Advanced Security at /advsec/fabrikam — which the client is
// pointed at through Options.Endpoint. Responses use the shapes Microsoft
// documents; where a published sample exists (testdata/learn) it is served
// verbatim, and where none does a response is built in the same form.
//
// Anything unhandled answers 404 with Azure DevOps's error envelope, which is
// how an organization missing a feature behaves.
type fakeOrg struct {
	t          *testing.T
	server     *httptest.Server
	server2022 bool

	mu       sync.Mutex
	routes   map[string]http.HandlerFunc
	requests []*http.Request

	// The organization's data, which the handlers answer from.
	identities  []fakeIdentity
	memberships map[string][]string // subject -> member subjects
	acls        map[string]map[string]fakeACE
	policies    map[string][]map[string]any // project ID -> policy configurations
	branchPol   map[string][]map[string]any // "repoID|ref" -> E3 answer
}

type fakeIdentity struct {
	Descriptor, Subject, Name, Account string
	Group, Inactive, Everyone          bool
	ScopeType                          string
}

type fakeACE struct{ allow, deny int64 }

// Fixture identities. The descriptors follow the forms Azure DevOps uses:
// TFS SIDs for Azure DevOps and Entra groups, ClaimsIdentity for Entra users,
// ServiceIdentity for build services.
const (
	tenant      = "7a394543-62fd-4274-a7d2-8fac775942b6"
	projectID   = "6ce954b1-ce1f-45d1-b94d-e6bf2464ba2c" // Fabrikam-Fiber-Git, from the Learn samples
	project2ID  = "281f9a5b-af0d-49b4-a1df-fe6f5e5f84d0" // TestGit
	repoMainID  = "278d5cd2-584d-4b63-824a-2ba458937249" // Fabrikam-Fiber-Git (master)
	repoEmptyID = "5febef5a-833d-4e14-b9c0-14cb638f91e6" // AnotherRepository (no default branch)
	repoTestID  = "66efb083-777a-4cac-a350-a24b046be6be" // TestGit
	repoArchID  = "0d6e9b4f-7c2a-4f8e-9b1d-3a5c7e9f1b2d" // a disabled repository, built for the tests

	descPCA      = "Microsoft.TeamFoundation.Identity;S-1-9-1551374245-1204400969-2402986413-2179408616-0-0-0-0-1"
	descPCSA     = "Microsoft.TeamFoundation.Identity;S-1-9-1551374245-1204400969-2402986413-2179408616-0-0-0-0-2"
	descPCVU     = "Microsoft.TeamFoundation.Identity;S-1-9-1551374245-1204400969-2402986413-2179408616-0-0-0-0-3"
	descPA       = "Microsoft.TeamFoundation.Identity;S-1-9-1551374245-1204400969-2402986413-2179408616-1-1-1-1-1"
	descContrib  = "Microsoft.TeamFoundation.Identity;S-1-9-1551374245-1204400969-2402986413-2179408616-1-1-1-1-2"
	descPVU      = "Microsoft.TeamFoundation.Identity;S-1-9-1551374245-1204400969-2402986413-2179408616-1-1-1-1-3"
	descReaders  = "Microsoft.TeamFoundation.Identity;S-1-9-1551374245-1204400969-2402986413-2179408616-1-1-1-1-4"
	descPlatform = "Microsoft.TeamFoundation.Identity;S-1-9-1551374245-1204400969-2402986413-2179408616-3-9-9-9-9"
	descBuild    = "Microsoft.TeamFoundation.ServiceIdentity;e26baa74-481c-42bc-a78c-f2a89decc807:Build:6ce954b1-ce1f-45d1-b94d-e6bf2464ba2c"
	descAlice    = "Microsoft.IdentityModel.Claims.ClaimsIdentity;" + tenant + `\alice@fabrikam.com`
	descBob      = "Microsoft.IdentityModel.Claims.ClaimsIdentity;" + tenant + `\bob@fabrikam.com`
	descCarol    = "Microsoft.IdentityModel.Claims.ClaimsIdentity;" + tenant + `\carol@fabrikam.com`
	descDave     = "Microsoft.IdentityModel.Claims.ClaimsIdentity;" + tenant + `\dev@mailserver.com`
	descErin     = "Microsoft.IdentityModel.Claims.ClaimsIdentity;" + tenant + `\erin@fabrikam.com`
	descGone     = "Microsoft.IdentityModel.Claims.ClaimsIdentity;" + tenant + `\gone@fabrikam.com`

	// The creator of every ref in the Learn refs sample.
	subjDave = "aad.YmFjMGYyZDctNDA3ZC03OGRhLTlhMjUtNmJhZjUwMWFjY2U5"
)

// Every Git permission bit a default Project Administrators group holds —
// everything but the three bypasses, which Microsoft documents as "not set for
// any security group".
const (
	adminBits       int64 = 2 | 4 | 16 | 32 | 64 | 256 | 512 | 1024 | 2048 | 4096 | 8192 | 16384
	contributorBits int64 = 2 | 4 | 16 | 32 | 64 | 16384
)

func defaultIdentities() []fakeIdentity {
	return []fakeIdentity{
		{Descriptor: descPCA, Subject: "vssgp.PCA", Name: `[fabrikam]\Project Collection Administrators`, Account: "Project Collection Administrators", Group: true, ScopeType: "ServiceHost"},
		{Descriptor: descPCSA, Subject: "vssgp.PCSA", Name: `[fabrikam]\Project Collection Service Accounts`, Account: "Project Collection Service Accounts", Group: true, ScopeType: "ServiceHost"},
		{Descriptor: descPCVU, Subject: "vssgp.PCVU", Name: `[fabrikam]\Project Collection Valid Users`, Account: "Project Collection Valid Users", Group: true, Everyone: true, ScopeType: "ServiceHost"},
		{Descriptor: descPA, Subject: "vssgp.PA", Name: `[Fabrikam-Fiber-Git]\Project Administrators`, Account: "Project Administrators", Group: true, ScopeType: "TeamProject"},
		{Descriptor: descContrib, Subject: "vssgp.CONTRIB", Name: `[Fabrikam-Fiber-Git]\Contributors`, Account: "Contributors", Group: true, ScopeType: "TeamProject"},
		{Descriptor: descPVU, Subject: "vssgp.PVU", Name: `[Fabrikam-Fiber-Git]\Project Valid Users`, Account: "Project Valid Users", Group: true, Everyone: true, ScopeType: "TeamProject"},
		{Descriptor: descReaders, Subject: "vssgp.READERS", Name: `[Fabrikam-Fiber-Git]\Readers`, Account: "Readers", Group: true, ScopeType: "TeamProject"},
		{Descriptor: descPlatform, Subject: "aadgp.PLATFORM", Name: `[fabrikam]\Platform Engineers`, Account: "Platform Engineers", Group: true},
		{Descriptor: descBuild, Subject: "svc.BUILD", Name: "Project Collection Build Service (fabrikam)", Account: "Build"},
		{Descriptor: descAlice, Subject: "aad.ALICE", Name: "alice@fabrikam.com", Account: "alice@fabrikam.com"},
		{Descriptor: descBob, Subject: "aad.BOB", Name: "bob@fabrikam.com", Account: "bob@fabrikam.com"},
		{Descriptor: descCarol, Subject: "aad.CAROL", Name: "carol@fabrikam.com", Account: "carol@fabrikam.com"},
		{Descriptor: descDave, Subject: subjDave, Name: "dev@mailserver.com", Account: "dev@mailserver.com"},
		{Descriptor: descErin, Subject: "aad.ERIN", Name: "erin@fabrikam.com", Account: "erin@fabrikam.com"},
		{Descriptor: descGone, Subject: "aad.GONE", Name: "gone@fabrikam.com", Account: "gone@fabrikam.com", Inactive: true},
	}
}

func newFakeOrg(t *testing.T) *fakeOrg {
	t.Helper()
	f := &fakeOrg{
		t:          t,
		routes:     map[string]http.HandlerFunc{},
		identities: defaultIdentities(),
		memberships: map[string][]string{
			"vssgp.PCA":      {"aad.ALICE", "vssgp.PCSA"},
			"vssgp.PCSA":     {"svc.BUILD"},
			"vssgp.PA":       {"aad.CAROL", "aad.BOB", "aad.GONE"},
			"vssgp.CONTRIB":  {subjDave, "aadgp.PLATFORM"},
			"vssgp.READERS":  {},
			"aadgp.PLATFORM": {"aad.ERIN"},
		},
		acls: map[string]map[string]fakeACE{
			// Organization-wide: Project Collection Administrators hold every
			// right except the bypasses; the build service can contribute.
			"repoV2": {
				descPCA:   {allow: adminBits},
				descBuild: {allow: contributorBits},
			},
			"repoV2/" + projectID: {
				descPA:      {allow: adminBits},
				descContrib: {allow: contributorBits},
				descReaders: {allow: 2},
				descPVU:     {allow: 2},
			},
			"repoV2/" + project2ID: {
				descPA:  {allow: adminBits},
				descPVU: {allow: 2},
			},
			"repoV2/eb6e4656-77fc-42a1-9181-4c6d8e9da5d1": {
				descPA: {allow: adminBits},
			},
			// The creator of master was granted Force push on it when they
			// pushed it — Azure Repos does that for every branch's creator.
			branchToken(projectID, repoMainID, "refs/heads/master"): {
				descDave: {allow: 8 | 2048 | 8192},
			},
		},
		policies:  map[string][]map[string]any{},
		branchPol: map[string][]map[string]any{},
	}
	f.installDefaults()
	f.server = httptest.NewServer(f)
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakeOrg) endpoint() *Endpoint {
	base := func(prefix string) *url.URL {
		u, _ := url.Parse(f.server.URL + prefix)
		return u
	}
	return &Endpoint{
		Deployment:       "services",
		Organization:     "fabrikam",
		Core:             base("/fabrikam"),
		Identity:         base("/vssps/fabrikam"),
		Entitlements:     base("/vsaex/fabrikam"),
		AdvancedSecurity: base("/advsec/fabrikam"),
	}
}

// serverEndpoint is an Azure DevOps Server collection: core and identities on
// the collection URL, no Graph, no entitlements, no Advanced Security.
func (f *fakeOrg) serverEndpoint() *Endpoint {
	u, _ := url.Parse(f.server.URL + "/fabrikam")
	return &Endpoint{Deployment: "server", Organization: "fabrikam", Core: u, Identity: u}
}

func (f *fakeOrg) handle(path string, h http.HandlerFunc) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.routes[path] = h
}

func (f *fakeOrg) json(path string, body any) {
	f.handle(path, func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, http.StatusOK, body) })
}

func (f *fakeOrg) learn(path, file string) {
	raw := learnSample(f.t, file)
	f.handle(path, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8; api-version=7.1")
		w.Write(raw)
	})
}

func (f *fakeOrg) fail(path string, status int, message string) {
	f.handle(path, func(w http.ResponseWriter, _ *http.Request) { writeError(w, status, message) })
}

func learnSample(t *testing.T, file string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "learn", file))
	if err != nil {
		t.Fatalf("read sample %s: %v", file, err)
	}
	return raw
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8; api-version=7.1")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(body)
}

// writeError answers in Azure DevOps's error envelope.
func writeError(w http.ResponseWriter, status int, message string) {
	typeKey := "VssServiceException"
	switch {
	case strings.HasPrefix(message, "TF401174"):
		typeKey = "GitItemNotFoundException"
	case strings.Contains(message, "out of range"):
		typeKey = "VssVersionOutOfRangeException"
	}
	writeJSON(w, status, map[string]any{
		"$id": "1", "innerException": nil, "message": message,
		"typeName": "Microsoft.VisualStudio.Services.Common." + typeKey + ", Microsoft.VisualStudio.Services.Common",
		"typeKey":  typeKey, "errorCode": 0, "eventId": 3000,
	})
}

func collection(items any) map[string]any {
	n := 0
	if list, ok := items.([]any); ok {
		n = len(list)
	}
	if list, ok := items.([]map[string]any); ok {
		n = len(list)
	}
	return map[string]any{"count": n, "value": items}
}

func (f *fakeOrg) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.requests = append(f.requests, r.Clone(r.Context()))
	h, ok := f.routes[r.URL.Path]
	f.mu.Unlock()
	if ok {
		h(w, r)
		return
	}
	writeError(w, http.StatusNotFound, "TF400898: An Internal Error Occurred. (no route for "+r.URL.Path+")")
}

// requestsTo returns the requests whose path contains fragment.
func (f *fakeOrg) requestsTo(fragment string) []*http.Request {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []*http.Request
	for _, r := range f.requests {
		if strings.Contains(r.URL.Path, fragment) {
			out = append(out, r)
		}
	}
	return out
}

func (f *fakeOrg) identityJSON(id fakeIdentity, members []string) map[string]any {
	props := map[string]any{
		"SchemaClassName": map[string]any{"$type": "System.String", "$value": map[bool]string{true: "Group", false: "User"}[id.Group]},
		"Account":         map[string]any{"$type": "System.String", "$value": id.Account},
	}
	if id.Everyone {
		props["SpecialType"] = map[string]any{"$type": "System.String", "$value": "EveryoneApplicationGroup"}
	}
	if id.ScopeType != "" {
		props["ScopeType"] = map[string]any{"$type": "System.String", "$value": id.ScopeType}
	}
	if strings.Contains(id.Account, "@") {
		props["Mail"] = map[string]any{"$type": "System.String", "$value": id.Account}
	}
	out := map[string]any{
		"id":                  fmt.Sprintf("%08x-0000-0000-0000-000000000000", len(id.Descriptor)),
		"descriptor":          id.Descriptor,
		"subjectDescriptor":   id.Subject,
		"providerDisplayName": id.Name,
		"isActive":            !id.Inactive,
		"members":             members,
		"memberOf":            []string{},
		"properties":          props,
	}
	if id.Group {
		out["isContainer"] = true
	}
	return out
}

func (f *fakeOrg) findIdentity(match func(fakeIdentity) bool) (fakeIdentity, bool) {
	for _, id := range f.identities {
		if match(id) {
			return id, true
		}
	}
	return fakeIdentity{}, false
}

// expandedMembers is what IMS's ExpandedDown answers for a group: every
// member at any depth, as identity descriptors.
func (f *fakeOrg) expandedMembers(subject string) []string {
	seen := map[string]bool{}
	var out []string
	var walk func(string)
	walk = func(s string) {
		for _, m := range f.memberships[s] {
			if seen[m] {
				continue
			}
			seen[m] = true
			if id, ok := f.findIdentity(func(i fakeIdentity) bool { return i.Subject == m }); ok {
				out = append(out, id.Descriptor)
			}
			walk(m)
		}
	}
	walk(subject)
	return out
}

func (f *fakeOrg) installDefaults() {
	// Core.
	f.handle("/fabrikam/_apis/projects", func(w http.ResponseWriter, r *http.Request) {
		// Microsoft's sample, verbatim — no visibility field — for the list;
		// the preflight's $top=1 gets the same.
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Write(learnSample(f.t, "projects-list.json"))
	})
	f.json("/fabrikam/_apis/projects/Fabrikam-Fiber-Git", map[string]any{
		"id": projectID, "name": "Fabrikam-Fiber-Git", "state": "wellFormed", "visibility": "private",
	})
	f.json("/fabrikam/_apis/projects/TestGit", map[string]any{
		"id": project2ID, "name": "TestGit", "state": "wellFormed", "visibility": "public",
	})
	f.json("/fabrikam/_apis/projects/Fabrikam-Fiber-TFVC", map[string]any{
		"id": "eb6e4656-77fc-42a1-9181-4c6d8e9da5d1", "name": "Fabrikam-Fiber-TFVC", "state": "wellFormed", "visibility": "private",
	})
	f.json("/fabrikam/_apis/securitynamespaces/2e9eb7ed-3c0a-47d4-87c1-0ffdd275fd87", collection([]any{map[string]any{
		"namespaceId": "2e9eb7ed-3c0a-47d4-87c1-0ffdd275fd87", "name": "Git Repositories",
		"actions": []any{
			map[string]any{"bit": 8, "name": "ForcePush"}, map[string]any{"bit": 128, "name": "PolicyExempt"},
			map[string]any{"bit": 256, "name": "CreateRepository"}, map[string]any{"bit": 512, "name": "DeleteRepository"},
			map[string]any{"bit": 8192, "name": "ManagePermissions"}, map[string]any{"bit": 32768, "name": "PullRequestBypassPolicy"},
		},
	}}))

	// The Learn repository list puts every repository under the
	// organization; here the first project holds two plus a disabled one, and
	// TestGit holds its own.
	f.json("/fabrikam/"+projectID+"/_apis/git/repositories", collection([]any{
		map[string]any{"id": repoEmptyID, "name": "AnotherRepository", "project": map[string]any{"id": projectID, "name": "Fabrikam-Fiber-Git"}},
		map[string]any{"id": repoMainID, "name": "Fabrikam-Fiber-Git", "defaultBranch": "refs/heads/master", "project": map[string]any{"id": projectID, "name": "Fabrikam-Fiber-Git"}},
		map[string]any{"id": repoArchID, "name": "Archive-2019", "defaultBranch": "refs/heads/main", "isDisabled": true, "project": map[string]any{"id": projectID, "name": "Fabrikam-Fiber-Git"}},
	}))
	f.json("/fabrikam/"+project2ID+"/_apis/git/repositories", collection([]any{
		map[string]any{"id": repoTestID, "name": "TestGit", "defaultBranch": "refs/heads/master", "isFork": true,
			"parentRepository": map[string]any{"name": "Upstream", "project": map[string]any{"name": "Fabrikam-Fiber-Git"}},
			"project":          map[string]any{"id": project2ID, "name": "TestGit"}},
	}))
	f.json("/fabrikam/eb6e4656-77fc-42a1-9181-4c6d8e9da5d1/_apis/git/repositories", collection([]any{}))
	f.json("/fabrikam/"+projectID+"/_apis/git/repositories/Fabrikam-Fiber-Git", map[string]any{
		"id": repoMainID, "name": "Fabrikam-Fiber-Git", "defaultBranch": "refs/heads/master", "project": map[string]any{"id": projectID, "name": "Fabrikam-Fiber-Git"},
	})

	// Branches: the Learn refs sample for the main repository — master and
	// two feature branches, all created by the same user — and dates that
	// match it, in the stats sample's shape.
	f.learn("/fabrikam/"+projectID+"/_apis/git/repositories/"+repoMainID+"/refs", "refs-list.json")
	f.json("/fabrikam/"+projectID+"/_apis/git/repositories/"+repoMainID+"/stats/branches", collection([]any{
		branchStat("master", "2026-09-28T10:00:00Z"),
		branchStat("feature/calcApp", "2026-09-20T10:00:00Z"),
		branchStat("feature/replacer", "2025-01-10T10:00:00Z"),
	}))
	f.json("/fabrikam/"+projectID+"/_apis/git/repositories/"+repoEmptyID+"/refs", collection([]any{}))
	f.json("/fabrikam/"+project2ID+"/_apis/git/repositories/"+repoTestID+"/refs", collection([]any{
		map[string]any{"name": "refs/heads/master", "objectId": "23d0bc5b128a10056dc68afece360d8a0fabb014"},
	}))
	f.json("/fabrikam/"+project2ID+"/_apis/git/repositories/"+repoTestID+"/stats/branches", collection([]any{
		branchStat("master", "2026-09-30T10:00:00Z"),
	}))

	// SECURITY.md at the root of the main repository; .github and docs do not
	// exist (TF401174); TestGit has nothing at all.
	f.handle("/fabrikam/"+projectID+"/_apis/git/repositories/"+repoMainID+"/items", func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("scopePath") {
		case "/":
			writeJSON(w, http.StatusOK, collection([]any{
				map[string]any{"objectId": "61a86f", "gitObjectType": "tree", "path": "/", "isFolder": true},
				map[string]any{"objectId": "61a870", "gitObjectType": "blob", "path": "/SECURITY.md"},
				map[string]any{"objectId": "61a871", "gitObjectType": "blob", "path": "/README.md"},
			}))
		default:
			writeError(w, http.StatusNotFound, fmt.Sprintf("TF401174: The item '%s' could not be found in the repository 'Fabrikam-Fiber-Git' at the version specified by '<Branch: master >'.", r.URL.Query().Get("scopePath")))
		}
	})
	f.handle("/fabrikam/"+project2ID+"/_apis/git/repositories/"+repoTestID+"/items", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("scopePath") == "/" {
			writeJSON(w, http.StatusOK, collection([]any{map[string]any{"gitObjectType": "blob", "path": "/README.md"}}))
			return
		}
		writeError(w, http.StatusNotFound, "TF401174: The item could not be found in the repository.")
	})

	// Policies.
	f.policies[projectID] = append(samplePolicies(f.t), synthesizedPolicies()...)
	f.policies[project2ID] = []map[string]any{}
	f.branchPol[repoMainID+"|refs/heads/master"] = appliesTo(f.policies[projectID], repoMainID, "refs/heads/master")
	f.handle("/fabrikam/"+projectID+"/_apis/policy/configurations", f.policyList(projectID))
	f.handle("/fabrikam/"+project2ID+"/_apis/policy/configurations", f.policyList(project2ID))
	f.handle("/fabrikam/"+projectID+"/_apis/git/policy/configurations", f.branchPolicyList())
	f.handle("/fabrikam/"+project2ID+"/_apis/git/policy/configurations", f.branchPolicyList())

	// Access control lists.
	f.handle("/fabrikam/_apis/accesscontrollists/2e9eb7ed-3c0a-47d4-87c1-0ffdd275fd87", f.aclHandler)

	// Identities and Graph.
	f.handle("/vssps/fabrikam/_apis/identities", f.identityHandler)
	f.handle("/fabrikam/_apis/identities", f.identityHandler) // Server: IMS on the collection
	for subject := range f.memberships {
		subject := subject
		f.handle("/vssps/fabrikam/_apis/graph/Memberships/"+subject, func(w http.ResponseWriter, r *http.Request) {
			if !strings.EqualFold(r.URL.Query().Get("direction"), "down") {
				writeError(w, http.StatusBadRequest, "expected direction=down")
				return
			}
			var out []any
			for _, m := range f.memberships[subject] {
				out = append(out, map[string]any{"containerDescriptor": subject, "memberDescriptor": m})
			}
			writeJSON(w, http.StatusOK, collection(out))
		})
	}

	// User entitlements: two pages, the continuation token in the body, the
	// way this API (alone) carries it.
	f.handle("/vsaex/fabrikam/_apis/userentitlements", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("continuationToken") == "" {
			writeJSON(w, http.StatusOK, map[string]any{"continuationToken": "page-2", "totalCount": 4, "items": []any{
				entitlement("alice@fabrikam.com", "active", "express", "2026-09-30T08:00:00Z", "2024-01-01T00:00:00Z", "member"),
				entitlement("bob@fabrikam.com", "active", "express", "2025-12-01T08:00:00Z", "2024-01-01T00:00:00Z", "member"),
			}})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"continuationToken": nil, "totalCount": 4, "items": []any{
			entitlement("invitee@partner.example", "pending", "express", "0001-01-01T00:00:00Z", "2026-01-15T00:00:00Z", "guest"),
			entitlement("former@fabrikam.com", "disabled", "express", "2024-02-01T00:00:00Z", "2023-01-01T00:00:00Z", "member"),
		}})
	})

	// Advanced Security, every repository in one answer.
	f.json("/advsec/fabrikam/_apis/management/enablement", map[string]any{
		"reposEnablementStatus": []any{
			map[string]any{"projectId": projectID, "repositoryId": repoMainID,
				"secretProtectionFeatures": map[string]any{"secretProtectionEnabled": true, "blockPushes": true},
				"codeSecurityFeatures":     map[string]any{"codeSecurityEnabled": true, "codeQLEnabled": true, "dependencyScanningInjectionEnabled": false}},
			map[string]any{"projectId": project2ID, "repositoryId": repoTestID,
				"secretProtectionFeatures": map[string]any{"secretProtectionEnabled": true, "blockPushes": nil}},
		},
	})
}

func branchStat(name, date string) map[string]any {
	return map[string]any{
		"name": name,
		"commit": map[string]any{
			"commitId":  "67cae2b029dff7eb3dc062b49403aaedca5bad8d",
			"author":    map[string]any{"name": "Chuck Reinhart", "email": "fabrikamfiber3@hotmail.com", "date": date},
			"committer": map[string]any{"name": "Chuck Reinhart", "email": "fabrikamfiber3@hotmail.com", "date": date},
		},
		"aheadCount": 0, "behindCount": 0, "isBaseVersion": name == "master",
	}
}

func entitlement(name, status, license, lastAccess, created, metaType string) map[string]any {
	return map[string]any{
		"id":               fmt.Sprintf("%x", len(name)),
		"accessLevel":      map[string]any{"accountLicenseType": license, "licensingSource": "account", "status": status},
		"dateCreated":      created,
		"lastAccessedDate": lastAccess,
		"user": map[string]any{
			"subjectKind": "user", "metaType": metaType, "principalName": name, "mailAddress": name,
			"displayName": strings.Split(name, "@")[0], "origin": "aad", "descriptor": "aad." + name,
		},
	}
}

// samplePolicies is the Learn policy list, verbatim: required reviewers on
// master and releases/ across repositories (17), an optional minimum count on
// master (18), and a build on features/ (19).
func samplePolicies(t *testing.T) []map[string]any {
	var doc struct {
		Value []map[string]any `json:"value"`
	}
	if err := json.Unmarshal(learnSample(t, "policy-configurations-list.json"), &doc); err != nil {
		t.Fatalf("decode policy sample: %v", err)
	}
	return doc.Value
}

func policyObject(id int, typeID, typeName string, blocking bool, settings map[string]any) map[string]any {
	return map[string]any{
		"id": id, "revision": 1, "isEnabled": true, "isBlocking": blocking, "isDeleted": false,
		"type":     map[string]any{"id": typeID, "displayName": typeName},
		"settings": settings,
	}
}

func scope(repo any, ref any, kind string) map[string]any {
	return map[string]any{"repositoryId": repo, "refName": ref, "matchKind": kind}
}

// synthesizedPolicies are the policies no Learn sample shows: the
// project-wide "Protect the default branch of each repository" scope
// (DefaultBranch, as Microsoft's Terraform provider writes it), a cross-repo
// prefix, and per-repository exact scopes.
func synthesizedPolicies() []map[string]any {
	return []map[string]any{
		policyObject(25, typeMinReviewers, "Minimum number of reviewers", true, map[string]any{
			"minimumApproverCount": 2, "creatorVoteCounts": false, "resetOnSourcePush": true, "blockLastPusherVote": true,
			"scope": []any{scope(nil, nil, "DefaultBranch")},
		}),
		policyObject(26, typeCommentRequirements, "Comment requirements", true, map[string]any{
			"scope": []any{scope(nil, "refs/heads/", "Prefix")},
		}),
		policyObject(27, typeMergeStrategy, "Require a merge strategy", true, map[string]any{
			"allowSquash": true, "allowRebase": true,
			"scope": []any{scope(repoMainID, "refs/heads/master", "Exact")},
		}),
		policyObject(28, typeBuild, "Build", true, map[string]any{
			"buildDefinitionId": 5, "displayName": "CI", "queueOnSourceUpdateOnly": false, "validDuration": 0,
			"scope": []any{scope(repoMainID, "refs/heads/master", "exact")},
		}),
		policyObject(29, typeStatus, "Status", true, map[string]any{
			"statusGenre": "security", "statusName": "verify-signatures", "policyApplicability": nil,
			"scope": []any{scope(repoMainID, "refs/heads/master", "Exact")},
		}),
		policyObject(30, typeBuild, "Build", true, map[string]any{
			"buildDefinitionId": 9, "displayName": "docs", "filenamePatterns": []any{"/docs/*"},
			"scope": []any{scope(repoMainID, "refs/heads/master", "Exact")},
		}),
		// A file-size limit applies to every branch and protects none.
		policyObject(31, "2e26e725-8201-4edd-8bf5-978563c34a80", "File size restriction", true, map[string]any{
			"maximumGitBlobSizeInBytes": 10485760, "scope": []any{map[string]any{"repositoryId": repoMainID}},
		}),
		// Deleted and disabled policies are reported by the API and must not
		// count.
		func() map[string]any {
			p := policyObject(32, typeWorkItemLinking, "Work item linking", true, map[string]any{"scope": []any{scope(nil, nil, "DefaultBranch")}})
			p["isDeleted"] = true
			return p
		}(),
		func() map[string]any {
			p := policyObject(33, typeWorkItemLinking, "Work item linking", true, map[string]any{"scope": []any{scope(nil, nil, "DefaultBranch")}})
			p["isEnabled"] = false
			return p
		}(),
	}
}

// appliesTo is what the server answers for a branch: the policies whose scope
// covers it, by the documented semantics.
func appliesTo(policies []map[string]any, repoID, ref string) []map[string]any {
	var out []map[string]any
	for _, p := range policies {
		raw, _ := json.Marshal(p["settings"])
		var st policySettings
		json.Unmarshal(raw, &st)
		if m, _, _ := matchScope(st.Scope, repoID, ref); m == scopeMatches {
			out = append(out, p)
			continue
		}
		// Repository-wide settings apply to every branch of their repository.
		for _, s := range st.Scope {
			if s.RefName == nil && s.MatchKind == "" && s.RepositoryID != nil && *s.RepositoryID == repoID {
				out = append(out, p)
			}
		}
	}
	return out
}

// policyList answers the project-level list, two to a page so the
// continuation header is exercised.
func (f *fakeOrg) policyList(project string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		all := f.policies[project]
		f.mu.Unlock()
		pagedPolicies(w, r, all, 4)
	}
}

func (f *fakeOrg) branchPolicyList() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		f.mu.Lock()
		key := q.Get("repositoryId") + "|" + q.Get("refName")
		answer, ok := f.branchPol[key]
		f.mu.Unlock()
		if !ok {
			answer = []map[string]any{}
		}
		pagedPolicies(w, r, answer, 3)
	}
}

// pagedPolicies serves size items per page, sorted by ID, continuing from the
// ID in continuationToken — the documented mechanism — with the next one in
// x-ms-continuationtoken.
func pagedPolicies(w http.ResponseWriter, r *http.Request, all []map[string]any, size int) {
	sorted := append([]map[string]any(nil), all...)
	sort.Slice(sorted, func(i, j int) bool { return idOf(sorted[i]) < idOf(sorted[j]) })
	start := 0
	if tok := r.URL.Query().Get("continuationToken"); tok != "" {
		var from int
		fmt.Sscanf(tok, "%d", &from)
		for start < len(sorted) && idOf(sorted[start]) < from {
			start++
		}
	}
	end := start + size
	if end > len(sorted) {
		end = len(sorted)
	}
	if end < len(sorted) {
		w.Header().Set("x-ms-continuationtoken", fmt.Sprintf("%d", idOf(sorted[end])))
	}
	page := sorted[start:end]
	if page == nil {
		page = []map[string]any{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"count": len(page), "value": page})
}

func idOf(p map[string]any) int {
	switch v := p["id"].(type) {
	case int:
		return v
	case float64:
		return int(v)
	}
	return 0
}

// aclHandler answers access control list queries. Without descriptors it
// returns the explicit entries at the token (and below it, with recurse);
// with descriptors it returns the token's list with one evaluated entry per
// descriptor, as the "filter by descriptors" and "include extended info"
// samples show, zero values omitted.
func (f *fakeOrg) aclHandler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	token := q.Get("token")
	f.mu.Lock()
	defer f.mu.Unlock()

	if ds := q.Get("descriptors"); ds != "" {
		aces := map[string]any{}
		for _, d := range strings.Split(ds, ",") {
			var allow, deny, effAllow, effDeny int64
			for tok, entries := range f.acls {
				if !tokenCovers(tok, token) {
					continue
				}
				for desc, ace := range entries {
					if !strings.EqualFold(desc, d) {
						continue
					}
					effAllow |= ace.allow
					effDeny |= ace.deny
					if strings.EqualFold(tok, token) {
						allow, deny = ace.allow, ace.deny
					}
				}
			}
			effAllow &^= effDeny
			ext := map[string]any{}
			if effAllow != 0 {
				ext["effectiveAllow"] = effAllow
			}
			if effDeny != 0 {
				ext["effectiveDeny"] = effDeny
			}
			entry := map[string]any{"descriptor": d, "allow": allow, "deny": deny}
			if len(ext) > 0 {
				entry["extendedInfo"] = ext
			}
			aces[d] = entry
		}
		writeJSON(w, http.StatusOK, collection([]any{map[string]any{
			"inheritPermissions": true, "token": token, "acesDictionary": aces, "includeExtendedInfo": true,
		}}))
		return
	}

	recurse := strings.EqualFold(q.Get("recurse"), "true")
	lists := []any{}
	for tok, entries := range f.acls {
		if !strings.EqualFold(tok, token) && !(recurse && tokenCovers(token, tok)) {
			continue
		}
		aces := map[string]any{}
		for desc, ace := range entries {
			aces[desc] = map[string]any{"descriptor": desc, "allow": ace.allow, "deny": ace.deny}
		}
		lists = append(lists, map[string]any{"inheritPermissions": true, "token": tok, "acesDictionary": aces})
	}
	writeJSON(w, http.StatusOK, collection(lists))
}

func (f *fakeOrg) identityHandler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f.mu.Lock()
	defer f.mu.Unlock()
	membership := strings.ToLower(q.Get("queryMembership"))
	render := func(id fakeIdentity) map[string]any {
		members := []string{}
		switch membership {
		case "expandeddown", "expanded":
			members = f.expandedMembers(id.Subject)
		case "direct":
			for _, m := range f.memberships[id.Subject] {
				if mid, ok := f.findIdentity(func(i fakeIdentity) bool { return i.Subject == m }); ok {
					members = append(members, mid.Descriptor)
				}
			}
		}
		return f.identityJSON(id, members)
	}

	var out []any
	switch {
	case q.Get("descriptors") != "":
		for _, d := range strings.Split(q.Get("descriptors"), ",") {
			if id, ok := f.findIdentity(func(i fakeIdentity) bool { return strings.EqualFold(i.Descriptor, d) }); ok {
				out = append(out, render(id))
			} else {
				out = append(out, nil)
			}
		}
	case q.Get("subjectDescriptors") != "":
		for _, s := range strings.Split(q.Get("subjectDescriptors"), ",") {
			if id, ok := f.findIdentity(func(i fakeIdentity) bool { return strings.EqualFold(i.Subject, s) }); ok {
				out = append(out, render(id))
			} else {
				out = append(out, nil)
			}
		}
	case q.Get("searchFilter") != "":
		for _, id := range f.identities {
			if strings.EqualFold(id.Account, q.Get("filterValue")) {
				out = append(out, render(id))
			}
		}
	}
	if out == nil {
		out = []any{}
	}
	writeJSON(w, http.StatusOK, collection(out))
}
