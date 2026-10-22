package azuredevops

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/scm-bench/azure-devops-bench/internal/config"
	"github.com/scm-bench/azure-devops-bench/internal/scm"
)

// fetcherOn builds a fetcher for one endpoint of a fake organization, for
// tests that drive the directory and the ACL evaluation directly.
func fetcherOn(t *testing.T, ep *Endpoint) *Fetcher {
	t.Helper()
	c, err := NewClient(Options{Endpoint: ep, Token: "pat", MaxRetries: 1})
	if err != nil {
		t.Fatal(err)
	}
	c.sleep = func(context.Context, time.Duration) error { return nil }
	return NewFetcher(c, config.Default())
}

// fetcherServing builds a fetcher whose every request is answered by h.
func fetcherServing(t *testing.T, deployment string, h http.HandlerFunc) *Fetcher {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL + "/org")
	return fetcherOn(t, &Endpoint{Deployment: deployment, Organization: "org", Core: u, Identity: u})
}

func (f *Fetcher) warnedAbout(fragment string) bool {
	f.warnMu.Lock()
	defer f.warnMu.Unlock()
	for _, w := range f.warnings {
		if strings.Contains(w, fragment) {
			return true
		}
	}
	return false
}

// graphGroup adds a group to the fake organization with a Graph memberships
// route of its own; installDefaults only routes the groups it starts with.
func (f *fakeOrg) graphGroup(id fakeIdentity, members ...string) {
	f.mu.Lock()
	f.identities = append(f.identities, id)
	f.memberships[id.Subject] = members
	f.mu.Unlock()
	f.handle("/vssps/fabrikam/_apis/graph/Memberships/"+id.Subject, func(w http.ResponseWriter, _ *http.Request) {
		var out []any
		for _, m := range members {
			out = append(out, map[string]any{"containerDescriptor": id.Subject, "memberDescriptor": m})
		}
		writeJSON(w, http.StatusOK, collection(out))
	})
}

func identityOf(t *testing.T, raw string) apiIdentity {
	t.Helper()
	var id apiIdentity
	if err := json.Unmarshal([]byte(raw), &id); err != nil {
		t.Fatal(err)
	}
	return id
}

// ---- classification --------------------------------------------------------

func TestPrincipalsAreNamedByWhatTheyHave(t *testing.T) {
	prop := func(v string) string { return `{"$type":"System.String","$value":"` + v + `"}` }
	for _, tc := range []struct {
		name, raw string
		kind      principalKind
		want      string
	}{
		{"a custom display name wins", `{"descriptor":"Microsoft.TeamFoundation.Identity;S-1","isContainer":true,"providerDisplayName":"[x]\\G","customDisplayName":"Release managers"}`, kindGroup, "Release managers"},
		{"an Active Directory group", `{"descriptor":"System.Security.Principal.WindowsIdentity;S-1-5-21-1","isContainer":true,"providerDisplayName":"CORP\\Developers"}`, kindExternalGroup, `CORP\Developers`},
		{"a group with only an account", `{"descriptor":"Microsoft.TeamFoundation.Identity;S-2","isContainer":true,"properties":{"Account":` + prop("Auditors") + `}}`, kindGroup, "Auditors"},
		{"a service with only an account", `{"descriptor":"Microsoft.TeamFoundation.ServiceIdentity;b:Build:1","properties":{"Account":` + prop("Build") + `}}`, kindService, "Build"},
		{"a person by mail", `{"descriptor":"Microsoft.IdentityModel.Claims.ClaimsIdentity;t\\x","subjectDescriptor":"aad.X","properties":{"Account":` + prop("x") + `,"Mail":` + prop("x@fabrikam.com") + `}}`, kindHuman, "x@fabrikam.com"},
		{"a domain account", `{"descriptor":"System.Security.Principal.WindowsIdentity;S-1-5-21-2","properties":{"Account":` + prop("jdoe") + `,"Domain":` + prop("CORP") + `}}`, kindHuman, `CORP\jdoe`},
		{"a bare account", `{"descriptor":"Microsoft.IdentityModel.Claims.ClaimsIdentity;t\\y","properties":{"Account":` + prop("jdoe") + `}}`, kindHuman, "jdoe"},
		{"only a display name", `{"descriptor":"Microsoft.IdentityModel.Claims.ClaimsIdentity;t\\z","providerDisplayName":"Zed"}`, kindHuman, "Zed"},
		{"nothing but a descriptor", `{"descriptor":"Microsoft.IdentityModel.Claims.ClaimsIdentity;t\\w"}`, kindHuman, `Microsoft.IdentityModel.Claims.ClaimsIdentity;t\w`},
	} {
		p := newPrincipal(identityOf(t, tc.raw))
		if p.Kind != tc.kind || p.Name != tc.want {
			t.Errorf("%s: kind %d name %q, want kind %d name %q", tc.name, p.Kind, p.Name, tc.kind, tc.want)
		}
	}
}

// ---- set algebra -----------------------------------------------------------

func TestSetAlgebraCorners(t *testing.T) {
	human := &principal{Descriptor: "h", Kind: kindHuman, Name: "h"}
	svc := &principal{Descriptor: "s", Kind: kindService, Name: "s"}
	grp := &principal{Descriptor: "g", Kind: kindGroup, Name: "g"}
	all := &principal{Descriptor: "e", Kind: kindGroup, Name: "e", Everyone: true}

	everyone := newPset()
	everyone.add(all)
	full := newPset()
	full.add(human)
	full.add(svc)
	full.add(grp)

	if got := intersect(everyone, everyone); !got.everyone || len(got.groups) != 1 {
		t.Errorf("everyone ∩ everyone = %+v", got)
	}
	if got := intersect(full, everyone); len(got.humans) != 1 || len(got.services) != 1 || len(got.groups) != 1 {
		t.Errorf("full ∩ everyone = %+v", got)
	}
	if got := intersect(full, full); len(got.humans) != 1 || len(got.services) != 1 || len(got.groups) != 1 {
		t.Errorf("full ∩ full = %+v", got)
	}
	onlyHuman := newPset()
	onlyHuman.add(human)
	if got := subtract(full, onlyHuman); len(got.services) != 1 || len(got.humans) != 0 {
		t.Errorf("full − human = %+v", got)
	}
}

// ---- lookups ---------------------------------------------------------------

func TestLookupSkipsBlanksRepeatsAndUnknowns(t *testing.T) {
	fo := newFakeOrg(t)
	f := fetcherOn(t, fo.endpoint())
	got := f.dir.resolve(context.Background(), []string{"", descAlice, strings.ToUpper(descAlice), "Microsoft.TeamFoundation.Identity;S-unknown"})
	if len(got) != 1 {
		t.Errorf("resolved = %v", got)
	}
	// The unknown one is remembered as failed and not asked about again.
	before := len(fo.requestsTo("/_apis/identities"))
	f.dir.resolve(context.Background(), []string{"Microsoft.TeamFoundation.Identity;S-unknown"})
	if after := len(fo.requestsTo("/_apis/identities")); after != before {
		t.Errorf("an identity known to be unresolvable was asked about again")
	}
}

// An identity search that turns up users, other groups and a project's
// same-named group still finds the one collection-level group.
func TestFindCollectionGroupIgnoresNearMisses(t *testing.T) {
	prop := func(v string) map[string]any { return map[string]any{"$type": "System.String", "$value": v} }
	results := []any{
		map[string]any{"descriptor": "Microsoft.IdentityModel.Claims.ClaimsIdentity;t\\pca", "providerDisplayName": "Project Collection Administrators", "properties": map[string]any{"Account": prop("Project Collection Administrators")}},
		map[string]any{"descriptor": "Microsoft.TeamFoundation.Identity;S-other", "isContainer": true, "providerDisplayName": "[org]\\Other", "properties": map[string]any{"Account": prop("Other")}},
		map[string]any{"descriptor": "Microsoft.TeamFoundation.Identity;S-proj", "isContainer": true, "providerDisplayName": "[P]\\Project Collection Administrators", "properties": map[string]any{"Account": prop("Project Collection Administrators"), "ScopeType": prop("TeamProject")}},
		map[string]any{"descriptor": "Microsoft.TeamFoundation.Identity;S-pca", "isContainer": true, "providerDisplayName": "[org]\\Project Collection Administrators", "properties": map[string]any{"Account": prop("Project Collection Administrators")}},
	}
	f := fetcherServing(t, scm.DeploymentServices, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, collection(results))
	})
	p, err := f.dir.findCollectionGroup(context.Background(), "Project Collection Administrators")
	if err != nil || p.Descriptor != "Microsoft.TeamFoundation.Identity;S-pca" {
		t.Errorf("found %+v, %v", p, err)
	}

	failing := fetcherServing(t, scm.DeploymentServices, func(w http.ResponseWriter, _ *http.Request) {
		writeError(w, http.StatusBadRequest, "TF400813: no")
	})
	if _, err := failing.dir.findCollectionGroup(context.Background(), "Project Collection Administrators"); err == nil {
		t.Error("a failed search found a group")
	}
}

// ---- Graph expansion -------------------------------------------------------

func TestGraphExpansionLowerBounds(t *testing.T) {
	ctx := context.Background()

	t.Run("an external group", func(t *testing.T) {
		fo := newFakeOrg(t)
		f := fetcherOn(t, fo.endpoint())
		set := f.dir.expand(ctx, &principal{Descriptor: descPlatform, Subject: "aadgp.PLATFORM", Name: "Platform", Kind: kindExternalGroup})
		if set.complete || len(set.humans) != 1 {
			t.Errorf("set = %+v", set)
		}
	})

	t.Run("no subject descriptor", func(t *testing.T) {
		fo := newFakeOrg(t)
		f := fetcherOn(t, fo.endpoint())
		set := f.dir.expand(ctx, &principal{Descriptor: "Microsoft.TeamFoundation.Identity;S-x", Name: "Orphans", Kind: kindGroup})
		if set.complete || !f.warnedAbout("no Graph subject descriptor") {
			t.Errorf("set = %+v, warnings = %v", set, f.warnings)
			for _, r := range fo.requestsTo("identities") {
				t.Log(r.URL.String())
			}
		}
	})

	t.Run("nesting past the bound", func(t *testing.T) {
		fo := newFakeOrg(t)
		const depth = maxGroupDepth + 2
		for i := depth; i >= 0; i-- {
			var members []string
			if i < depth {
				members = []string{fmt.Sprintf("vssgp.NEST%d", i+1)}
			}
			fo.graphGroup(fakeIdentity{Descriptor: fmt.Sprintf("Microsoft.TeamFoundation.Identity;S-NEST-%d", i), Subject: fmt.Sprintf("vssgp.NEST%d", i),
				Name: fmt.Sprintf("Nest %d", i), Account: fmt.Sprintf("Nest %d", i), Group: true}, members...)
		}
		f := fetcherOn(t, fo.endpoint())
		set := f.dir.expand(ctx, &principal{Descriptor: "Microsoft.TeamFoundation.Identity;S-NEST-0", Subject: "vssgp.NEST0", Name: "Nest 0", Kind: kindGroup})
		if set.complete || !f.warnedAbout("nests more than") {
			t.Errorf("set complete = %v, warnings = %v", set.complete, f.warnings)
		}
	})

	t.Run("odd members", func(t *testing.T) {
		fo := newFakeOrg(t)
		// A group with no subject descriptor of its own, named in the
		// membership by its bare base64 identity descriptor.
		bareGroup := "Microsoft.TeamFoundation.Identity;S-BARE"
		fo.mu.Lock()
		fo.identities = append(fo.identities, fakeIdentity{Descriptor: bareGroup, Name: "[x]\\Bare", Account: "Bare", Group: true})
		fo.mu.Unlock()
		fo.graphGroup(fakeIdentity{Descriptor: "Microsoft.TeamFoundation.Identity;S-ODD", Subject: "vssgp.ODD", Name: "[x]\\Odd", Account: "Odd", Group: true},
			"vssgp.ODD", // itself
			"",          // nothing
			"vssgp.PVU", // everyone
			base64.RawURLEncoding.EncodeToString([]byte(bareGroup)),
		)
		fo.graphGroup(fakeIdentity{Descriptor: "Microsoft.TeamFoundation.Identity;S-LOST", Subject: "vssgp.LOST", Name: "[x]\\Lost", Account: "Lost", Group: true},
			base64.RawURLEncoding.EncodeToString([]byte("Microsoft.TeamFoundation.Identity;S-NOBODY")), // decodes, resolves to no one
			"not!base64", // neither a subject nor a descriptor
		)
		f := fetcherOn(t, fo.endpoint())
		set := f.dir.expand(ctx, &principal{Descriptor: "Microsoft.TeamFoundation.Identity;S-ODD", Subject: "vssgp.ODD", Name: "[x]\\Odd", Kind: kindGroup})
		if !set.everyone {
			t.Errorf("set = %+v, warnings = %v", set, f.warnings)
		}
		if _, ok := set.groups[descriptorKey(bareGroup)]; !ok {
			t.Errorf("the group named by its bare descriptor is missing: %v", set.groups)
		}
		lost := f.dir.expand(ctx, &principal{Descriptor: "Microsoft.TeamFoundation.Identity;S-LOST", Subject: "vssgp.LOST", Name: "[x]\\Lost", Kind: kindGroup})
		if lost.complete || !f.warnedAbout("could not be resolved") {
			t.Errorf("lost = %+v, warnings = %v", lost, f.warnings)
		}
	})
}

// ---- IMS expansion (Server) ------------------------------------------------

// imsDirectory answers IMS the way a Server collection does, from a fixed
// set of identities and one group's member lists.
func imsDirectory(t *testing.T, group string, expanded, direct []string, ids map[string]map[string]any) *Fetcher {
	t.Helper()
	return fetcherServing(t, scm.DeploymentServer, func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		var out []any
		for _, d := range strings.Split(q.Get("descriptors"), ",") {
			if strings.EqualFold(d, group) {
				members := expanded
				if strings.EqualFold(q.Get("queryMembership"), "Direct") {
					members = direct
				}
				out = append(out, map[string]any{"descriptor": group, "isContainer": true, "members": members, "providerDisplayName": "[c]\\G"})
				continue
			}
			if id, ok := ids[d]; ok {
				out = append(out, id)
			} else {
				out = append(out, nil)
			}
		}
		writeJSON(w, http.StatusOK, collection(out))
	})
}

func TestIMSExpansionLowerBounds(t *testing.T) {
	ctx := context.Background()
	const (
		group   = "Microsoft.TeamFoundation.Identity;S-G"
		person  = "Microsoft.IdentityModel.Claims.ClaimsIdentity;t\\p@c.com"
		adGroup = "System.Security.Principal.WindowsIdentity;S-1-5-21-9"
		all     = "Microsoft.TeamFoundation.Identity;S-ALL"
		nobody  = "Microsoft.TeamFoundation.Identity;S-NOBODY"
	)
	ids := map[string]map[string]any{
		person:  {"descriptor": person, "isActive": true, "properties": map[string]any{"Account": map[string]any{"$value": "p@c.com"}}},
		adGroup: {"descriptor": adGroup, "isContainer": true, "providerDisplayName": "CORP\\Devs"},
		all:     {"descriptor": all, "isContainer": true, "providerDisplayName": "[c]\\Project Collection Valid Users"},
	}
	f := imsDirectory(t, group, []string{person, adGroup, all, nobody, group}, []string{person, nobody}, ids)

	set := f.dir.expandIMS(ctx, &principal{Descriptor: group, Name: "[c]\\G", Kind: kindExternalGroup})
	if set.complete || !set.everyone || len(set.humans) != 1 {
		t.Errorf("expansion = %+v", set)
	}
	if !f.warnedAbout("could not be fully expanded") {
		t.Errorf("warnings = %v", f.warnings)
	}

	direct, ok := f.dir.directMembers(ctx, &principal{Descriptor: group, Name: "[c]\\G", Kind: kindGroup})
	if ok || len(direct) != 1 {
		t.Errorf("direct = %v, %v; want the one resolvable member, incomplete", direct, ok)
	}

	// The group itself not returned, and IMS failing outright.
	missing := f.dir.expandIMS(ctx, &principal{Descriptor: nobody, Name: "Nobody", Kind: kindGroup})
	if missing.complete || !f.warnedAbout("the identity was not returned") {
		t.Errorf("missing = %+v, warnings = %v", missing, f.warnings)
	}
	failing := fetcherServing(t, scm.DeploymentServer, func(w http.ResponseWriter, _ *http.Request) {
		writeError(w, http.StatusBadRequest, "TF400813: no")
	})
	if set := failing.dir.expandIMS(ctx, &principal{Descriptor: group, Name: "G", Kind: kindGroup}); set.complete {
		t.Error("a failed expansion is complete")
	}
	if _, ok := failing.dir.directMembers(ctx, &principal{Descriptor: group, Name: "G", Kind: kindGroup}); ok {
		t.Error("a failed direct listing is complete")
	}
}

// ---- ACL evaluation --------------------------------------------------------

func TestEvaluateReadsOnlyWhatTheServerEvaluated(t *testing.T) {
	ctx := context.Background()
	const token = "repoV2/p"
	answer := func(body any) *Fetcher {
		return fetcherServing(t, scm.DeploymentServices, func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, http.StatusOK, body) })
	}

	if eval, err := answer(nil).evaluate(ctx, token, nil); err != nil || !eval.complete {
		t.Errorf("nobody to ask about: %+v, %v", eval, err)
	}

	failing := fetcherServing(t, scm.DeploymentServices, func(w http.ResponseWriter, _ *http.Request) { writeError(w, http.StatusBadRequest, "no") })
	if _, err := failing.evaluate(ctx, token, []string{"a"}); err == nil {
		t.Error("a failed evaluation succeeded")
	}

	other := answer(collection([]any{map[string]any{"token": "repoV2/q", "acesDictionary": map[string]any{}}}))
	if eval, _ := other.evaluate(ctx, token, []string{"a"}); eval.complete {
		t.Error("an answer about another token counts as an evaluation")
	}

	// "a" keyed only by its dictionary key, and evaluated; "b" with explicit
	// bits only; "c" missing altogether.
	mixed := answer(collection([]any{map[string]any{"token": token + "/", "acesDictionary": map[string]any{
		"a": map[string]any{"allow": 0, "extendedInfo": map[string]any{"effectiveAllow": 8}},
		"b": map[string]any{"descriptor": "b", "allow": 8},
	}}}))
	eval, err := mixed.evaluate(ctx, token, []string{"a", "b", "c"})
	if err != nil || eval.complete || !eval.has("a", 8) || eval.has("b", 8) {
		t.Errorf("mixed = %+v, %v", eval, err)
	}
}

func TestACEDescriptorsFallBackToTheKey(t *testing.T) {
	got := aceDescriptors([]apiACL{{Token: "repoV2", AcesDictionary: map[string]apiACE{"D1": {}}}}, func(string) bool { return true })
	if len(got) != 1 || got[0] != "D1" {
		t.Errorf("aceDescriptors = %v", got)
	}
}

// ---- the namespace check ---------------------------------------------------

func TestNamespaceCheck(t *testing.T) {
	asked := false
	f := fetcherServing(t, "", func(http.ResponseWriter, *http.Request) { asked = true })
	f.checkNamespace(context.Background())
	if asked {
		t.Error("a client with no deployment asked for the namespace")
	}

	fo := newFakeOrg(t)
	fo.json("/fabrikam/_apis/securitynamespaces/2e9eb7ed-3c0a-47d4-87c1-0ffdd275fd87", collection([]any{map[string]any{
		"name": "Git Repositories", "actions": []any{map[string]any{"bit": 16, "name": "ForcePush"}},
	}}))
	s := mustFetch(t, fo, nil)
	if !warned(s, "defines ForcePush as bit 16") {
		t.Errorf("warnings = %v", s.Metadata.Warnings)
	}
}

// ---- whole fetches ---------------------------------------------------------

// failWhen wraps a route so requests matching match fail with a 400, and the
// rest reach the original handler.
func (f *fakeOrg) failWhen(path string, orig http.HandlerFunc, match func(url.Values) bool) {
	f.handle(path, func(w http.ResponseWriter, r *http.Request) {
		if match(r.URL.Query()) {
			writeError(w, http.StatusBadRequest, "TF400813: refused by the test")
			return
		}
		orig(w, r)
	})
}

const aclPath = "/fabrikam/_apis/accesscontrollists/2e9eb7ed-3c0a-47d4-87c1-0ffdd275fd87"

func TestTransportWarningsReachTheSnapshot(t *testing.T) {
	fo := newFakeOrg(t)
	c, err := NewClient(Options{Endpoint: fo.endpoint(), Token: "pat", Insecure: true})
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewFetcher(c, config.Default()).Fetch(context.Background(), FetchOptions{Now: testNow, Projects: []string{"Fabrikam-Fiber-TFVC"}})
	if err != nil {
		t.Fatal(err)
	}
	if !warned(s, "TLS certificate verification was disabled") {
		t.Errorf("warnings = %v", s.Metadata.Warnings)
	}
	// That project has no repositories, which is worth saying too.
	if !warned(s, "covered 0 repositories") {
		t.Errorf("warnings = %v", s.Metadata.Warnings)
	}
}

// A scan cancelled while projects and repositories wait for a slot stops
// them where they wait, and reports the cancellation rather than a partial
// snapshot.
func TestACancelledScanStopsWaitingWork(t *testing.T) {
	fo := newFakeOrg(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var once sync.Once
	fo.mu.Lock()
	refs := fo.routes["/fabrikam/"+projectID+"/_apis/git/repositories/"+repoMainID+"/refs"]
	fo.mu.Unlock()
	for _, id := range []string{repoEmptyID, repoMainID, repoArchID} {
		path := "/fabrikam/" + projectID + "/_apis/git/repositories/" + id + "/refs"
		fo.mu.Lock()
		orig := fo.routes[path]
		fo.mu.Unlock()
		if orig == nil {
			orig = refs
		}
		fo.handle(path, func(w http.ResponseWriter, r *http.Request) {
			once.Do(cancel)
			orig(w, r)
		})
	}
	c, _ := NewClient(Options{Endpoint: fo.endpoint(), Token: "pat"})
	if _, err := NewFetcher(c, config.Default()).Fetch(ctx, FetchOptions{Now: testNow, Concurrency: 1}); err == nil {
		t.Error("a cancelled scan returned a snapshot")
	}
}

// Cancelled while the first project holds the only slot: the others never
// start.
func TestACancelledScanStopsWaitingProjects(t *testing.T) {
	fo := newFakeOrg(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var once sync.Once
	for _, id := range []string{projectID, project2ID, "eb6e4656-77fc-42a1-9181-4c6d8e9da5d1"} {
		path := "/fabrikam/" + id + "/_apis/policy/configurations"
		fo.mu.Lock()
		orig := fo.routes[path]
		fo.mu.Unlock()
		if orig == nil {
			orig = func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, http.StatusOK, collection([]any{})) }
		}
		fo.handle(path, func(w http.ResponseWriter, r *http.Request) {
			once.Do(cancel)
			orig(w, r)
		})
	}
	c, _ := NewClient(Options{Endpoint: fo.endpoint(), Token: "pat"})
	if _, err := NewFetcher(c, config.Default()).Fetch(ctx, FetchOptions{Now: testNow, Concurrency: 1}); err == nil {
		t.Error("a cancelled scan returned a snapshot")
	}
}

func TestTargetsThatCannotBeRead(t *testing.T) {
	t.Run("the project list", func(t *testing.T) {
		fo := newFakeOrg(t)
		fo.mu.Lock()
		orig := fo.routes["/fabrikam/_apis/projects"]
		fo.mu.Unlock()
		fo.failWhen("/fabrikam/_apis/projects", orig, func(q url.Values) bool { return q.Get("$top") == "100" })
		if _, err := fetchWith(t, fo, nil); err == nil || !strings.Contains(err.Error(), "list projects") {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("a named project", func(t *testing.T) {
		fo := newFakeOrg(t)
		fo.fail("/fabrikam/_apis/projects/Fabrikam-Fiber-Git", http.StatusBadRequest, "TF400813: no")
		if _, err := fetchWith(t, fo, func(s *fetchSetup) { s.opts.Projects = []string{"Fabrikam-Fiber-Git"} }); err == nil || !strings.Contains(err.Error(), "fetch project") {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("a named repository", func(t *testing.T) {
		fo := newFakeOrg(t)
		fo.fail("/fabrikam/"+projectID+"/_apis/git/repositories/Fabrikam-Fiber-Git", http.StatusBadRequest, "TF400813: no")
		if _, err := fetchWith(t, fo, func(s *fetchSetup) { s.opts.Repositories = []string{"Fabrikam-Fiber-Git/Fabrikam-Fiber-Git"} }); err == nil || !strings.Contains(err.Error(), "fetch repository") {
			t.Errorf("err = %v", err)
		}
	})
}

func TestOneProjectReportsProgressWithoutAProjectCount(t *testing.T) {
	var lines []string
	var mu sync.Mutex
	mustFetch(t, newFakeOrg(t), func(s *fetchSetup) {
		s.opts.Projects = []string{"Fabrikam-Fiber-Git"}
		s.opts.Progress = func(line string) { mu.Lock(); lines = append(lines, line); mu.Unlock() }
	})
	if len(lines) == 0 || strings.Contains(lines[0], "project 1/") {
		t.Errorf("progress = %v", lines)
	}
}

// A collection administrator that is a service identity is listed as one.
func TestAServiceAmongTheAdministrators(t *testing.T) {
	fo := newFakeOrg(t)
	fo.mu.Lock()
	fo.memberships["vssgp.PCA"] = append(fo.memberships["vssgp.PCA"], "svc.BUILD")
	fo.mu.Unlock()
	s := mustFetch(t, fo, nil)
	for _, a := range s.Organization.Admins {
		if a.Type == "service" {
			return
		}
	}
	t.Errorf("admins = %+v", s.Organization.Admins)
}

func TestProjectPermissionsThatCannotBeRead(t *testing.T) {
	ptok := projectToken(projectID)
	t.Run("the project's entries", func(t *testing.T) {
		fo := newFakeOrg(t)
		fo.failWhen(aclPath, fo.aclHandler, func(q url.Values) bool {
			return strings.EqualFold(q.Get("token"), ptok) && q.Get("descriptors") == ""
		})
		s := mustFetch(t, fo, nil)
		if !warned(s, "Git permissions are not readable") {
			t.Errorf("warnings = %v", s.Metadata.Warnings)
		}
	})
	t.Run("who may create repositories", func(t *testing.T) {
		fo := newFakeOrg(t)
		fo.failWhen(aclPath, fo.aclHandler, func(q url.Values) bool {
			return strings.EqualFold(q.Get("token"), ptok) && q.Get("descriptors") != ""
		})
		s := mustFetch(t, fo, nil)
		if !warned(s, "who may create repositories could not be evaluated") {
			t.Errorf("warnings = %v", s.Metadata.Warnings)
		}
	})
}

// ---- repositories ----------------------------------------------------------

// The main repository with its default branch unset, though it has branches.
func withoutDefaultBranch(fo *fakeOrg) {
	fo.json("/fabrikam/"+projectID+"/_apis/git/repositories", collection([]any{
		map[string]any{"id": repoMainID, "name": "Fabrikam-Fiber-Git", "project": map[string]any{"id": projectID, "name": "Fabrikam-Fiber-Git"}},
	}))
}

func TestBranchesWithoutADefault(t *testing.T) {
	t.Run("repository policies readable", func(t *testing.T) {
		fo := newFakeOrg(t)
		withoutDefaultBranch(fo)
		repo := findRepo(t, mustFetch(t, fo, nil), "Fabrikam-Fiber-Git/Fabrikam-Fiber-Git")
		if repo.Available["defaultBranch"] || !strings.Contains(strings.Join(repo.Errors, " "), "no default branch is configured") {
			t.Errorf("repo = %+v", repo.Errors)
		}
	})
	t.Run("repository policies unreadable", func(t *testing.T) {
		fo := newFakeOrg(t)
		withoutDefaultBranch(fo)
		fo.failWhen("/fabrikam/"+projectID+"/_apis/git/policy/configurations", fo.branchPolicyList(), func(q url.Values) bool { return q.Get("refName") == "" })
		repo := findRepo(t, mustFetch(t, fo, nil), "Fabrikam-Fiber-Git/Fabrikam-Fiber-Git")
		if repo.Available["branchRestrictions"] {
			t.Errorf("restrictions available over an unreadable policy list: %v", repo.Errors)
		}
	})
	t.Run("project policies unreadable", func(t *testing.T) {
		fo := newFakeOrg(t)
		withoutDefaultBranch(fo)
		fo.fail("/fabrikam/"+projectID+"/_apis/policy/configurations", http.StatusBadRequest, "TF400813: no")
		repo := findRepo(t, mustFetch(t, fo, nil), "Fabrikam-Fiber-Git/Fabrikam-Fiber-Git")
		if !repo.Available["branchRestrictions"] {
			t.Errorf("restrictions = %v", repo.Errors)
		}
	})
}

func TestBranchDatesThatCannotBeRead(t *testing.T) {
	stats := "/fabrikam/" + projectID + "/_apis/git/repositories/" + repoMainID + "/stats/branches"
	t.Run("unreadable", func(t *testing.T) {
		fo := newFakeOrg(t)
		fo.fail(stats, http.StatusBadRequest, "TF400813: no")
		repo := findRepo(t, mustFetch(t, fo, nil), "Fabrikam-Fiber-Git/Fabrikam-Fiber-Git")
		if repo.Available["branchAges"] {
			t.Error("branch ages available over an unreadable list")
		}
	})
	t.Run("author dates and garbage", func(t *testing.T) {
		fo := newFakeOrg(t)
		authorOnly := branchStat("master", "2026-09-28T10:00:00Z")
		authorOnly["commit"].(map[string]any)["committer"] = map[string]any{}
		garbled := branchStat("feature/calcApp", "last tuesday")
		fo.json(stats, collection([]any{authorOnly, garbled, branchStat("feature/replacer", "2025-01-10T10:00:00Z")}))
		repo := findRepo(t, mustFetch(t, fo, nil), "Fabrikam-Fiber-Git/Fabrikam-Fiber-Git")
		if repo.Available["branchAges"] {
			t.Error("a garbled date was read")
		}
		for _, b := range repo.Branches {
			if b.ID == "refs/heads/master" && b.AgeDays < 0 {
				t.Error("the author date was not used when the committer date is missing")
			}
		}
	})
}

func TestRepositoryPermissionsThatCannotBeRead(t *testing.T) {
	rtok := repoToken(projectID, repoMainID)
	btok := branchToken(projectID, repoMainID, "refs/heads/master")
	for name, tc := range map[string]struct {
		match func(url.Values) bool
		want  string
	}{
		"the repository's entries": {func(q url.Values) bool {
			return strings.EqualFold(q.Get("token"), rtok) && q.Get("descriptors") == ""
		}, "repository Git permissions"},
		"the repository evaluation": {func(q url.Values) bool {
			return strings.EqualFold(q.Get("token"), rtok) && q.Get("descriptors") != ""
		}, "repository Git permissions"},
		"the branch evaluation": {func(q url.Values) bool {
			return strings.EqualFold(q.Get("token"), btok) && q.Get("descriptors") != ""
		}, "default branch Git permissions"},
	} {
		t.Run(name, func(t *testing.T) {
			fo := newFakeOrg(t)
			fo.failWhen(aclPath, fo.aclHandler, tc.match)
			repo := findRepo(t, mustFetch(t, fo, nil), "Fabrikam-Fiber-Git/Fabrikam-Fiber-Git")
			if repo.Available["bypass"] {
				t.Errorf("bypass available over unreadable permissions (%s): %v", tc.want, repo.Errors)
			}
		})
	}
}

// An entry on the repository itself makes its holder a candidate, and an
// everyone group holding two rights is listed under each.
func TestRepositoryEntriesAndEveryoneGrants(t *testing.T) {
	fo := newFakeOrg(t)
	fo.mu.Lock()
	fo.acls[repoToken(projectID, repoMainID)] = map[string]fakeACE{descBob: {allow: 4}}
	fo.acls["repoV2/"+projectID][descPVU] = fakeACE{allow: 2 | 4}
	fo.acls["repoV2"][descPCVU] = fakeACE{allow: 2}
	fo.mu.Unlock()
	s := mustFetch(t, fo, nil)
	repo := findRepo(t, s, "Fabrikam-Fiber-Git/Fabrikam-Fiber-Git")
	n := 0
	for _, p := range repo.Permissions.EveryoneGrants {
		if strings.HasSuffix(p.Name, "Project Valid Users") {
			n++
		}
	}
	if n < 2 {
		t.Errorf("everyone grants = %+v", repo.Permissions.EveryoneGrants)
	}
}
