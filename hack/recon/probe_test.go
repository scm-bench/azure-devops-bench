// Package recon tests probe.sh, the read-only capture script the README sends
// people to run against their own organization. A script handed a production
// credential gets the same scrutiny as the binary: these tests run it against
// a stand-in organization and check every promise its header makes.
package recon

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

const (
	// A PAT-shaped value: 52 base32 characters.
	testToken = "q3x7vdl4kq2c6mfzd5s7jmyo4kezs2nkc3jjhd6tq5qyixu2wfpa"
	pid       = "6ce954b1-ce1f-45d1-b94d-e6bf2464ba2c"
	rid       = "278d5cd2-584d-4b63-824a-2ba458937249"
	pcaDesc   = "Microsoft.TeamFoundation.Identity;S-1-9-1551374245-1204400969-2402986413-2179408616-0-0-0-0-1"
	paDesc    = "Microsoft.TeamFoundation.Identity;S-1-9-1551374245-1204400969-2402986413-2179408616-1-1-1-1-1"
	creator   = "Microsoft.IdentityModel.Claims.ClaimsIdentity;7a394543\\dev@fabrikam.com"
	member    = "Microsoft.IdentityModel.Claims.ClaimsIdentity;7a394543\\alice@fabrikam.com"
	gitNS     = "2e9eb7ed-3c0a-47d4-87c1-0ffdd275fd87"
)

type seen struct {
	Method, Host, Path, Query, Auth string
	Suppressed                      bool
}

// standIn answers the requests probe.sh makes, in the documented shapes, and
// records them. It echoes the Authorization header back in one body and sets
// a cookie on another, to prove neither reaches a capture.
type standIn struct {
	mu   sync.Mutex
	reqs []seen
}

func (s *standIn) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host := r.Header.Get("X-Original-Host")
	if host == "" {
		host = r.Host
	}
	s.mu.Lock()
	s.reqs = append(s.reqs, seen{r.Method, host, r.URL.Path, r.URL.RawQuery, r.Header.Get("Authorization"), r.Header.Get("X-TFS-FedAuthRedirect") == "Suppress"})
	s.mu.Unlock()

	reply := func(body any) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8; api-version=7.1")
		json.NewEncoder(w).Encode(body)
	}
	fail := func(status int, msg string) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(map[string]any{"message": msg, "typeKey": "VssServiceException"})
	}
	list := func(items ...any) map[string]any { return map[string]any{"count": len(items), "value": items} }

	if r.Header.Get("Authorization") != "Basic "+base64.StdEncoding.EncodeToString([]byte(":"+testToken)) {
		if r.Header.Get("X-TFS-FedAuthRedirect") == "Suppress" {
			w.Header().Set("WWW-Authenticate", "Basic realm=\"https://dev.azure.com/\"")
			fail(http.StatusUnauthorized, "TF400813: The user is not authorized to access this resource.")
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusNonAuthoritativeInfo)
		fmt.Fprint(w, "<html><body>Sign in to your account</body></html>")
		return
	}

	// The organization or collection segment is the first; the rest routes.
	parts := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/"), "/", 2)
	rest := "/"
	if len(parts) == 2 {
		rest += parts[1]
	}
	q := r.URL.Query()
	switch {
	case rest == "/_apis/projects" && q.Get("stateFilter") == "":
		reply(list(map[string]any{"id": pid, "name": "Fabrikam"}))
	case rest == "/_apis/projects" && q.Get("continuationToken") == "":
		w.Header().Set("x-ms-continuationtoken", "1")
		reply(list(map[string]any{"id": pid, "name": "Fabrikam", "state": "wellFormed"}))
	case rest == "/_apis/projects":
		reply(list(map[string]any{"id": "00000000-0000-0000-0000-000000000002", "name": "Other", "state": "wellFormed"}))
	case rest == "/_apis/projects/Fabrikam":
		w.Header().Set("Set-Cookie", "VstsSession=session-cookie-value; HttpOnly")
		reply(map[string]any{"id": pid, "name": "Fabrikam", "visibility": "private",
			"description": "echoed " + r.Header.Get("Authorization"), "accessToken": "should-not-survive"})
	case rest == "/_apis/securitynamespaces/"+gitNS:
		reply(list(map[string]any{"namespaceId": gitNS, "actions": []any{map[string]any{"bit": 8, "name": "ForcePush"}}}))
	case rest == "/_apis/accesscontrollists/"+gitNS:
		token := q.Get("token")
		var aces map[string]any
		switch {
		case q.Get("descriptors") != "":
			aces = map[string]any{}
			for _, d := range strings.Split(q.Get("descriptors"), ",") {
				aces[d] = map[string]any{"descriptor": d, "allow": 0, "deny": 0, "extendedInfo": map[string]any{"effectiveAllow": 2}}
			}
		case token == "repoV2":
			aces = map[string]any{pcaDesc: map[string]any{"descriptor": pcaDesc, "allow": 16382}}
		case token == "repoV2/"+pid:
			aces = map[string]any{paDesc: map[string]any{"descriptor": paDesc, "allow": 16382}}
		default:
			aces = map[string]any{creator: map[string]any{"descriptor": creator, "allow": 8}}
		}
		reply(list(map[string]any{"inheritPermissions": true, "token": token, "acesDictionary": aces}))
	case rest == "/"+pid+"/_apis/git/repositories":
		reply(list(
			map[string]any{"id": "0d6e9b4f-7c2a-4f8e-9b1d-3a5c7e9f1b2d", "name": "archived", "defaultBranch": "refs/heads/main", "isDisabled": true},
			map[string]any{"id": rid, "name": "app", "defaultBranch": "refs/heads/main"},
		))
	case rest == "/"+pid+"/_apis/git/repositories/app":
		reply(map[string]any{"id": rid, "name": "app", "defaultBranch": "refs/heads/main"})
	case rest == "/"+pid+"/_apis/git/repositories/"+rid+"/refs":
		reply(list(map[string]any{"name": "refs/heads/main", "objectId": "abc", "creator": map[string]any{"descriptor": "aad.Q1JFQVRPUg"}}))
	case rest == "/"+pid+"/_apis/git/repositories/"+rid+"/stats/branches":
		reply(list(map[string]any{"name": "main", "commit": map[string]any{"committer": map[string]any{"date": "2026-09-30T00:00:00Z"}}}))
	case rest == "/"+pid+"/_apis/git/repositories/"+rid+"/items" && q.Get("scopePath") == "/":
		reply(list(map[string]any{"path": "/SECURITY.md", "gitObjectType": "blob"}))
	case strings.HasSuffix(rest, "/items") && strings.Contains(rest, rid):
		fail(http.StatusNotFound, "TF401174: The item could not be found in the repository.")
	case strings.HasSuffix(rest, "/items"):
		fail(http.StatusNotFound, "TF401019: The Git repository with name or identifier 00000000-0000-0000-0000-000000000000 does not exist or you do not have permissions for the operation you are attempting.")
	case rest == "/"+pid+"/_apis/policy/configurations", rest == "/"+pid+"/_apis/git/policy/configurations":
		reply(list())
	case rest == "/_apis/identities":
		switch {
		case q.Get("searchFilter") == "General":
			reply(list(map[string]any{"descriptor": pcaDesc, "subjectDescriptor": "vssgp.PCA", "providerDisplayName": "[fabrikam]\\Project Collection Administrators"}))
		case q.Get("subjectDescriptors") != "":
			reply(list(map[string]any{"descriptor": creator, "subjectDescriptor": q.Get("subjectDescriptors")}))
		case q.Get("queryMembership") == "ExpandedDown" || q.Get("queryMembership") == "Direct":
			reply(list(map[string]any{"descriptor": q.Get("descriptors"), "members": []any{member, pcaDesc}}))
		default:
			var out []any
			for _, d := range strings.Split(q.Get("descriptors"), ",") {
				name := "someone"
				if d == paDesc {
					name = "[Fabrikam]\\Project Administrators"
				}
				out = append(out, map[string]any{"descriptor": d, "providerDisplayName": name})
			}
			reply(list(out...))
		}
	case rest == "/_apis/graph/Memberships/vssgp.PCA":
		reply(list(map[string]any{"containerDescriptor": "vssgp.PCA", "memberDescriptor": "aad.QUxJQ0U"}))
	case rest == "/_apis/userentitlements" && q.Get("continuationToken") == "":
		reply(map[string]any{"items": []any{map[string]any{"user": map[string]any{"principalName": "alice@fabrikam.com"}, "lastAccessedDate": "0001-01-01T00:00:00Z"}}, "continuationToken": "page-2"})
	case rest == "/_apis/userentitlements":
		reply(map[string]any{"items": []any{map[string]any{"user": map[string]any{"principalName": "bob@fabrikam.com"}}}})
	case rest == "/_apis/management/enablement":
		reply(map[string]any{"reposEnablementStatus": []any{}})
	default:
		fail(http.StatusNotFound, "TF400898: no route for "+r.URL.Path)
	}
}

func (s *standIn) requests() []seen {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]seen(nil), s.reqs...)
}

func requireTools(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("probe.sh is a POSIX shell script")
	}
	for _, tool := range []string{"bash", "curl", "jq", "awk", "od", "iconv", "base64"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is not installed", tool)
		}
	}
}

// runProbe runs probe.sh with the given organization URL and extra
// environment, returning its output and the capture directory.
func runProbe(t *testing.T, orgURL string, extraEnv ...string) (string, string) {
	t.Helper()
	out := filepath.Join(t.TempDir(), "capture")
	cmd := exec.Command("bash", "probe.sh", "Fabrikam")
	cmd.Env = append(os.Environ(),
		"AZURE_DEVOPS_URL="+orgURL,
		"AZURE_DEVOPS_TOKEN="+testToken,
		"PROBE_OUT="+out,
	)
	cmd.Env = append(cmd.Env, extraEnv...)
	combined, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("probe.sh failed: %v\n%s", err, combined)
	}
	return string(combined), out
}

// secretForms are the token as sent and as it could plausibly be echoed.
func secretForms() []string {
	return []string{
		testToken,
		base64.StdEncoding.EncodeToString([]byte(":" + testToken)),
		base64.StdEncoding.EncodeToString([]byte(testToken)),
	}
}

func assertNoSecret(t *testing.T, where, text string) {
	t.Helper()
	for _, s := range secretForms() {
		if strings.Contains(text, s) {
			t.Errorf("%s contains the credential", where)
		}
	}
}

// assertCaptureIsClean checks every promise about what lands on disk.
func assertCaptureIsClean(t *testing.T, dir string) {
	t.Helper()
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Errorf("capture directory mode = %o, want 700", info.Mode().Perm())
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".") || strings.HasSuffix(e.Name(), ".tmp") {
			t.Errorf("temporary file %s outlived the run", e.Name())
		}
		path := filepath.Join(dir, e.Name())
		info, _ := os.Stat(path)
		if info.Mode().Perm() != 0o600 {
			t.Errorf("%s mode = %o, want 600", e.Name(), info.Mode().Perm())
		}
		raw, _ := os.ReadFile(path)
		assertNoSecret(t, e.Name(), string(raw))
		if strings.Contains(string(raw), "session-cookie-value") || strings.Contains(string(raw), "should-not-survive") {
			t.Errorf("%s kept a cookie or a secret-named field", e.Name())
		}
	}
	echoed, err := os.ReadFile(filepath.Join(dir, "05-project.json"))
	if err != nil || !strings.Contains(string(echoed), "[REDACTED]") {
		t.Errorf("the echoed credential was not replaced: %s (%v)", echoed, err)
	}
}

func captureIDs(t *testing.T, dir string) []string {
	t.Helper()
	f, err := os.Open(filepath.Join(dir, "index.tsv"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var ids []string
	sc := bufio.NewScanner(f)
	sc.Scan() // header
	for sc.Scan() {
		ids = append(ids, strings.SplitN(sc.Text(), "\t", 2)[0])
	}
	return ids
}

// The real curl against a stand-in Azure DevOps Server collection on
// loopback: the flow end to end, with the flags curl is actually given.
func TestProbeAgainstAServerCollection(t *testing.T) {
	requireTools(t)
	s := &standIn{}
	srv := httptest.NewServer(s)
	defer srv.Close()

	output, dir := runProbe(t, srv.URL+"/DefaultCollection")
	assertNoSecret(t, "the probe's output", output)
	assertCaptureIsClean(t, dir)

	reqs := s.requests()
	for _, r := range reqs {
		if r.Method != http.MethodGet {
			t.Errorf("%s %s: the probe sent something other than a GET", r.Method, r.Path)
		}
		if strings.Contains(r.Path+r.Query, testToken) {
			t.Errorf("the credential travelled in a URL: %s?%s", r.Path, r.Query)
		}
	}
	// The three deliberately unauthenticated preflights, then the real one.
	if len(reqs) < 4 || reqs[0].Auth != "" || !strings.HasPrefix(reqs[1].Auth, "Basic ") || reqs[1].Auth == reqs[3].Auth ||
		!reqs[1].Suppressed || reqs[2].Suppressed || !reqs[3].Suppressed {
		t.Errorf("preflights = %+v", reqs[:min(4, len(reqs))])
	}

	ids := strings.Join(captureIDs(t, dir), " ")
	for _, want := range []string{"00-no-credential", "01-invalid-credential", "02-invalid-credential-no-suppress", "03-preflight",
		"04-projects.p1", "04-projects.p2", "04-projects-paging.p2", "11-refs.p1", "11-refs-paging.p1", "16-policies-project-paging.p1", "14-items-absent-path", "15-items-absent-repository",
		"17-policies-branch.p1", "22-identities", "23-collection-administrators-expanded", "26-project-administrators-expanded",
		"27-acl-evaluate-project", "28-acl-evaluate-repository", "29-acl-evaluate-branch"} {
		if !strings.Contains(ids, want) {
			t.Errorf("capture %s is missing from %s", want, ids)
		}
	}
	for _, absent := range []string{"25-collection-administrators-graph", "30-user-entitlements", "31-advanced-security"} {
		if strings.Contains(ids, absent) {
			t.Errorf("%s was probed on Server, which has no such API", absent)
		}
	}

	// The branch token spells main as the fetcher does, and the evaluation
	// asked about a member who holds rights only through a group.
	var branch seen
	for _, r := range reqs {
		if strings.Contains(r.Query, "refs%2Fheads%2F") && strings.Contains(r.Query, "includeExtendedInfo=true") {
			branch = r
		}
	}
	q, _ := url.ParseQuery(branch.Query)
	if q.Get("token") != "repoV2/"+pid+"/"+rid+"/refs/heads/6d00610069006e00/" {
		t.Errorf("branch token = %q", q.Get("token"))
	}
	if !strings.Contains(q.Get("descriptors"), member) || !strings.Contains(q.Get("descriptors"), creator) {
		t.Errorf("evaluated descriptors = %q", q.Get("descriptors"))
	}
	if raw, _ := os.ReadFile(filepath.Join(dir, "probe.txt")); !strings.Contains(string(raw), "deployment:    server") {
		t.Errorf("probe.txt = %s", raw)
	}
}

// fakeCurl is put first on PATH for the Services scenario. It records how it
// was invoked — which is where a credential in an argument list would show —
// then hands the request to the real curl, pointed at the stand-in over
// loopback with the host it was meant for in X-Original-Host. stdin, which
// carries the Authorization header, passes through untouched.
const fakeCurl = `#!/bin/sh
for a in "$@"; do printf '%s\n' "$a"; done >>"$PROBE_FAKE_CURL_LOG"
printf '%s\n' '----' >>"$PROBE_FAKE_CURL_LOG"
n=$#
host=
for a in "$@"; do
	case $a in
	https://*)
		host=${a#https://}
		host=${host%%/*}
		a="$PROBE_FAKE_CURL_TARGET${a#https://$host}"
		;;
	=https) a='=http' ;;
	esac
	set -- "$@" "$a"
done
shift "$n"
exec "$PROBE_REAL_CURL" --header "X-Original-Host: $host" "$@"
`

// The Services hosts cannot be served from loopback, so the fake curl above
// stands in front of the real one.
func TestProbeAgainstServicesKeepsTheTokenOffTheCommandLine(t *testing.T) {
	requireTools(t)
	s := &standIn{}
	srv := httptest.NewServer(s)
	defer srv.Close()

	realCurl, _ := exec.LookPath("curl")
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "curl"), []byte(fakeCurl), 0o700); err != nil {
		t.Fatal(err)
	}
	log := filepath.Join(t.TempDir(), "curl.log")

	output, dir := runProbe(t, "https://dev.azure.com/fabrikam",
		"PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"PROBE_REAL_CURL="+realCurl,
		"PROBE_FAKE_CURL_TARGET="+srv.URL,
		"PROBE_FAKE_CURL_LOG="+log,
	)
	assertNoSecret(t, "the probe's output", output)
	assertCaptureIsClean(t, dir)

	raw, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	invocations := strings.Split(strings.TrimSuffix(string(raw), "----\n"), "----\n")
	if len(invocations) < 30 {
		t.Fatalf("curl ran %d times; the log is not what this test thinks it is", len(invocations))
	}
	for _, args := range invocations {
		assertNoSecret(t, "a curl argument list", args)
		if !strings.Contains(args, "--request\nGET\n") {
			t.Errorf("curl was not told to GET:\n%s", args)
		}
	}

	hosts := map[string]bool{}
	for _, r := range s.requests() {
		hosts[r.Host] = true
		if r.Method != http.MethodGet {
			t.Errorf("%s %s", r.Method, r.Path)
		}
	}
	for _, h := range []string{"dev.azure.com", "vssps.dev.azure.com", "vsaex.dev.azure.com", "advsec.dev.azure.com"} {
		if !hosts[h] {
			t.Errorf("nothing was asked of %s; hosts = %v", h, hosts)
		}
	}
	ids := strings.Join(captureIDs(t, dir), " ")
	for _, want := range []string{"25-collection-administrators-graph", "30-user-entitlements.p1", "30-user-entitlements.p2", "31-advanced-security"} {
		if !strings.Contains(ids, want) {
			t.Errorf("capture %s is missing from %s", want, ids)
		}
	}
}

func TestProbeRefusesUnsafeInvocations(t *testing.T) {
	requireTools(t)
	for _, tc := range []struct {
		name, url, token, want string
	}{
		{"cleartext", "http://ado.example.com/DefaultCollection", testToken, "cleartext"},
		{"credentials in the URL", "https://user:pw@dev.azure.com/fabrikam", testToken, "carries credentials"},
		{"project page", "https://dev.azure.com/fabrikam/Fabrikam", testToken, "points inside"},
		{"no token", "https://dev.azure.com/fabrikam", "", "AZURE_DEVOPS_TOKEN"},
		{"short token", "https://dev.azure.com/fabrikam", "abc", "too short"},
		{"quoted token", "https://dev.azure.com/fabrikam", "\"" + testToken + "\"", "characters"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command("bash", "probe.sh")
			cmd.Env = append(os.Environ(), "AZURE_DEVOPS_URL="+tc.url, "AZURE_DEVOPS_TOKEN="+tc.token, "PROBE_OUT="+filepath.Join(t.TempDir(), "o"))
			out, err := cmd.CombinedOutput()
			if code := cmd.ProcessState.ExitCode(); err == nil || code != 2 {
				t.Errorf("exit = %d (%v), want 2", code, err)
			}
			if !strings.Contains(string(out), tc.want) {
				t.Errorf("output %q does not mention %q", out, tc.want)
			}
			assertNoSecret(t, "the refusal", string(out))
		})
	}
}
