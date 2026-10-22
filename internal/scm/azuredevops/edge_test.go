package azuredevops

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/scm-bench/azure-devops-bench/internal/config"
)

// ---- client ----------------------------------------------------------------

// A concurrency above the transport's idle-connection pool raises the pool
// with it, or the extra connections would be torn down after every request.
func TestHighConcurrencyRaisesTheIdlePool(t *testing.T) {
	c, err := NewClient(Options{URL: "https://dev.azure.com/fabrikam", Token: "pat", Concurrency: 500})
	if err != nil {
		t.Fatal(err)
	}
	tr := c.httpClient.Transport.(*http.Transport)
	if tr.MaxIdleConnsPerHost != 500 || tr.MaxIdleConns < 500 {
		t.Errorf("idle pool = %d per host, %d total", tr.MaxIdleConnsPerHost, tr.MaxIdleConns)
	}
}

func TestNewClientRefusesAnUnusableURL(t *testing.T) {
	if _, err := NewClient(Options{URL: "https://dev.azure.com", Token: "pat"}); err == nil {
		t.Error("a URL naming no organization was accepted")
	}
}

// The client narrates through the callbacks it is given.
func TestClientNarration(t *testing.T) {
	var logs, warns []string
	c, err := NewClient(Options{URL: "https://dev.azure.com/fabrikam", Token: "pat",
		Logf:  func(f string, a ...any) { logs = append(logs, fmt.Sprintf(f, a...)) },
		Warnf: func(f string, a ...any) { warns = append(warns, fmt.Sprintf(f, a...)) },
	})
	if err != nil {
		t.Fatal(err)
	}
	c.logf("hello %d", 1)
	c.warnf("careful %d", 2)
	if len(logs) != 1 || len(warns) != 1 {
		t.Errorf("logs = %v, warns = %v", logs, warns)
	}
}

func TestAnErrorWithoutATFCode(t *testing.T) {
	if code := (&APIError{Messages: []string{"no code here"}}).tfCode(); code != "" {
		t.Errorf("tfCode = %q", code)
	}
}

func TestAPathThatIsNoURLFailsBeforeSending(t *testing.T) {
	c := newTestClient(t, func(http.ResponseWriter, *http.Request) { t.Error("a request was sent") })
	if _, err := c.get(context.Background(), ServiceCore, "/%zz", nil); err == nil || !strings.Contains(err.Error(), "build request") {
		t.Errorf("err = %v", err)
	}
}

// A cancelled wait — between retries, or at the Retry-After gate — ends the
// request with the context's error rather than another attempt.
func TestAWaitThatIsCancelledEndsTheRequest(t *testing.T) {
	stop := errors.New("cancelled while waiting")

	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) { writeError(w, 503, "busy") })
	c.sleep = func(context.Context, time.Duration) error { return stop }
	if _, err := c.get(context.Background(), ServiceCore, "/_apis/x", nil); !errors.Is(err, stop) {
		t.Errorf("between retries: err = %v", err)
	}

	c = newTestClient(t, func(http.ResponseWriter, *http.Request) { t.Error("a request was sent through a closed gate") })
	c.sleep = func(context.Context, time.Duration) error { return stop }
	c.notBefore = time.Now().Add(time.Hour)
	if _, err := c.get(context.Background(), ServiceCore, "/_apis/x", nil); !errors.Is(err, stop) {
		t.Errorf("at the gate: err = %v", err)
	}
}

// A body cut off mid-read is transient: retried, then reported.
func TestATruncatedBodyIsRetriedThenReported(t *testing.T) {
	calls := 0
	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		calls++
		conn, buf, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		fmt.Fprint(buf, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{\"count\":")
		buf.Flush()
	})
	_, err := c.get(context.Background(), ServiceCore, "/_apis/x", nil)
	if err == nil || !strings.Contains(err.Error(), "read body") {
		t.Errorf("err = %v", err)
	}
	if calls != 3 {
		t.Errorf("calls = %d, want the first and two retries", calls)
	}
}

func TestContentTypeLabelKeepsWhatItCannotParse(t *testing.T) {
	if got := contentTypeLabel("text/html; ;"); got != "text/html; ;" {
		t.Errorf("contentTypeLabel = %q", got)
	}
}

func TestSleepContext(t *testing.T) {
	if err := sleepContext(context.Background(), 0); err != nil {
		t.Errorf("no wait: %v", err)
	}
	if err := sleepContext(context.Background(), time.Millisecond); err != nil {
		t.Errorf("a short wait: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := sleepContext(ctx, time.Hour); !errors.Is(err, context.Canceled) {
		t.Errorf("a cancelled wait: %v", err)
	}
}

// Every way a page can fail to be a page is an error naming the endpoint.
func TestGetAllRefusesWhatIsNotAPage(t *testing.T) {
	for name, tc := range map[string]struct {
		body string
		want string
	}{
		"not a collection":        {`{"something":"else"}`, "no value or items list"},
		"an item of another type": {`{"count":1,"value":["text"]}`, "decode item"},
		"a broken bare array":     {`[1,`, "decode response"},
	} {
		t.Run(name, func(t *testing.T) {
			c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprint(w, tc.body)
			})
			if _, err := getAll[item](context.Background(), c, ServiceCore, "/_apis/x", nil, pageOptions{}); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

// A server that keeps handing out fresh continuation tokens is stopped at a
// bound rather than followed forever.
func TestGetAllStopsAtThePageBound(t *testing.T) {
	calls := 0
	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.Header().Set("X-MS-ContinuationToken", fmt.Sprint(calls))
		writeJSON(w, 200, map[string]any{"count": 0, "value": []any{}})
	})
	if _, err := getAll[item](context.Background(), c, ServiceCore, "/_apis/x", nil, pageOptions{}); err == nil || !strings.Contains(err.Error(), "exceeded") {
		t.Errorf("err = %v", err)
	}
	if calls != maxPages {
		t.Errorf("calls = %d, want %d", calls, maxPages)
	}
}

func TestDecodeTokenOfAnotherShape(t *testing.T) {
	if got := decodeToken(json.RawMessage(`42`)); got != "" {
		t.Errorf("decodeToken = %q", got)
	}
}

func TestGetJSONRefusesAnUndecodableBody(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `[1,2]`)
	})
	var out struct{ ID string }
	if err := c.getJSON(context.Background(), ServiceCore, "/_apis/x", nil, &out); err == nil || !strings.Contains(err.Error(), "decode response") {
		t.Errorf("err = %v", err)
	}
}

// ---- endpoint --------------------------------------------------------------

func TestServiceNames(t *testing.T) {
	for s, want := range map[Service]string{ServiceCore: "core", ServiceIdentity: "identity", ServiceEntitlements: "entitlements", ServiceAdvancedSecurity: "advsec"} {
		if got := s.String(); got != want {
			t.Errorf("%d.String() = %q, want %q", s, got, want)
		}
	}
}

func TestOrganizationURLsThatNameNothing(t *testing.T) {
	for raw, want := range map[string]string{
		"https:///fabrikam":                   "no host",
		"https://a.b.visualstudio.com":        "not an organization URL",
		"https://.visualstudio.com/something": "not an organization URL",
	} {
		if _, _, err := ParseOrganizationURL(raw); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: err = %v, want %q", raw, err, want)
		}
	}
}

func TestRedactURLLeavesAnUnparseableURLWithoutCredentialsAlone(t *testing.T) {
	raw := "https://dev.azure.com/%zz"
	if got := redactURL(raw); got != raw {
		t.Errorf("redactURL = %q", got)
	}
}

func TestLocalhostIsLoopback(t *testing.T) {
	if !isLoopback(&url.URL{Host: "LOCALHOST:8080"}) {
		t.Error("localhost is not loopback")
	}
}

// ---- models ----------------------------------------------------------------

func TestIdentityDescriptorShapes(t *testing.T) {
	for raw, want := range map[string]string{
		`null`: "",
		`"Microsoft.TeamFoundation.Identity;S-1"`:                                 "Microsoft.TeamFoundation.Identity;S-1",
		`{"identityType":"Microsoft.TeamFoundation.Identity","identifier":"S-1"}`: "Microsoft.TeamFoundation.Identity;S-1",
		`{}`: "",
	} {
		var d identityDescriptor
		if err := json.Unmarshal([]byte(raw), &d); err != nil || string(d) != want {
			t.Errorf("%s: %q, %v; want %q", raw, d, err, want)
		}
	}
	var d identityDescriptor
	if err := json.Unmarshal([]byte(`[1]`), &d); err == nil {
		t.Error("an array was accepted as a descriptor")
	}
}

func TestFlexibleScalars(t *testing.T) {
	var s flexString
	if err := json.Unmarshal([]byte(`null`), &s); err != nil || s != "" {
		t.Errorf("flexString(null) = %q, %v", s, err)
	}
	var n flexInt
	if err := json.Unmarshal([]byte(`null`), &n); err != nil || n != 0 {
		t.Errorf("flexInt(null) = %d, %v", n, err)
	}
	if err := json.Unmarshal([]byte(`"many"`), &n); err == nil {
		t.Error("flexInt accepted a word")
	}
	var f flexFloat
	if err := json.Unmarshal([]byte(`null`), &f); err != nil || f != 0 {
		t.Errorf("flexFloat(null) = %v, %v", f, err)
	}
	if err := json.Unmarshal([]byte(`"many"`), &f); err == nil {
		t.Error("flexFloat accepted a word")
	}
}

func TestIdentityPropertyThatIsNotAString(t *testing.T) {
	id := apiIdentity{Properties: map[string]json.RawMessage{"Level": json.RawMessage(`{"$type":"System.Int32","$value":5}`)}}
	if got := id.property("Level"); got != "5" {
		t.Errorf("property = %q", got)
	}
}

// ---- tls -------------------------------------------------------------------

// A platform with no system roots still gets the bundle on its own.
func TestABundleWithoutSystemRoots(t *testing.T) {
	orig := systemCertPool
	systemCertPool = func() (*x509.CertPool, error) { return nil, errors.New("no system roots") }
	t.Cleanup(func() { systemCertPool = orig })
	if _, err := LoadCABundle(writeCA(t)); err != nil {
		t.Errorf("err = %v", err)
	}
}

// ---- users -----------------------------------------------------------------

func TestUserNamesAndStates(t *testing.T) {
	f := &Fetcher{now: testNow}
	var e apiUserEntitlement
	e.User.MailAddress = "mail@fabrikam.com"
	e.User.DisplayName = "Mail"
	e.AccessLevel.Status = "none"
	u := f.toUser(e)
	if u.Name != "mail@fabrikam.com" || !u.Active || u.Licensed {
		t.Errorf("no principal name, status none: %+v", u)
	}
	e.User.MailAddress = ""
	if u := f.toUser(e); u.Name != "Mail" {
		t.Errorf("display name fallback = %q", u.Name)
	}
	for _, raw := range []string{"", "yesterday"} {
		if _, ok := parseTime(raw); ok {
			t.Errorf("parseTime(%q) succeeded", raw)
		}
	}
}

// ---- fetcher helpers -------------------------------------------------------

func TestDaysSince(t *testing.T) {
	f := &Fetcher{now: testNow}
	if got := f.daysSince(time.Time{}); got != -1 {
		t.Errorf("zero time = %d", got)
	}
	if got := f.daysSince(testNow.Add(time.Hour)); got != 0 {
		t.Errorf("a future time = %d, want fresh", got)
	}
}

func TestVisibilityLabel(t *testing.T) {
	for _, tc := range []struct {
		ps   projectState
		want string
	}{
		{projectState{}, ""},
		{projectState{visibilityKnown: true}, "private"},
		{projectState{visibilityKnown: true, public: true}, "public"},
	} {
		if got := visibilityLabel(&tc.ps); got != tc.want {
			t.Errorf("visibilityLabel(%+v) = %q, want %q", tc.ps, got, tc.want)
		}
	}
}

func TestParseTargetsSkipsBlanksAndDuplicates(t *testing.T) {
	got, err := parseTargets(FetchOptions{
		Projects:     []string{" ", "Fabrikam"},
		Repositories: []string{"", "Other/app", "other/APP"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.projects) != 2 || len(got.reposIn("other")) != 1 {
		t.Errorf("targets = %+v", got)
	}
}

// ---- policies --------------------------------------------------------------

func policyOf(t *testing.T, typeID string, blocking bool, settings string) policy {
	t.Helper()
	p, err := decodePolicy(apiPolicy{ID: 1, IsEnabled: true, IsBlocking: blocking, Type: apiPolicyType{ID: typeID}, Settings: json.RawMessage(settings)})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestPolicyNamesAndScopes(t *testing.T) {
	if got := policyOf(t, "0000-unknown", true, `{}`).typeName(); got != "0000-unknown" {
		t.Errorf("an unknown, unnamed type = %q", got)
	}
	if m, _, _ := matchScope(nil, repoMainID, "refs/heads/master"); m != scopeUnknown {
		t.Errorf("no scope = %v", m)
	}
	if m, _, _ := matchScope([]policyScope{{MatchKind: "Exact"}}, repoMainID, "refs/heads/master"); m != scopeUnknown {
		t.Errorf("an exact scope with no ref = %v", m)
	}
}

func TestPullRequestSettingsCorners(t *testing.T) {
	s := derivePullRequestSettings([]policy{
		// The author's vote counting on a policy needing nobody leaves no
		// independent reviewer, not minus one.
		policyOf(t, typeMinReviewers, true, `{"minimumApproverCount":0,"creatorVoteCounts":true}`),
		policyOf(t, typeWorkItemLinking, true, `{}`),
		// Optional required reviewers are still listed.
		policyOf(t, typeRequiredReviewers, false, `{"requiredReviewerIds":["x"]}`),
	})
	if s.RequiredApprovers != 0 || !s.WorkItemLinkingRequired || len(s.RequiredReviewers) != 1 || s.RequiredReviewers[0].Blocking {
		t.Errorf("settings = %+v", s)
	}
}

func TestChecksThatGateOnlySomePullRequests(t *testing.T) {
	if !checkConditional(policyOf(t, typeStatus, true, `{"statusName":"x","policyApplicability":1}`)) {
		t.Error("a status that applies only once posted is conditional")
	}
	if got := checkName(policyOf(t, typeStatus, true, `{"statusName":"lint"}`)); got != "lint" {
		t.Errorf("an ungenred status = %q", got)
	}
	if got := checkName(policyOf(t, typeBuild, true, `{"buildDefinitionId":7}`)); got != "build definition 7" {
		t.Errorf("an unnamed build = %q", got)
	}
}

// Policies read directly: a list that cannot be read, a setting that cannot
// be decoded, and a repository-wide list with an inactive policy in it.
func TestPolicyListsDirectly(t *testing.T) {
	bad := `{"count":1,"value":[{"id":9,"isEnabled":true,"type":{"id":"` + typeBuild + `"},"settings":"not an object"}]}`
	good := `{"count":2,"value":[` +
		`{"id":1,"isEnabled":true,"isBlocking":true,"type":{"id":"` + typeMinReviewers + `"},"settings":{"minimumApproverCount":1}},` +
		`{"id":2,"isEnabled":false,"isBlocking":true,"type":{"id":"` + typeMinReviewers + `"},"settings":{}}]}`
	serve := func(body string, status int) *Fetcher {
		c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
			if status != 200 {
				writeError(w, status, "TF400813: not authorized")
				return
			}
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, body)
		})
		return NewFetcher(c, config.Default())
	}
	ctx := context.Background()

	if _, err := serve("", 403).fetchProjectPolicies(ctx, projectID); err == nil {
		t.Error("project list: a 403 was read")
	}
	if _, err := serve(bad, 200).fetchProjectPolicies(ctx, projectID); err == nil || !strings.Contains(err.Error(), "policy 9 settings") {
		t.Errorf("project list: err = %v", err)
	}
	if _, err := serve("", 403).fetchBranchPolicies(ctx, projectID, repoMainID, "refs/heads/master", nil, false); err == nil {
		t.Error("branch list: a 403 was read")
	}
	if _, err := serve(bad, 200).fetchBranchPolicies(ctx, projectID, repoMainID, "refs/heads/master", nil, false); err == nil {
		t.Error("branch list: undecodable settings were read")
	}
	if _, err := serve("", 403).fetchRepositoryPolicies(ctx, projectID, repoMainID); err == nil {
		t.Error("repository list: a 403 was read")
	}
	if _, err := serve(bad, 200).fetchRepositoryPolicies(ctx, projectID, repoMainID); err == nil {
		t.Error("repository list: undecodable settings were read")
	}
	got, err := serve(good, 200).fetchRepositoryPolicies(ctx, projectID, repoMainID)
	if err != nil || len(got) != 1 || got[0].api.ID != 1 {
		t.Errorf("repository list = %+v, %v; want only the enabled policy", got, err)
	}
}
