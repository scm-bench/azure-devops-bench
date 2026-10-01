package azuredevops

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseOrganizationURL(t *testing.T) {
	for _, tc := range []struct {
		raw                       string
		deployment, org, core, id string
		entitlements, advsec      string
	}{
		{"https://dev.azure.com/fabrikam", "services", "fabrikam", "https://dev.azure.com/fabrikam",
			"https://vssps.dev.azure.com/fabrikam", "https://vsaex.dev.azure.com/fabrikam", "https://advsec.dev.azure.com/fabrikam"},
		{"dev.azure.com/fabrikam/", "services", "fabrikam", "https://dev.azure.com/fabrikam",
			"https://vssps.dev.azure.com/fabrikam", "https://vsaex.dev.azure.com/fabrikam", "https://advsec.dev.azure.com/fabrikam"},
		{"https://fabrikam.visualstudio.com", "services", "fabrikam", "https://fabrikam.visualstudio.com",
			"https://vssps.dev.azure.com/fabrikam", "https://vsaex.dev.azure.com/fabrikam", "https://advsec.dev.azure.com/fabrikam"},
		{"https://fabrikam.visualstudio.com/DefaultCollection", "services", "fabrikam", "https://fabrikam.visualstudio.com",
			"https://vssps.dev.azure.com/fabrikam", "https://vsaex.dev.azure.com/fabrikam", "https://advsec.dev.azure.com/fabrikam"},
		{"https://ado.corp.example/DefaultCollection", "server", "DefaultCollection", "https://ado.corp.example/DefaultCollection",
			"https://ado.corp.example/DefaultCollection", "", ""},
		{"https://ado.corp.example:8443/tfs/Finance/", "server", "Finance", "https://ado.corp.example:8443/tfs/Finance",
			"https://ado.corp.example:8443/tfs/Finance", "", ""},
	} {
		t.Run(tc.raw, func(t *testing.T) {
			ep, creds, err := ParseOrganizationURL(tc.raw)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if creds {
				t.Error("no credentials were in the URL")
			}
			str := func(u *url.URL) string {
				if u == nil {
					return ""
				}
				return u.String()
			}
			if ep.Deployment != tc.deployment || ep.Organization != tc.org || str(ep.Core) != tc.core || str(ep.Identity) != tc.id ||
				str(ep.Entitlements) != tc.entitlements || str(ep.AdvancedSecurity) != tc.advsec {
				t.Errorf("endpoint = %s %s core=%s id=%s ent=%s adv=%s", ep.Deployment, ep.Organization,
					str(ep.Core), str(ep.Identity), str(ep.Entitlements), str(ep.AdvancedSecurity))
			}
			if tc.deployment == "server" && (ep.Has(ServiceEntitlements) || ep.Has(ServiceAdvancedSecurity)) {
				t.Error("Server has no entitlements or Advanced Security")
			}
		})
	}
}

func TestParseOrganizationURLRefusesWhatItCannotScan(t *testing.T) {
	for _, tc := range []struct{ raw, want string }{
		{"", "required"},
		{"https://dev.azure.com", "names no organization"},
		// A project page pasted from the browser would scan the whole
		// organization while the user believed they had narrowed it.
		{"https://dev.azure.com/fabrikam/Fabrikam-Fiber", "--project Fabrikam-Fiber"},
		{"https://fabrikam.visualstudio.com/Fabrikam-Fiber", "--project Fabrikam-Fiber"},
		{"https://ado.corp.example", "names no collection"},
		{"ftp://dev.azure.com/fabrikam", "scheme"},
		{"https://user:pa ss@%zz", "invalid organization URL"},
	} {
		t.Run(tc.raw, func(t *testing.T) {
			_, _, err := ParseOrganizationURL(tc.raw)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

// A credential pasted into the URL is removed before the URL can reach the
// snapshot, the report or the SARIF, and the client says it ignored it.
func TestCredentialsInTheURLAreStrippedAndReported(t *testing.T) {
	c, err := NewClient(Options{URL: "https://user:secret-pat@dev.azure.com/fabrikam", Token: "pat"})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	if strings.Contains(c.BaseURL(), "secret-pat") || strings.Contains(c.BaseURL(), "user") {
		t.Errorf("base URL = %q", c.BaseURL())
	}
	if w := strings.Join(c.TransportWarnings(), " "); !strings.Contains(w, "ignored and removed") {
		t.Errorf("warnings = %v", c.TransportWarnings())
	}
}

func TestRedactURL(t *testing.T) {
	for raw, want := range map[string]string{
		"https://user:pass@dev.azure.com/org": "https://xxxxx@dev.azure.com/org",
		"https://pat@dev.azure.com/org":       "https://xxxxx@dev.azure.com/org",
		"https://dev.azure.com/org":           "https://dev.azure.com/org",
		"https://u:p@%zz/path":                "https://xxxxx@%zz/path",
		"no-scheme-at-all":                    "no-scheme-at-all",
	} {
		if got := redactURL(raw); got != want {
			t.Errorf("redactURL(%q) = %q, want %q", raw, got, want)
		}
	}
}

func TestATokenIsRequired(t *testing.T) {
	if _, err := NewClient(Options{URL: "https://dev.azure.com/fabrikam", Token: "  "}); err == nil || !strings.Contains(err.Error(), "AZURE_DEVOPS_TOKEN") {
		t.Errorf("err = %v", err)
	}
}

// The token can read every repository; http:// to anything but this machine
// is refused unless the config says the network is trusted.
func TestCleartextIsRefusedExceptOnLoopback(t *testing.T) {
	if _, err := NewClient(Options{URL: "http://ado.corp.example/DefaultCollection", Token: "pat"}); err == nil || !strings.Contains(err.Error(), "cleartext") {
		t.Errorf("err = %v", err)
	}
	if _, err := NewClient(Options{URL: "http://127.0.0.1:8080/DefaultCollection", Token: "pat"}); err != nil {
		t.Errorf("loopback refused: %v", err)
	}
	c, err := NewClient(Options{URL: "http://ado.corp.example/DefaultCollection", Token: "pat", AllowPlaintext: true})
	if err != nil {
		t.Fatalf("allowPlaintext refused: %v", err)
	}
	if w := strings.Join(c.TransportWarnings(), " "); !strings.Contains(w, "cleartext") {
		t.Errorf("warnings = %v", c.TransportWarnings())
	}
}

func TestInsecureIsRecordedAsAWarning(t *testing.T) {
	c, err := NewClient(Options{URL: "https://dev.azure.com/fabrikam", Token: "pat", Insecure: true})
	if err != nil {
		t.Fatal(err)
	}
	if w := strings.Join(c.TransportWarnings(), " "); !strings.Contains(w, "verification was disabled") {
		t.Errorf("warnings = %v", c.TransportWarnings())
	}
}

func writeCA(t *testing.T) string {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Corp Root"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "ca.pem")
	os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	return path
}

// caFile adds to the system roots; a file that is missing or holds no
// certificate is an error, not a bundle that silently added nothing.
func TestCABundle(t *testing.T) {
	if _, err := LoadCABundle(writeCA(t)); err != nil {
		t.Errorf("a valid bundle was refused: %v", err)
	}
	if _, err := LoadCABundle(filepath.Join(t.TempDir(), "missing.pem")); err == nil {
		t.Error("a missing bundle was accepted")
	}
	empty := filepath.Join(t.TempDir(), "empty.pem")
	os.WriteFile(empty, []byte("not a certificate"), 0o600)
	if _, err := LoadCABundle(empty); err == nil || !strings.Contains(err.Error(), "no PEM certificate") {
		t.Errorf("err = %v", err)
	}
	if _, err := NewClient(Options{URL: "https://dev.azure.com/fabrikam", Token: "pat", CAFile: empty}); err == nil {
		t.Error("a client was built over an unusable CA bundle")
	}
	if _, err := NewClient(Options{URL: "https://dev.azure.com/fabrikam", Token: "pat", CAFile: writeCA(t)}); err != nil {
		t.Errorf("client with a CA bundle: %v", err)
	}
}

func TestAuthorizationFollowsTheTokensShape(t *testing.T) {
	for token, wantScheme := range map[string]string{
		"eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln":              "Bearer",
		"eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0.":                   "Bearer",
		"52charsoflowercasebase32thatpatsusedtolooklikeabcdefgh": "Basic",
		"AZDO-new-format-pat-with-dashes_and_underscores":        "Basic",
		"one.two":   "Basic",
		"a..b":      "Basic",
		"x.y.z.w":   "Basic",
		"has space": "Basic",
	} {
		header, method := authorization(token)
		if !strings.HasPrefix(header, wantScheme+" ") {
			t.Errorf("%q → %q, want %s", token, header, wantScheme)
		}
		if (wantScheme == "Bearer") != (method == AuthEntra) {
			t.Errorf("%q method = %q", token, method)
		}
	}
}

func newTestClient(t *testing.T, h http.HandlerFunc) *Client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL + "/org")
	c, err := NewClient(Options{Endpoint: &Endpoint{Deployment: "services", Core: u, Identity: u}, Token: "pat", MaxRetries: 2})
	if err != nil {
		t.Fatal(err)
	}
	c.sleep = func(context.Context, time.Duration) error { return nil }
	return c
}

type item struct {
	ID int `json:"id"`
}

func TestGetAllFollowsTheHeaderToken(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("continuationToken") {
		case "":
			w.Header().Set("X-MS-ContinuationToken", "2")
			writeJSON(w, 200, map[string]any{"count": 2, "value": []any{map[string]any{"id": 0}, map[string]any{"id": 1}}})
		case "2":
			writeJSON(w, 200, map[string]any{"count": 1, "value": []any{map[string]any{"id": 2}}})
		}
	})
	got, err := getAll[item](context.Background(), c, ServiceCore, "/_apis/x", nil, pageOptions{})
	if err != nil || len(got) != 3 {
		t.Fatalf("got %v, %v", got, err)
	}
}

func TestGetAllFollowsTheBodyToken(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("continuationToken") == "" {
			writeJSON(w, 200, map[string]any{"items": []any{map[string]any{"id": 0}}, "continuationToken": "next"})
			return
		}
		writeJSON(w, 200, map[string]any{"items": []any{map[string]any{"id": 1}}, "continuationToken": nil})
	})
	got, err := getAll[item](context.Background(), c, ServiceCore, "/_apis/x", nil, pageOptions{})
	if err != nil || len(got) != 2 {
		t.Fatalf("got %v, %v", got, err)
	}
}

// A token that does not advance is a server walking in a circle.
func TestGetAllRefusesATokenThatDoesNotAdvance(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-MS-ContinuationToken", "same")
		writeJSON(w, 200, map[string]any{"count": 1, "value": []any{map[string]any{"id": 0}}})
	})
	if _, err := getAll[item](context.Background(), c, ServiceCore, "/_apis/x", nil, pageOptions{}); err == nil || !strings.Contains(err.Error(), "did not advance") {
		t.Errorf("err = %v", err)
	}
}

// A full page with no way to the next one is an error where it matters: a
// truncated policy list reads as an unprotected branch.
func TestGetAllRefusesAFullPageWithoutAToken(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, 200, map[string]any{"count": 2, "value": []any{map[string]any{"id": 0}, map[string]any{"id": 1}}})
	})
	if _, err := getAll[item](context.Background(), c, ServiceCore, "/_apis/x", nil, pageOptions{top: 2, fullPageNeedsToken: true}); err == nil || !strings.Contains(err.Error(), "full page") {
		t.Errorf("err = %v", err)
	}
}

// The project list also documents $skip; a full page with no token advances
// by it.
func TestGetAllFallsBackToSkip(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("$skip") {
		case "":
			writeJSON(w, 200, map[string]any{"count": 2, "value": []any{map[string]any{"id": 0}, map[string]any{"id": 1}}})
		case "2":
			writeJSON(w, 200, map[string]any{"count": 1, "value": []any{map[string]any{"id": 2}}})
		default:
			t.Errorf("unexpected $skip %q", r.URL.Query().Get("$skip"))
		}
	})
	got, err := getAll[item](context.Background(), c, ServiceCore, "/_apis/x", nil, pageOptions{top: 2, skipFallback: true})
	if err != nil || len(got) != 3 {
		t.Fatalf("got %v, %v", got, err)
	}
}

func TestDecodeCollection(t *testing.T) {
	for body, want := range map[string]int{
		`[{"id":1},{"id":2}]`:            2,
		`{"count":1,"value":[{"id":1}]}`: 1,
		`{"items":[{"id":1}]}`:           1,
		`{"count":0,"value":null}`:       0,
		`{"count":0,"value":[]}`:         0,
	} {
		items, _, err := decodeCollection([]byte(body))
		if err != nil || len(items) != want {
			t.Errorf("%s → %d items, %v; want %d", body, len(items), err, want)
		}
	}
	// No list at all is not an empty list.
	for _, body := range []string{`{"id":1}`, `{"count":3,"value":null}`, `{"value":"x"}`, `nope`} {
		if _, _, err := decodeCollection([]byte(body)); err == nil {
			t.Errorf("%s decoded as a list", body)
		}
	}
	if _, tok, _ := decodeCollection([]byte(`{"items":[],"continuationToken":["abc"]}`)); tok != "abc" {
		t.Errorf("array token = %q", tok)
	}
}

func TestServerErrorsAreRetriedThenReported(t *testing.T) {
	calls := 0
	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		calls++
		writeError(w, 503, "TF400898: An Internal Error Occurred.")
	})
	_, err := c.get(context.Background(), ServiceCore, "/_apis/x", nil)
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != 503 || calls != 3 {
		t.Errorf("err = %v after %d calls", err, calls)
	}
}

func TestTransportErrorsAreRetried(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	u, _ := url.Parse(srv.URL + "/org")
	srv.Close() // nothing listens any more
	c, _ := NewClient(Options{Endpoint: &Endpoint{Deployment: "services", Core: u, Identity: u}, Token: "pat", MaxRetries: 1})
	c.sleep = func(context.Context, time.Duration) error { return nil }
	var attempts []int
	c.onRequest = func(e RequestEvent) { attempts = append(attempts, e.Attempt) }
	if _, err := c.get(context.Background(), ServiceCore, "/_apis/x", nil); err == nil {
		t.Fatal("a dead server answered")
	}
	if len(attempts) != 2 {
		t.Errorf("attempts = %v", attempts)
	}
}

func TestAServiceTheDeploymentLacksIsAnError(t *testing.T) {
	c := newTestClient(t, func(http.ResponseWriter, *http.Request) {})
	if _, err := c.get(context.Background(), ServiceAdvancedSecurity, "/_apis/x", nil); err == nil {
		t.Error("a missing service was called")
	}
}

func TestRedirectDetail(t *testing.T) {
	from, _ := url.Parse("https://dev.azure.com/org/_apis/projects")
	if d := redirectDetail(from, "http://evil.example/collect"); !strings.Contains(d, "down to cleartext") {
		t.Errorf("downgrade = %q", d)
	}
	if d := redirectDetail(from, "https://login.microsoftonline.com/x"); !strings.Contains(d, "sign-in page") {
		t.Errorf("sign-in = %q", d)
	}
	if d := redirectDetail(from, "https://user:pw@other.example/x"); strings.Contains(d, "pw") || !strings.Contains(d, "not followed") {
		t.Errorf("other = %q", d)
	}
	if d := redirectDetail(from, ""); !strings.Contains(d, "no destination") {
		t.Errorf("empty = %q", d)
	}
	if d := redirectDetail(from, "%zz"); !strings.Contains(d, "unparseable") {
		t.Errorf("bad = %q", d)
	}
}

func TestParseRetryAfter(t *testing.T) {
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	if d, ok := parseRetryAfter("5", now); !ok || d != 5*time.Second {
		t.Errorf("seconds = %v %v", d, ok)
	}
	if d, ok := parseRetryAfter("0.5", now); !ok || d != 500*time.Millisecond {
		t.Errorf("fraction = %v %v", d, ok)
	}
	if d, ok := parseRetryAfter(now.Add(30*time.Second).Format(http.TimeFormat), now); !ok || d != 30*time.Second {
		t.Errorf("date = %v %v", d, ok)
	}
	if d, ok := parseRetryAfter(now.Add(-time.Minute).Format(http.TimeFormat), now); !ok || d != 0 {
		t.Errorf("past date = %v %v", d, ok)
	}
	for _, bad := range []string{"", "-3", "soon"} {
		if _, ok := parseRetryAfter(bad, now); ok {
			t.Errorf("%q accepted", bad)
		}
	}
}

// A Retry-After past the cap is honoured up to the cap, so a server asking
// for an hour slows the scan instead of hanging it.
func TestRetryAfterIsCapped(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {})
	h := http.Header{}
	h.Set("Retry-After", "3600")
	if got := c.noteRetryAfter(h); got != maxRetryAfter {
		t.Errorf("wait = %v, want the %v cap", got, maxRetryAfter)
	}
}

func TestBackoffGrowsAndStaysUnderTheCeiling(t *testing.T) {
	for attempt := 1; attempt <= 50; attempt++ {
		d := backoff(attempt)
		if d <= 0 || d > 16*time.Second {
			t.Errorf("backoff(%d) = %v", attempt, d)
		}
	}
	if backoff(0) <= 0 {
		t.Error("backoff(0) must still be positive")
	}
}

func TestJSONContentTypes(t *testing.T) {
	for ct, want := range map[string]bool{
		"application/json; charset=utf-8; api-version=7.1": true,
		"text/json":                true,
		"application/problem+json": true,
		"text/html; charset=utf-8": false,
		"":                         false,
		"application/json;;bad":    true,
	} {
		if got := isJSONContentType(ct); got != want {
			t.Errorf("isJSONContentType(%q) = %v", ct, got)
		}
	}
	if contentTypeLabel("") == "" || contentTypeLabel("text/html; charset=x") != "text/html" {
		t.Error("contentTypeLabel")
	}
}

func TestErrorClassification(t *testing.T) {
	notFound := &APIError{StatusCode: 404, Messages: []string{"TF401019: The Git repository with name or identifier x does not exist or you do not have permissions."}}
	if !isNoAccess404(notFound) || !IsNotFound(notFound) {
		t.Error("TF401019 is a 404 about access")
	}
	absent := &APIError{StatusCode: 404, Messages: []string{"TF401174: The item '/.github' could not be found."}}
	if isNoAccess404(absent) {
		t.Error("TF401174 is about the path")
	}
	signIn := &APIError{StatusCode: 203, kind: kindSignIn, detail: "sign-in page"}
	if !isSignInLike(signIn) || IsUnauthorized(signIn) || !strings.Contains(signIn.Error(), "sign-in page") {
		t.Error("a 203 is sign-in-like and not a status error")
	}
	wrapped := fmt.Errorf("context: %w", &APIError{StatusCode: 403})
	if !IsForbidden(wrapped) {
		t.Error("wrapped 403")
	}
	if (&APIError{StatusCode: 500, Path: "/x"}).Error() != "GET /x: 500 Internal Server Error" {
		t.Error("an empty message falls back to the status text")
	}
	if isAPIVersionError(&APIError{StatusCode: 400, Messages: []string{"TF400813: something else"}}) {
		t.Error("an unrelated 400 is not a version error")
	}
	if !isAPIVersionError(&APIError{StatusCode: 400, TypeKey: "VssVersionOutOfRangeException"}) {
		t.Error("VssVersionOutOfRangeException is a version error")
	}
}

func TestParseErrorBody(t *testing.T) {
	if msgs, key := parseErrorBody([]byte(`{"message":"TF401019: nope","typeKey":"GitRepositoryNotFoundException"}`)); msgs[0] != "TF401019: nope" || key != "GitRepositoryNotFoundException" {
		t.Errorf("envelope = %v %q", msgs, key)
	}
	if msgs, _ := parseErrorBody([]byte("<html>Sign in</html>")); !strings.Contains(msgs[0], "HTML") {
		t.Errorf("html = %v", msgs)
	}
	long := strings.Repeat("界", 300)
	if msgs, _ := parseErrorBody([]byte(long)); len([]rune(msgs[0])) != 203 {
		t.Errorf("truncated to %d runes", len([]rune(msgs[0])))
	}
	if msgs, _ := parseErrorBody(nil); msgs != nil {
		t.Errorf("empty = %v", msgs)
	}
}

func TestChunkKeepsQueriesShort(t *testing.T) {
	var many []string
	for i := 0; i < 400; i++ {
		many = append(many, fmt.Sprintf("Microsoft.IdentityModel.Claims.ClaimsIdentity;%s\\user%03d@fabrikam.com", tenant, i))
	}
	batches := chunk(many)
	if len(batches) < 2 {
		t.Fatalf("%d batches", len(batches))
	}
	total := 0
	for _, b := range batches {
		total += len(b)
		if n := len(url.QueryEscape(strings.Join(b, ","))); n > maxQueryLength+200 {
			t.Errorf("batch of %d bytes", n)
		}
	}
	if total != len(many) {
		t.Errorf("lost descriptors: %d of %d", total, len(many))
	}
}

// Branch tokens encode each segment as UTF-16LE hex, per Microsoft's
// "Git repo tokens for the security service".
func TestBranchTokenEncoding(t *testing.T) {
	if got := encodeTokenSegment("master"); got != "6d0061007300740065007200" {
		t.Errorf("master = %s", got)
	}
	got := branchToken("P", "R", "refs/heads/user/mattc/feature1")
	want := "repoV2/p/r/refs/heads/7500730065007200/6d006100740074006300/66006500610074007500720065003100/"
	if got != want {
		t.Errorf("token = %s, want %s", got, want)
	}
	if !tokenCovers("repoV2/p", got) || !tokenCovers("REPOV2/P/R", got) || tokenCovers("repoV2/p/r/refs/heads/7500", got) {
		t.Error("tokenCovers must follow whole segments, case-insensitively")
	}
}

func TestFlexibleDecoding(t *testing.T) {
	var s policySettings
	raw := `{"minimumApproverCount":"2","creatorVoteCounts":"true","validDuration":"720.0","policyApplicability":null,"scope":[{"repositoryId":null,"refName":"refs/heads/main","matchKind":"exact"}]}`
	if err := jsonUnmarshal(raw, &s); err != nil {
		t.Fatal(err)
	}
	if s.MinimumApproverCount != 2 || !s.CreatorVoteCounts || s.ValidDuration != 720 || s.PolicyApplicability != nil {
		t.Errorf("settings = %+v", s)
	}
	var d identityDescriptor
	if err := jsonUnmarshal(`{"identityType":"Microsoft.TeamFoundation.Identity","identifier":"S-1-9-1"}`, &d); err != nil || d != "Microsoft.TeamFoundation.Identity;S-1-9-1" {
		t.Errorf("object descriptor = %q %v", d, err)
	}
	if err := jsonUnmarshal(`null`, &d); err != nil || d != "" {
		t.Errorf("null descriptor = %q", d)
	}
	var v flexString
	if err := jsonUnmarshal(`2`, &v); err != nil || v != "2" {
		t.Errorf("numeric visibility = %q", v)
	}
	if pub, known := parseVisibility("2"); !pub || !known {
		t.Error("2 is public")
	}
	if _, known := parseVisibility("organization"); known {
		t.Error("an unrankable visibility is unknown")
	}
}

func jsonUnmarshal(raw string, out any) error { return json.Unmarshal([]byte(raw), out) }
