package cli

import (
	"bytes"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/scm-bench/azure-devops-bench/internal/scm/azuredevops"
)

func get(path, scope string, status int) azuredevops.RequestEvent {
	return azuredevops.RequestEvent{
		Method: http.MethodGet, Path: path, Scope: scope,
		Status: status, Duration: 12 * time.Millisecond,
	}
}

// The closing line is the reason this exists: the operator handed over a token
// that can read every repository, and this is where they are told what it was
// used for.
func TestSummaryAccountsForEveryRequest(t *testing.T) {
	tr := newTracer(&bytes.Buffer{}, false, false)
	for i := 0; i < 59; i++ {
		tr.record(get("/fabrikam/_apis/projects", "", 200))
	}

	summary, _ := tr.summary()
	for _, want := range []string{"59 requests", "59 GET", "0 writes", "read-only"} {
		if !strings.Contains(summary, want) {
			t.Errorf("summary = %q, missing %q", summary, want)
		}
	}
	if !strings.HasPrefix(summary, "✓") {
		t.Errorf("summary = %q, want it to open with a tick", summary)
	}
}

// The count comes from the requests that were actually sent, not from the
// promise that they are all GET. If that ever stops being true, this is what
// says so — quietly reporting "read-only" anyway would be the worst outcome.
func TestSummaryFlagsANonReadRequest(t *testing.T) {
	tr := newTracer(&bytes.Buffer{}, false, false)
	tr.record(get("/fabrikam/_apis/projects", "", 200))
	tr.record(azuredevops.RequestEvent{Method: http.MethodPost, Path: "/fabrikam/_apis/projects", Status: 201})

	summary, _ := tr.summary()
	if strings.Contains(summary, "read-only") {
		t.Errorf("summary = %q, must not claim read-only after a POST", summary)
	}
	for _, want := range []string{"NOT READ-ONLY", "1 POST", "✗"} {
		if !strings.Contains(summary, want) {
			t.Errorf("summary = %q, missing %q", summary, want)
		}
	}
}

func TestSummaryIsEmptyWhenNothingWasSent(t *testing.T) {
	if s, _ := newTracer(&bytes.Buffer{}, false, false).summary(); s != "" {
		t.Errorf("summary = %q, want nothing when no request was made", s)
	}
}

func TestSummaryCountsRetries(t *testing.T) {
	tr := newTracer(&bytes.Buffer{}, false, false)
	tr.record(get("/fabrikam/_apis/projects", "", 500))
	e := get("/fabrikam/_apis/projects", "", 200)
	e.Attempt = 1
	tr.record(e)

	if s, _ := tr.summary(); !strings.Contains(s, "1 retried") {
		t.Errorf("summary = %q, want the retry counted", s)
	}
}

// Requests arrive interleaved across concurrent repositories, so a repository's
// requests are held and printed together once it finishes.
func TestRequestsAreGroupedByRepository(t *testing.T) {
	var buf bytes.Buffer
	tr := newTracer(&buf, false, true)

	pid := "6ce954b1-ce1f-45d1-b94d-e6bf2464ba2c"
	tr.record(get("/fabrikam/_apis/projects", "", 200))
	tr.record(get("/fabrikam/"+pid+"/_apis/git/repositories/278d5cd2-584d-4b63-824a-2ba458937249/refs", "PRJ/a", 200))
	tr.record(get("/fabrikam/"+pid+"/_apis/git/repositories/5febef5a-833d-4e14-b9c0-14cb638f91e6/refs", "PRJ/b", 200))
	tr.record(get("/fabrikam/"+pid+"/_apis/git/policy/configurations", "PRJ/a", 200))

	// Nothing repository-scoped has been printed yet.
	if strings.Contains(buf.String(), "PRJ/a") {
		t.Errorf("a repository was printed before it finished:\n%s", buf.String())
	}
	// The instance-level request has, since it has nothing to wait for.
	if !strings.Contains(buf.String(), "/projects") {
		t.Errorf("an unscoped request was withheld:\n%s", buf.String())
	}

	tr.repositoryDone("PRJ/a")
	out := buf.String()

	if !strings.Contains(out, "PRJ/a") {
		t.Errorf("the finished repository was not printed:\n%s", out)
	}
	if strings.Contains(out, "PRJ/b") {
		t.Errorf("an unfinished repository was printed:\n%s", out)
	}
	// Both of that repository's requests belong to the block.
	if !strings.Contains(out, "/{project}/git/repositories/278d5cd2…/refs") || !strings.Contains(out, "/{project}/git/policy/configurations") {
		t.Errorf("the group is missing requests:\n%s", out)
	}
}

// Accounting must happen whether or not anything is being displayed: the
// closing line is printed even when the request log is off.
func TestQuietTracerStillCounts(t *testing.T) {
	var buf bytes.Buffer
	tr := newTracer(&buf, false, false)

	tr.record(get("/fabrikam/p/_apis/git/repositories/r/refs", "PRJ/a", 200))
	tr.repositoryDone("PRJ/a")

	if buf.Len() != 0 {
		t.Errorf("a quiet tracer wrote %q", buf.String())
	}
	if s, _ := tr.summary(); !strings.Contains(s, "1 requests") {
		t.Errorf("summary = %q, want the request counted anyway", s)
	}
}

func TestShortenPath(t *testing.T) {
	pid := "6ce954b1-ce1f-45d1-b94d-e6bf2464ba2c"
	for _, tc := range []struct {
		event azuredevops.RequestEvent
		want  string
	}{
		{azuredevops.RequestEvent{Path: "/fabrikam/_apis/projects"}, "/projects"},
		{azuredevops.RequestEvent{Path: "/fabrikam/" + pid + "/_apis/git/repositories/278d5cd2-584d-4b63-824a-2ba458937249/stats/branches"},
			"/{project}/git/repositories/278d5cd2…/stats/branches"},
		{azuredevops.RequestEvent{Path: "/vssps.example/fabrikam/_apis/graph/Memberships/vssgp.X", Service: azuredevops.ServiceIdentity},
			"identity:/graph/Memberships/vssgp.X"},
		// A Server collection path two segments deep is not a project.
		{azuredevops.RequestEvent{Path: "/tfs/DefaultCollection/_apis/projects"}, "/projects"},
		{azuredevops.RequestEvent{Path: "/odd/path"}, "/odd/path"},
	} {
		if got := shortenPath(tc.event); got != tc.want {
			t.Errorf("shortenPath(%q) = %q, want %q", tc.event.Path, got, tc.want)
		}
	}
}

// record and repositoryDone are called from the fetch goroutines.
func TestTracerIsSafeForConcurrentUse(t *testing.T) {
	tr := newTracer(&bytes.Buffer{}, false, true)

	var wg sync.WaitGroup
	for i := range 20 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			scope := "PRJ/repo"
			tr.record(get("/fabrikam/p/_apis/git/repositories/r/refs", scope, 200))
			tr.repositoryDone(scope)
		}(i)
	}
	wg.Wait()

	if s, _ := tr.summary(); !strings.Contains(s, "20 requests") {
		t.Errorf("summary = %q, want all 20 counted", s)
	}
}

func TestFormatDuration(t *testing.T) {
	for d, want := range map[time.Duration]string{
		12 * time.Millisecond:   "12ms",
		1500 * time.Millisecond: "1.5s",
		2 * time.Second:         "2.0s",
	} {
		if got := formatDuration(d); got != want {
			t.Errorf("formatDuration(%v) = %q, want %q", d, got, want)
		}
	}
}

// Without the query, paging and batched lookups print as the same line over
// and over and read as the tool hammering one endpoint.
func TestQueryContextDistinguishesOtherwiseIdenticalRequests(t *testing.T) {
	for _, tc := range []struct {
		name  string
		query url.Values
		want  string
	}{
		{"no query", nil, ""},
		// api-version and $top ride on nearly every request.
		{"noise only", url.Values{"api-version": {"7.1"}, "$top": {"100"}}, ""},
		{"later page", url.Values{"api-version": {"7.1"}, "continuationToken": {"42"}}, "?continuationToken=42"},
		{"long token", url.Values{"continuationToken": {"abcdefghijklmnopqrstuvwxyz"}}, "?continuationToken=abcdefghijkl…"},
		// Descriptor lists can run to kilobytes; the count is what matters.
		{"descriptors", url.Values{"descriptors": {"a,b,c"}, "queryMembership": {"None"}}, "?descriptors=3"},
		{"acl token", url.Values{"token": {"repoV2/6ce954b1/278d5cd2/refs/heads/6d00/"}, "recurse": {"false"}}, "?recurse=false&token=repoV2(5)"},
	} {
		if got := queryContext(tc.query); got != tc.want {
			t.Errorf("%s: queryContext(%v) = %q, want %q", tc.name, tc.query, got, tc.want)
		}
	}
}

// Throttling is the one thing about pace an operator can act on, so the trace
// shows it.
func TestThrottlingIsShown(t *testing.T) {
	e := get("/fabrikam/_apis/projects", "", 200)
	e.RetryAfter = 7 * time.Second
	e.RateLimitRemaining = "12"
	line := newTracer(&bytes.Buffer{}, false, true).formatRequest(e, "")
	if !strings.Contains(line, "retry-after 7s") || !strings.Contains(line, "remaining 12") {
		t.Errorf("line = %q", line)
	}
}

// The path column is padded by hand so the dimmed query does not push the
// status and duration out of line. Colour must not change where they land.
func TestRequestColumnsLineUpWithAndWithoutColour(t *testing.T) {
	e := get("/fabrikam/_apis/projects", "", 200)
	e.Query = url.Values{"api-version": {"7.1"}, "continuationToken": {"100"}}

	plain := newTracer(&bytes.Buffer{}, false, true).formatRequest(e, "")
	coloured := newTracer(&bytes.Buffer{}, true, true).formatRequest(e, "")

	if !strings.Contains(plain, "?continuationToken=100") {
		t.Fatalf("the group is missing from the line: %q", plain)
	}
	if stripANSI(coloured) != plain {
		t.Errorf("colour changed the layout:\n plain    %q\n coloured %q", plain, stripANSI(coloured))
	}
}

func stripANSI(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		if s[i] == 0x1b {
			for i < len(s) && s[i] != 'm' {
				i++
			}
			i++
			continue
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}
