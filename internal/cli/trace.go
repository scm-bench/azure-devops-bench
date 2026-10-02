package cli

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/scm-bench/azure-devops-bench/internal/console"
	"github.com/scm-bench/azure-devops-bench/internal/scm/azuredevops"
)

// ANSI codes and the tag vocabulary come from internal/console, so the trace on
// stderr and the report on stdout stay one scheme. `azure-devops-bench scan 2>&1 | grep
// '^\[WARN\]'` only answers "what did this scan fail to see" if both streams
// use the same words.
const (
	ansiBold   = console.Bold
	ansiDim    = console.Dim
	ansiRed    = console.Red
	ansiGreen  = console.Green
	ansiYellow = console.Yellow
)

// tracer shows what the scan is actually doing, and accounts for it afterwards.
//
// The accounting is the point. This tool asks for a token that can read every
// repository in the organization — and, with vso.security_manage, a scope that
// could rewrite their permissions — and its central claim is that it only ever
// reads.
// That claim currently lives in the README and in a test — neither of which the
// person handing over the token is looking at. Printing each request as it goes
// out, and closing with a count of what was sent, turns the claim into
// something they can watch happen.
type tracer struct {
	out     io.Writer
	colour  bool
	verbose bool

	mu sync.Mutex
	// pending buffers each repository's requests until it finishes. The
	// requests themselves arrive interleaved — several repositories are in
	// flight at once — so grouping is only possible after the fact.
	pending map[string][]azuredevops.RequestEvent
	order   []string

	total    int
	byMethod map[string]int
	retries  int
}

func newTracer(out io.Writer, colour, verbose bool) *tracer {
	return &tracer{
		out:      out,
		colour:   colour,
		verbose:  verbose,
		pending:  map[string][]azuredevops.RequestEvent{},
		byMethod: map[string]int{},
	}
}

func (t *tracer) paint(code, s string) string {
	if !t.colour || s == "" {
		return s
	}
	return code + s + console.Reset
}

// tag renders the column-one tag every line printed here carries.
func (t *tracer) tag(g console.Tag) string {
	return console.Painter{Enabled: t.colour}.Render(g)
}

// record accounts for a request, and prints it when the scan is being shown.
// Requests that belong to a repository are held until that repository is done.
func (t *tracer) record(e azuredevops.RequestEvent) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.total++
	t.byMethod[e.Method]++
	if e.Attempt > 0 {
		t.retries++
	}
	if !t.verbose {
		return
	}
	if e.Scope == "" {
		// Instance and project requests have nothing to wait for.
		fmt.Fprintf(t.out, "%s %s\n", t.tag(console.Info), t.formatRequest(e, ""))
		return
	}
	if _, seen := t.pending[e.Scope]; !seen {
		t.order = append(t.order, e.Scope)
	}
	t.pending[e.Scope] = append(t.pending[e.Scope], e)
}

// repositoryDone flushes one repository's requests as a block.
func (t *tracer) repositoryDone(name string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	events := t.pending[name]
	delete(t.pending, name)
	for i, s := range t.order {
		if s == name {
			t.order = append(t.order[:i], t.order[i+1:]...)
			break
		}
	}
	if !t.verbose || len(events) == 0 {
		return
	}

	fmt.Fprintln(t.out)
	fmt.Fprintf(t.out, "%s   %s\n", t.tag(console.Info), t.paint(ansiBold, name))
	for _, e := range events {
		fmt.Fprintf(t.out, "%s %s\n", t.tag(console.Info), t.formatRequest(e, name))
	}
}

func (t *tracer) formatRequest(e azuredevops.RequestEvent, scope string) string {
	indent := "  "
	if scope != "" {
		indent = "    "
	}

	// Padded by hand for the same reason as the path below: %-4s on a coloured
	// string counts the escape bytes, so the method column silently lost its
	// padding whenever colour was on and every column after it shifted left.
	method := e.Method
	if method != http.MethodGet {
		// Anything that is not a read is the one thing worth shouting about.
		method = t.paint(ansiRed+ansiBold, method)
	} else {
		method = t.paint(ansiDim, method)
	}
	if n := 4 - utf8.RuneCountInString(e.Method); n > 0 {
		method += strings.Repeat(" ", n)
	}

	status := t.paint(ansiDim, "  -")
	switch {
	case e.Err != nil:
		status = t.paint(ansiRed, "err")
	case e.Status >= 500:
		status = t.paint(ansiRed, fmt.Sprintf("%3d", e.Status))
	case e.Status >= 400:
		// A 404 is ordinary here: it is how an absent add-on answers.
		status = t.paint(ansiYellow, fmt.Sprintf("%3d", e.Status))
	case e.Status > 0:
		status = t.paint(ansiGreen, fmt.Sprintf("%3d", e.Status))
	}

	// The path field is padded by hand because the query is dimmed: handing a
	// coloured string to %-52s pads against the escape bytes as well, and every
	// column after it stops lining up the moment colour is on.
	path := shortenPath(e)
	query := queryContext(e.Query)
	pad := ""
	if n := 52 - utf8.RuneCountInString(path+query); n > 0 {
		pad = strings.Repeat(" ", n)
	}
	field := path + t.paint(ansiDim, query) + pad

	line := fmt.Sprintf("%s%s %s %s %6s",
		indent, method, field, status, formatDuration(e.Duration))
	if e.Attempt > 0 {
		line += t.paint(ansiYellow, fmt.Sprintf("  retry %d", e.Attempt))
	}
	if e.RetryAfter > 0 {
		// Throttling is the one thing about pace an operator can act on:
		// a scan spending minutes asleep is waiting on Azure DevOps.
		line += t.paint(ansiYellow, fmt.Sprintf("  retry-after %s", e.RetryAfter))
	}
	if e.RateLimitRemaining != "" {
		line += t.paint(ansiDim, "  remaining "+e.RateLimitRemaining)
	}
	return line
}

// summary is the line the whole thing exists for: what was sent, and that none
// of it could have changed anything.
func (t *tracer) summary() (string, console.Tag) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.total == 0 {
		return "", console.Info
	}

	methods := make([]string, 0, len(t.byMethod))
	for m := range t.byMethod {
		methods = append(methods, m)
	}
	sort.Strings(methods)

	var parts []string
	writes := 0
	for _, m := range methods {
		parts = append(parts, fmt.Sprintf("%d %s", t.byMethod[m], m))
		if m != http.MethodGet {
			writes += t.byMethod[m]
		}
	}

	line := fmt.Sprintf("%d requests · %s", t.total, strings.Join(parts, " · "))
	if t.retries > 0 {
		line += fmt.Sprintf(" · %d retried", t.retries)
	}

	if writes > 0 {
		// Unreachable unless somebody adds a non-GET call. Saying so loudly
		// beats a silent contradiction of the tool's central promise.
		return t.paint(ansiRed+ansiBold, fmt.Sprintf("✗ %s · %d NOT READ-ONLY", line, writes)), console.Fail
	}
	return t.paint(ansiGreen, "✓ ") + t.paint(ansiDim, line+" · 0 writes · read-only"), console.Info
}

// queryContext renders the part of the query string that tells two otherwise
// identical requests apart.
//
// Not the whole query: api-version and $top are on nearly every request and
// distinguish nothing. Identity descriptor lists are reduced to a count — they
// can run to kilobytes, and the trace is about which requests went out, not
// whom they asked about.
func queryContext(q url.Values) string {
	if len(q) == 0 {
		return ""
	}
	keys := make([]string, 0, len(q))
	for k := range q {
		switch k {
		case "api-version", "$top", "queryMembership", "includeExtendedInfo", "includeAllProperties":
			continue
		}
		keys = append(keys, k)
	}
	if len(keys) == 0 {
		return ""
	}
	sort.Strings(keys)

	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		v := q.Get(k)
		switch k {
		case "descriptors", "subjectDescriptors":
			v = fmt.Sprintf("%d", len(strings.Split(v, ",")))
		case "continuationToken":
			if len(v) > 12 {
				v = v[:12] + "…"
			}
		case "token":
			// Security tokens embed GUIDs and hex-encoded branch names: the
			// depth says which level was asked about, which is what matters.
			v = fmt.Sprintf("%s(%d)", strings.SplitN(v, "/", 2)[0], strings.Count(strings.TrimSuffix(v, "/"), "/"))
		}
		parts = append(parts, k+"="+v)
	}
	return "?" + strings.Join(parts, "&")
}

// guidPattern matches the GUIDs that make Azure DevOps paths unreadable.
var guidPattern = regexp.MustCompile(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`)

// shortenPath drops what every request shares — the organization segment and
// "_apis" — and shortens GUIDs, so the interesting tail is what lines up.
func shortenPath(e azuredevops.RequestEvent) string {
	path := e.Path
	if i := strings.Index(path, "/_apis/"); i >= 0 {
		prefix := path[:i]
		path = path[i+len("/_apis"):]
		// A project-scoped call carries the project's ID between the
		// organization and _apis; keep that it was project-scoped, not the
		// GUID itself.
		segments := strings.Split(strings.Trim(prefix, "/"), "/")
		if last := segments[len(segments)-1]; guidPattern.MatchString(last) && len(last) == 36 {
			path = "/{project}" + path
		}
	}
	path = guidPattern.ReplaceAllStringFunc(path, func(g string) string { return g[:8] + "…" })
	if e.Service != azuredevops.ServiceCore {
		path = e.Service.String() + ":" + path
	}
	return path
}

func formatDuration(d time.Duration) string {
	switch {
	case d >= time.Second:
		return fmt.Sprintf("%.1fs", d.Seconds())
	default:
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
}
