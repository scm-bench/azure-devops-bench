// Package azuredevops fetches a normalized snapshot from an Azure DevOps
// organization (Services) or collection (Server). It only ever issues GET
// requests: scanning must never be able to change the organization it is
// auditing.
package azuredevops

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// maxPages bounds pagination so a misbehaving server cannot loop forever.
const maxPages = 1000

// maxRetryAfter caps how long one Retry-After may stall the scan. Azure DevOps
// documents delays of up to thirty seconds; a server asking for an hour should
// surface as a slow scan with a log line, not as a hang.
const maxRetryAfter = 60 * time.Second

// Client is a read-only Azure DevOps REST client.
type Client struct {
	ep         Endpoint
	httpClient *http.Client

	// authHeader is the Authorization value. It never leaves the client: not
	// in errors, not in events, not in the snapshot.
	authHeader string
	authMethod string
	userAgent  string

	maxRetries int
	onRequest  func(RequestEvent)
	// Logf receives progress lines; nil discards them. Repositories are
	// fetched concurrently, so this must be safe for concurrent use.
	Logf func(format string, args ...any)
	// Warnf receives lines about what the scan could not see.
	Warnf func(format string, args ...any)

	transportWarnings []string

	versionMu  sync.RWMutex
	apiVersion string

	// gate holds every request back until notBefore. Azure DevOps sends
	// Retry-After on throttled answers that are still 200 OK — the request
	// succeeded, the identity is simply over budget — and the next request is
	// the one that must wait. Honouring it only on a 429 is honouring it
	// after the server has run out of patience.
	gateMu    sync.Mutex
	notBefore time.Time

	// sleep waits for d or until ctx ends. Tests replace it so a suite that
	// exercises throttling does not spend real seconds doing it.
	sleep func(ctx context.Context, d time.Duration) error
	now   func() time.Time
}

// RequestEvent describes one HTTP request the scan made.
//
// Method is carried rather than assumed. The tool only ever issues GET, and a
// test enforces that — but a caller showing an operator what a token was used
// for should be reporting what actually went out, not repeating the promise.
type RequestEvent struct {
	Method  string
	Service Service
	// Path is the URL path, below the service host.
	Path string
	// Scope names the repository this request belongs to, when it belongs to
	// one, so a trace can group requests that arrive interleaved.
	Scope    string
	Status   int
	Duration time.Duration
	Err      error
	// Attempt is 0 for the first try; higher values are retries.
	Attempt int
	Query   url.Values
	// RetryAfter is the delay the server asked for, when it asked.
	RetryAfter time.Duration
	// RateLimitRemaining is X-RateLimit-Remaining, when sent.
	RateLimitRemaining string
}

type scopeKey struct{}

func withScope(ctx context.Context, name string) context.Context {
	return context.WithValue(ctx, scopeKey{}, name)
}

func scopeFrom(ctx context.Context) string {
	name, _ := ctx.Value(scopeKey{}).(string)
	return name
}

// Options configures a Client.
type Options struct {
	// URL is the organization or collection URL.
	URL string
	// Token is a personal access token or a Microsoft Entra access token.
	Token string
	// Timeout bounds a single HTTP request. Zero uses 30s.
	Timeout time.Duration
	// Insecure disables TLS verification.
	Insecure bool
	// AllowPlaintext permits an http:// URL to a non-loopback host.
	AllowPlaintext bool
	// CAFile is a PEM bundle added to the system roots.
	CAFile string
	// MaxRetries bounds retries of 429/5xx responses. Zero uses 3.
	MaxRetries int
	// Concurrency sizes the idle connection pool.
	Concurrency int
	// ToolVersion goes into the User-Agent.
	ToolVersion string
	Logf        func(format string, args ...any)
	Warnf       func(format string, args ...any)
	OnRequest   func(RequestEvent)
	// Endpoint replaces the endpoints derived from URL. Tests use it to point
	// every service at one stand-in server; nothing else should.
	Endpoint *Endpoint
}

// jwtShape is three dot-separated base64url segments, the first two non-empty:
// what a Microsoft Entra access token looks like and a PAT never does.
var jwtShape = regexp.MustCompile(`^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$`)

// Authentication methods recorded in the snapshot. Never the credential.
const (
	AuthPAT   = "pat"
	AuthEntra = "entra"
)

// authorization picks the scheme from the token's shape.
//
// An Entra access token (az account get-access-token --resource
// 499b84ac-1321-427f-aa17-267ca6975798) goes out as a bearer token; anything
// else is a personal access token, which Azure DevOps takes as Basic
// credentials with an empty user name. One flag for both means a pipeline
// switching from a PAT to a workload identity changes a secret, not a command
// line — and no Azure SDK is needed to do it.
func authorization(token string) (header, method string) {
	if jwtShape.MatchString(token) {
		return "Bearer " + token, AuthEntra
	}
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(":"+token)), AuthPAT
}

// NewClient validates the options and returns a ready client.
func NewClient(opts Options) (*Client, error) {
	var (
		ep             Endpoint
		hadCredentials bool
		err            error
	)
	if opts.Endpoint != nil {
		ep = *opts.Endpoint
	} else {
		ep, hadCredentials, err = ParseOrganizationURL(opts.URL)
		if err != nil {
			return nil, err
		}
	}
	token := strings.TrimSpace(opts.Token)
	if token == "" {
		return nil, errors.New("a token is required: --token or AZURE_DEVOPS_TOKEN (a personal access token, or an Entra access token)")
	}

	for _, s := range []Service{ServiceCore, ServiceIdentity, ServiceEntitlements, ServiceAdvancedSecurity} {
		if u := ep.URL(s); u != nil {
			if err := checkTransport(u, opts.AllowPlaintext); err != nil {
				return nil, err
			}
		}
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	retries := opts.MaxRetries
	if retries <= 0 {
		retries = 3
	}

	// Cloned from the default when it is still the standard transport, and
	// built from scratch when it is not: any library in the process can
	// replace http.DefaultTransport, and a bare type assertion turns that into
	// a panic at startup. Either way the proxy comes from HTTPS_PROXY and
	// NO_PROXY, which is how an enterprise network routes this traffic.
	transport := &http.Transport{Proxy: http.ProxyFromEnvironment}
	if standard, ok := http.DefaultTransport.(*http.Transport); ok {
		transport = standard.Clone()
	}
	if opts.Concurrency > transport.MaxIdleConnsPerHost {
		transport.MaxIdleConnsPerHost = opts.Concurrency
	}
	if transport.MaxIdleConnsPerHost > transport.MaxIdleConns {
		transport.MaxIdleConns = transport.MaxIdleConnsPerHost
	}

	var warnings []string
	switch {
	case opts.Insecure:
		transport.TLSClientConfig = tlsInsecureConfig()
		warnings = append(warnings, fmt.Sprintf(
			"TLS certificate verification was disabled (scan.insecure) for %s; this scan could have been intercepted", ep.Core.Host))
	case opts.CAFile != "":
		pool, err := LoadCABundle(opts.CAFile)
		if err != nil {
			return nil, err
		}
		transport.TLSClientConfig = transportTLS(pool)
	}
	if ep.Core.Scheme == "http" && !isLoopback(ep.Core) {
		warnings = append(warnings, fmt.Sprintf(
			"credentials were sent in cleartext over http:// to %s (scan.allowPlaintext)", ep.Core.Host))
	}
	if hadCredentials {
		// Said out loud rather than dropped in silence: someone who put a
		// credential in the URL expected it to authenticate them.
		warnings = append(warnings, "credentials embedded in the organization URL were ignored and removed; authentication uses --token")
	}

	header, method := authorization(token)
	version := opts.ToolVersion
	if version == "" {
		version = "dev"
	}
	return &Client{
		ep: ep,
		httpClient: &http.Client{
			Timeout:   timeout,
			Transport: transport,
			// Never followed. A redirect from an Azure DevOps API is a sign-in
			// page (an unaccepted credential) or a misconfigured proxy, and
			// following it would hand the Authorization header to wherever it
			// points. The 3xx comes back to the caller as unreadable instead.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		authHeader:        header,
		authMethod:        method,
		userAgent:         "azure-devops-bench/" + version,
		maxRetries:        retries,
		onRequest:         opts.OnRequest,
		Logf:              opts.Logf,
		Warnf:             opts.Warnf,
		transportWarnings: warnings,
		apiVersion:        "7.1",
		sleep:             sleepContext,
		now:               time.Now,
	}, nil
}

// checkTransport refuses to put a credential on the wire in the clear.
//
// The token this tool asks for can read every repository in the organization,
// and with vso.security_manage it can rewrite their permissions. Sending it
// over http:// hands that to anyone on the path, and by the time a warning is
// printed the credential is already out. Loopback is exempt: that traffic does
// not leave the machine, and it keeps local test servers usable.
func checkTransport(u *url.URL, allowPlaintext bool) error {
	if u.Scheme != "http" || isLoopback(u) || allowPlaintext {
		return nil
	}
	return fmt.Errorf("refusing to send credentials in cleartext to %s\n"+
		"use https://, or set scan.allowPlaintext: true in the config if this network is genuinely trusted", u.Redacted())
}

// Endpoint returns where each service lives.
func (c *Client) Endpoint() Endpoint { return c.ep }

// BaseURL is the organization or collection URL, as stamped into reports.
func (c *Client) BaseURL() string { return c.ep.Core.String() }

// AuthMethod is "pat" or "entra".
func (c *Client) AuthMethod() string { return c.authMethod }

// TransportWarnings returns the protections this client was told to give up.
func (c *Client) TransportWarnings() []string {
	return append([]string(nil), c.transportWarnings...)
}

// APIVersion is the api-version the core APIs are called with.
func (c *Client) APIVersion() string {
	c.versionMu.RLock()
	defer c.versionMu.RUnlock()
	return c.apiVersion
}

func (c *Client) setAPIVersion(v string) {
	c.versionMu.Lock()
	c.apiVersion = v
	c.versionMu.Unlock()
}

func (c *Client) logf(format string, args ...any) {
	if c.Logf != nil {
		c.Logf(format, args...)
	}
}

func (c *Client) warnf(format string, args ...any) {
	if c.Warnf != nil {
		c.Warnf(format, args...)
		return
	}
	c.logf("warning: "+format, args...)
}

// errorKind separates the ways a GET can fail to produce data.
type errorKind int

const (
	// kindStatus is an ordinary 4xx/5xx answer.
	kindStatus errorKind = iota
	// kindSignIn is a 203 Non-Authoritative Information: Azure DevOps's
	// answer to a credential it did not accept is an HTML sign-in page with a
	// success status, which Microsoft's own SDK treats as success.
	kindSignIn
	// kindRedirect is a 3xx, never followed.
	kindRedirect
	// kindNotJSON is a 2xx whose body is not JSON: a proxy's error page, a
	// sign-in page served with 200.
	kindNotJSON
)

// APIError describes a GET that did not produce data.
type APIError struct {
	StatusCode int
	Service    Service
	Path       string
	Messages   []string
	// TypeKey is Azure DevOps's exception type, e.g. GitItemNotFoundException.
	TypeKey string
	kind    errorKind
	// detail explains a non-status failure in plain words.
	detail string
}

func (e *APIError) Error() string {
	msg := strings.Join(e.Messages, "; ")
	switch e.kind {
	case kindSignIn, kindRedirect, kindNotJSON:
		msg = e.detail
	}
	if msg == "" {
		msg = http.StatusText(e.StatusCode)
	}
	return fmt.Sprintf("GET %s: %d %s", e.Path, e.StatusCode, msg)
}

// tfCode extracts the TFnnnnnn error code Azure DevOps prefixes its messages
// with, or "".
var tfCodePattern = regexp.MustCompile(`\bTF\d{6}\b`)

func (e *APIError) tfCode() string {
	for _, m := range e.Messages {
		if code := tfCodePattern.FindString(m); code != "" {
			return code
		}
	}
	return ""
}

func asAPIError(err error) (*APIError, bool) {
	var apiErr *APIError
	ok := errors.As(err, &apiErr)
	return apiErr, ok
}

func hasStatus(err error, code int) bool {
	apiErr, ok := asAPIError(err)
	return ok && apiErr.kind == kindStatus && apiErr.StatusCode == code
}

// IsNotFound reports a 404.
func IsNotFound(err error) bool { return hasStatus(err, http.StatusNotFound) }

// IsUnauthorized reports a 401.
func IsUnauthorized(err error) bool { return hasStatus(err, http.StatusUnauthorized) }

// IsForbidden reports a 403.
func IsForbidden(err error) bool { return hasStatus(err, http.StatusForbidden) }

// isSignInLike reports the answers that mean "this credential was not
// accepted here": a 203 sign-in page, a redirect, a 2xx that is not JSON.
func isSignInLike(err error) bool {
	apiErr, ok := asAPIError(err)
	return ok && apiErr.kind != kindStatus
}

// isNoAccess404 reports Azure DevOps's 404 that conflates "does not exist" and
// "you may not see it" (TF401019 for Git, and its relatives). On a resource
// the scan already read, it means access, not absence.
func isNoAccess404(err error) bool {
	apiErr, ok := asAPIError(err)
	if !ok || apiErr.kind != kindStatus || apiErr.StatusCode != http.StatusNotFound {
		return false
	}
	switch apiErr.tfCode() {
	case "TF401019", "TF200016", "TF401175":
		return true
	}
	return false
}

// isAPIVersionError reports a 400/404 complaining about the api-version,
// which is how an older Azure DevOps Server refuses 7.1.
func isAPIVersionError(err error) bool {
	apiErr, ok := asAPIError(err)
	if !ok || apiErr.kind != kindStatus {
		return false
	}
	if apiErr.StatusCode != http.StatusBadRequest && apiErr.StatusCode != http.StatusNotFound {
		return false
	}
	// Azure DevOps Server answers "The requested REST API version of 7.1 is
	// out of range for this server" with VssVersionOutOfRangeException; older
	// builds word it as an invalid api-version.
	text := strings.ToLower(strings.Join(apiErr.Messages, " ") + " " + apiErr.TypeKey)
	return strings.Contains(text, "versionoutofrange") || strings.Contains(text, "api-version") ||
		(strings.Contains(text, "api version") && strings.Contains(text, "out of range"))
}

// response is a successful GET.
type response struct {
	body   []byte
	header http.Header
}

// get issues one GET, retrying throttled and transient answers, and returns
// the body of a 2xx JSON response. path is below the service's base URL and
// already escaped.
func (c *Client) get(ctx context.Context, svc Service, path string, query url.Values) (*response, error) {
	base := c.ep.URL(svc)
	if base == nil {
		return nil, fmt.Errorf("%s is not available on this deployment", svc)
	}
	endpoint, err := url.Parse(strings.TrimRight(base.String(), "/") + path)
	if err != nil {
		return nil, fmt.Errorf("build request for %s: %w", path, err)
	}
	if query != nil {
		endpoint.RawQuery = query.Encode()
	}

	var lastErr error
	for attempt := 0; attempt <= c.maxRetries; attempt++ {
		if attempt > 0 {
			delay := backoff(attempt)
			c.logf("retrying %s in %s (attempt %d/%d)", endpoint.Path, delay, attempt, c.maxRetries)
			if err := c.sleep(ctx, delay); err != nil {
				return nil, err
			}
		}
		if err := c.waitGate(ctx); err != nil {
			return nil, err
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
		if err != nil {
			return nil, fmt.Errorf("build request for %s: %w", endpoint.Path, err)
		}
		req.Header.Set("Authorization", c.authHeader)
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", c.userAgent)
		// Asks for a 401 instead of a sign-in redirect when the credential is
		// not accepted. Microsoft's own client sends it; without it a rejected
		// token can come back as a 203 HTML page that looks like success.
		req.Header.Set("X-TFS-FedAuthRedirect", "Suppress")

		started := time.Now()
		resp, err := c.httpClient.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			c.emit(ctx, req.Method, svc, endpoint, query, 0, time.Since(started), attempt, err, nil)
			lastErr = fmt.Errorf("GET %s: %w", endpoint.Path, err)
			continue
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
		resp.Body.Close()
		wait := c.noteRetryAfter(resp.Header)
		c.emit(ctx, req.Method, svc, endpoint, query, resp.StatusCode, time.Since(started), attempt, readErr, resp.Header)
		if readErr != nil {
			lastErr = fmt.Errorf("GET %s: read body: %w", endpoint.Path, readErr)
			continue
		}
		if wait > 0 {
			c.logf("%s asked for %s before the next request (Retry-After)", endpoint.Host, wait)
		}

		status := resp.StatusCode
		switch {
		case status == http.StatusNonAuthoritativeInfo:
			return nil, &APIError{StatusCode: status, Service: svc, Path: endpoint.Path, kind: kindSignIn,
				detail: "non-authoritative answer (an HTML sign-in page): the credential was not accepted for this request"}
		case status >= 200 && status < 300:
			if !isJSONContentType(resp.Header.Get("Content-Type")) {
				return nil, &APIError{StatusCode: status, Service: svc, Path: endpoint.Path, kind: kindNotJSON,
					detail: fmt.Sprintf("the answer was %s, not JSON (a sign-in or proxy page)", contentTypeLabel(resp.Header.Get("Content-Type")))}
			}
			return &response{body: body, header: resp.Header}, nil
		case status >= 300 && status < 400:
			return nil, &APIError{StatusCode: status, Service: svc, Path: endpoint.Path, kind: kindRedirect,
				detail: redirectDetail(endpoint, resp.Header.Get("Location"))}
		case status == http.StatusTooManyRequests || status >= 500:
			lastErr = newStatusError(svc, endpoint.Path, status, body)
			continue
		default:
			// Every other 4xx is deterministic: retrying cannot change it.
			return nil, newStatusError(svc, endpoint.Path, status, body)
		}
	}
	return nil, lastErr
}

func newStatusError(svc Service, path string, status int, body []byte) *APIError {
	msgs, typeKey := parseErrorBody(body)
	return &APIError{StatusCode: status, Service: svc, Path: path, Messages: msgs, TypeKey: typeKey}
}

// redirectDetail names where a redirect pointed, with any credential removed,
// and says so plainly when it pointed from https down to http — the one
// redirect that would have put the token on the wire in the clear.
func redirectDetail(from *url.URL, location string) string {
	if location == "" {
		return "a redirect with no destination (not followed)"
	}
	target, err := from.Parse(location)
	if err != nil {
		return "a redirect to an unparseable location (not followed)"
	}
	clean := redactURL(target.String())
	if from.Scheme == "https" && target.Scheme == "http" {
		return fmt.Sprintf("a redirect from %s down to cleartext %s (refused)", redactURL(from.String()), clean)
	}
	if strings.Contains(strings.ToLower(target.Host), "login.") || strings.Contains(strings.ToLower(target.Path), "signin") ||
		strings.Contains(strings.ToLower(target.Path), "_signin") {
		return fmt.Sprintf("a redirect to a sign-in page (%s): the credential was not accepted", clean)
	}
	return fmt.Sprintf("a redirect to %s (not followed)", clean)
}

func isJSONContentType(value string) bool {
	if value == "" {
		return false
	}
	media, _, err := mime.ParseMediaType(value)
	if err != nil {
		media = strings.ToLower(strings.TrimSpace(strings.SplitN(value, ";", 2)[0]))
	}
	return media == "application/json" || media == "text/json" || strings.HasSuffix(media, "+json")
}

func contentTypeLabel(value string) string {
	if value == "" {
		return "a body with no content type"
	}
	media, _, err := mime.ParseMediaType(value)
	if err != nil {
		return value
	}
	return media
}

// emit reports a completed request.
func (c *Client) emit(ctx context.Context, method string, svc Service, u *url.URL, query url.Values, status int, took time.Duration, attempt int, err error, header http.Header) {
	if c.onRequest == nil {
		return
	}
	e := RequestEvent{
		Method:   method,
		Service:  svc,
		Path:     u.Path,
		Scope:    scopeFrom(ctx),
		Status:   status,
		Duration: took,
		Err:      err,
		Attempt:  attempt,
		Query:    query,
	}
	if header != nil {
		e.RetryAfter, _ = parseRetryAfter(header.Get("Retry-After"), c.now())
		e.RateLimitRemaining = header.Get("X-RateLimit-Remaining")
	}
	c.onRequest(e)
}

// noteRetryAfter moves the gate forward when the server asked for a pause,
// whatever the status, and returns the pause.
func (c *Client) noteRetryAfter(header http.Header) time.Duration {
	wait, ok := parseRetryAfter(header.Get("Retry-After"), c.now())
	if !ok || wait <= 0 {
		return 0
	}
	if wait > maxRetryAfter {
		wait = maxRetryAfter
	}
	until := c.now().Add(wait)
	c.gateMu.Lock()
	if until.After(c.notBefore) {
		c.notBefore = until
	}
	c.gateMu.Unlock()
	return wait
}

// waitGate blocks until the most recent Retry-After has passed. Every
// goroutine waits on the same gate: the budget being protected is the
// identity's, not one request's.
func (c *Client) waitGate(ctx context.Context) error {
	c.gateMu.Lock()
	until := c.notBefore
	c.gateMu.Unlock()
	if wait := until.Sub(c.now()); wait > 0 {
		return c.sleep(ctx, wait)
	}
	return nil
}

// parseRetryAfter reads both forms RFC 9110 allows: delay-seconds and an
// HTTP-date.
func parseRetryAfter(value string, now time.Time) (time.Duration, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, false
	}
	if secs, err := strconv.ParseFloat(value, 64); err == nil {
		if secs < 0 {
			return 0, false
		}
		return time.Duration(secs * float64(time.Second)), true
	}
	if at, err := http.ParseTime(value); err == nil {
		if d := at.Sub(now); d > 0 {
			return d, true
		}
		return 0, true
	}
	return 0, false
}

func sleepContext(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// backoff grows exponentially, with jitter.
//
// The jitter is not decoration. A scan fetches repositories concurrently, so a
// throttled organization rejects a batch of requests at once; without jitter
// every one of them would sleep for exactly the same interval and retry in the
// same instant, reproducing the burst that caused the throttling.
func backoff(attempt int) time.Duration {
	// Clamped before the shift: `1 << (attempt-1)` overflows for a large
	// attempt count and a negative duration reaches rand.Int64N, which panics.
	const maxShift = 4 // 1<<4 seconds == the 16s ceiling
	shift := attempt - 1
	if shift > maxShift {
		shift = maxShift
	}
	if shift < 0 {
		shift = 0
	}
	d := time.Duration(1<<uint(shift)) * time.Second
	return d - time.Duration(rand.Int64N(int64(d/4)))
}

// parseErrorBody pulls the message out of Azure DevOps's error envelope,
// falling back to a truncated body when it is not JSON.
func parseErrorBody(body []byte) ([]string, string) {
	var envelope struct {
		Message string `json:"message"`
		TypeKey string `json:"typeKey"`
	}
	if err := json.Unmarshal(body, &envelope); err == nil && envelope.Message != "" {
		return []string{envelope.Message}, envelope.TypeKey
	}
	text := strings.TrimSpace(string(body))
	if text == "" {
		return nil, ""
	}
	if strings.HasPrefix(text, "<") {
		// An HTML error page says nothing a reader can use, and can be long.
		return []string{"an HTML page instead of an error message"}, ""
	}
	// Truncated by runes, not bytes, so a localized Azure DevOps Server
	// answering in Chinese is not cut mid-character on its way into the report.
	if runes := []rune(text); len(runes) > 200 {
		text = string(runes[:200]) + "..."
	}
	return []string{text}, ""
}

// pageOptions shapes how a collection endpoint is walked.
type pageOptions struct {
	// top is sent as $top on every page; 0 sends nothing.
	top int
	// fullPageNeedsToken treats a full page with no continuation token as an
	// error rather than the end. An endpoint that caps its page size without
	// saying how to continue would otherwise hand back its first page as
	// though it were everything — and a truncated branch list reads as fewer
	// stale branches, a truncated policy list as an unprotected branch.
	fullPageNeedsToken bool
	// skipFallback advances with $skip when a full page arrives without a
	// token, for the project list, which documents both mechanisms.
	skipFallback bool
}

// getAll walks every page of a collection endpoint, decoding each element into
// a fresh T. Continuation tokens are read from the X-MS-ContinuationToken
// header, where most of Azure DevOps puts them, and from a continuationToken
// field in the body, where the user-entitlement API does.
func getAll[T any](ctx context.Context, c *Client, svc Service, path string, query url.Values, opts pageOptions) ([]T, error) {
	var out []T
	token, previous := "", ""
	skip := 0
	for page := 0; page < maxPages; page++ {
		q := cloneValues(query)
		if opts.top > 0 {
			q.Set("$top", strconv.Itoa(opts.top))
		}
		if token != "" {
			q.Set("continuationToken", token)
		}
		if skip > 0 {
			q.Set("$skip", strconv.Itoa(skip))
		}
		resp, err := c.get(ctx, svc, path, q)
		if err != nil {
			return out, err
		}
		items, bodyToken, err := decodeCollection(resp.body)
		if err != nil {
			return out, fmt.Errorf("GET %s: %w", path, err)
		}
		for _, raw := range items {
			var item T
			if err := json.Unmarshal(raw, &item); err != nil {
				return out, fmt.Errorf("GET %s: decode item: %w", path, err)
			}
			out = append(out, item)
		}

		next := strings.TrimSpace(resp.header.Get("X-MS-ContinuationToken"))
		if next == "" {
			next = bodyToken
		}
		if next == "" {
			full := opts.top > 0 && len(items) >= opts.top
			switch {
			case full && opts.skipFallback:
				skip += len(items)
				continue
			case full && opts.fullPageNeedsToken:
				return out, fmt.Errorf("GET %s: a full page of %d arrived with no continuation token, so the rest cannot be reached", path, len(items))
			}
			return out, nil
		}
		if next == previous || next == token {
			// The same token twice is a server walking in a circle; reading
			// on would repeat items forever and present the duplicates as data.
			return out, fmt.Errorf("GET %s: the continuation token did not advance", path)
		}
		previous, token = token, next
		skip = 0
	}
	return out, fmt.Errorf("GET %s: exceeded %d pages", path, maxPages)
}

// decodeCollection accepts the shapes Azure DevOps wraps lists in: the usual
// {"count": n, "value": [...]}, the user-entitlement API's {"items": [...],
// "continuationToken": "..."}, and a bare array.
func decodeCollection(body []byte) ([]json.RawMessage, string, error) {
	trimmed := strings.TrimSpace(string(body))
	if strings.HasPrefix(trimmed, "[") {
		var items []json.RawMessage
		if err := json.Unmarshal(body, &items); err != nil {
			return nil, "", fmt.Errorf("decode response: %w", err)
		}
		return items, "", nil
	}
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, "", fmt.Errorf("decode response: %w", err)
	}
	token := decodeToken(envelope["continuationToken"])
	for _, key := range []string{"value", "items"} {
		raw, ok := envelope[key]
		if !ok {
			continue
		}
		if strings.TrimSpace(string(raw)) == "null" {
			// A null list next to a count of zero is an empty list said
			// clumsily; a null list with anything else is not a list.
			if count, ok := envelope["count"]; ok && strings.TrimSpace(string(count)) == "0" {
				return nil, token, nil
			}
			continue
		}
		var items []json.RawMessage
		if err := json.Unmarshal(raw, &items); err != nil {
			return nil, "", fmt.Errorf("decode response: %s is not a list: %w", key, err)
		}
		return items, token, nil
	}
	// No list at all is not an empty list. A response that has neither field
	// is a different API answering than the one asked, and reading it as
	// "nothing configured" is how a missing list becomes a passing control.
	return nil, "", errors.New("the response carries no value or items list")
}

// decodeToken reads a body continuation token, which is a string on most
// endpoints and a one-element array on a few.
func decodeToken(raw json.RawMessage) string {
	if len(raw) == 0 || string(raw) == "null" {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return strings.TrimSpace(s)
	}
	var list []string
	if err := json.Unmarshal(raw, &list); err == nil && len(list) > 0 {
		return strings.TrimSpace(list[0])
	}
	return ""
}

func cloneValues(in url.Values) url.Values {
	out := make(url.Values, len(in)+3)
	for k, v := range in {
		out[k] = append([]string(nil), v...)
	}
	return out
}

// getJSON issues one GET and decodes the body into out.
func (c *Client) getJSON(ctx context.Context, svc Service, path string, query url.Values, out any) error {
	resp, err := c.get(ctx, svc, path, query)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(resp.body, out); err != nil {
		return fmt.Errorf("GET %s: decode response: %w", path, err)
	}
	return nil
}
