package azuredevops

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/scm-bench/azure-devops-bench/internal/scm"
)

// Service names one of the Azure DevOps hosts a scan talks to.
//
// Azure DevOps Services spreads its REST API across hosts: the core and Git
// APIs on dev.azure.com, identities and Graph on vssps, user entitlements on
// vsaex, Advanced Security on advsec. Azure DevOps Server answers the core and
// identity APIs on the collection URL and has no equivalent of the other two.
type Service int

const (
	// ServiceCore is projects, Git, policy and security.
	ServiceCore Service = iota
	// ServiceIdentity is IMS identities, and Graph on Services.
	ServiceIdentity
	// ServiceEntitlements is user entitlements (Services only).
	ServiceEntitlements
	// ServiceAdvancedSecurity is GitHub Advanced Security (Services only).
	ServiceAdvancedSecurity
)

func (s Service) String() string {
	switch s {
	case ServiceIdentity:
		return "identity"
	case ServiceEntitlements:
		return "entitlements"
	case ServiceAdvancedSecurity:
		return "advsec"
	default:
		return "core"
	}
}

// Endpoint is where each service of one organization or collection lives.
type Endpoint struct {
	// Deployment is scm.DeploymentServices or scm.DeploymentServer.
	Deployment string
	// Organization is the organization name on Services, the collection
	// name on Server. It is what group names are scoped by:
	// "[fabrikam]\Project Collection Administrators".
	Organization string
	// Core is the organization or collection URL, with no trailing slash.
	Core *url.URL
	// Identity hosts IMS (and Graph on Services).
	Identity *url.URL
	// Entitlements and AdvancedSecurity are nil on Server, where the APIs do
	// not exist.
	Entitlements     *url.URL
	AdvancedSecurity *url.URL
}

// URL returns the base URL of a service, or nil when this deployment does not
// have it.
func (e Endpoint) URL(s Service) *url.URL {
	switch s {
	case ServiceIdentity:
		return e.Identity
	case ServiceEntitlements:
		return e.Entitlements
	case ServiceAdvancedSecurity:
		return e.AdvancedSecurity
	default:
		return e.Core
	}
}

// Has reports whether this deployment offers the service at all.
func (e Endpoint) Has(s Service) bool { return e.URL(s) != nil }

// ParseOrganizationURL turns --url into the endpoints of every service.
//
// Three shapes are accepted, and the shape decides the deployment:
//
//	https://dev.azure.com/{org}         Services
//	https://{org}.visualstudio.com      Services (the legacy host)
//	https://{host}/{collection path}    Server
//
// Credentials embedded in the URL are stripped here and reported through
// hadCredentials, so the caller can say they were ignored. The URL is stamped
// into the snapshot, the report and the SARIF, and url.URL.String writes
// userinfo back out verbatim.
func ParseOrganizationURL(raw string) (ep Endpoint, hadCredentials bool, err error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return Endpoint{}, false, errors.New("an organization URL is required, e.g. https://dev.azure.com/fabrikam")
	}
	if !strings.Contains(raw, "://") {
		// A bare host is almost certainly meant as https.
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		// url.Error embeds the URL it failed on, credentials and all, so the
		// inner cause is unwrapped and the URL is redacted separately.
		reason := err
		var parseErr *url.Error
		if errors.As(err, &parseErr) {
			reason = parseErr.Err
		}
		return Endpoint{}, false, fmt.Errorf("invalid organization URL %q: %w", redactURL(raw), reason)
	}
	if u.Host == "" {
		return Endpoint{}, false, fmt.Errorf("invalid organization URL %q: no host", redactURL(raw))
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return Endpoint{}, false, fmt.Errorf("invalid organization URL %q: scheme must be https", redactURL(raw))
	}
	hadCredentials = u.User != nil
	u.User = nil
	u.RawQuery, u.Fragment, u.RawFragment = "", "", ""

	segments := pathSegments(u.Path)
	host := strings.ToLower(u.Hostname())

	switch {
	case host == "dev.azure.com":
		if len(segments) == 0 {
			return Endpoint{}, hadCredentials, fmt.Errorf("%s names no organization; use https://dev.azure.com/{organization}", u.Redacted())
		}
		if len(segments) > 1 {
			// https://dev.azure.com/fabrikam/Fabrikam-Fiber is a project page
			// pasted from a browser. Scanning the organization while the user
			// thought they had narrowed it to one project is the silent
			// widening the scoping flags exist to prevent.
			return Endpoint{}, hadCredentials, fmt.Errorf("%s points inside the organization; pass https://dev.azure.com/%s and narrow the scan with --project %s",
				u.Redacted(), segments[0], segments[1])
		}
		org := segments[0]
		return servicesEndpoint(org, u.Scheme), hadCredentials, nil

	case strings.HasSuffix(host, ".visualstudio.com"):
		org := strings.TrimSuffix(host, ".visualstudio.com")
		if org == "" || strings.Contains(org, ".") {
			return Endpoint{}, hadCredentials, fmt.Errorf("%s is not an organization URL; use https://{organization}.visualstudio.com or https://dev.azure.com/{organization}", u.Redacted())
		}
		if len(segments) > 0 && !strings.EqualFold(segments[0], "DefaultCollection") {
			return Endpoint{}, hadCredentials, fmt.Errorf("%s points inside the organization; pass https://%s and narrow the scan with --project %s",
				u.Redacted(), u.Host, segments[0])
		}
		ep := servicesEndpoint(org, u.Scheme)
		// The core APIs stay on the host the user named: an organization
		// reached through visualstudio.com may be allow-listed only there.
		ep.Core = &url.URL{Scheme: u.Scheme, Host: u.Host}
		return ep, hadCredentials, nil

	default:
		if len(segments) == 0 {
			return Endpoint{}, hadCredentials, fmt.Errorf("%s names no collection; Azure DevOps Server URLs look like https://%s/{collection} (or https://%s/tfs/{collection})",
				u.Redacted(), u.Host, u.Host)
		}
		collection := segments[len(segments)-1]
		base := &url.URL{Scheme: u.Scheme, Host: u.Host, Path: "/" + strings.Join(segments, "/")}
		return Endpoint{
			Deployment:   scm.DeploymentServer,
			Organization: collection,
			Core:         base,
			Identity:     base,
		}, hadCredentials, nil
	}
}

func servicesEndpoint(org, scheme string) Endpoint {
	host := func(sub string) *url.URL {
		return &url.URL{Scheme: scheme, Host: sub + "dev.azure.com", Path: "/" + org}
	}
	return Endpoint{
		Deployment:       scm.DeploymentServices,
		Organization:     org,
		Core:             host(""),
		Identity:         host("vssps."),
		Entitlements:     host("vsaex."),
		AdvancedSecurity: host("advsec."),
	}
}

func pathSegments(p string) []string {
	var out []string
	for _, s := range strings.Split(p, "/") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// redactURL renders a URL for an error message with any password removed.
//
// It takes a string rather than a *url.URL because the callers that need it
// most are on the path where parsing has already failed, and an unparseable
// URL is exactly as capable of carrying a credential as a valid one.
func redactURL(raw string) string {
	if u, err := url.Parse(raw); err == nil {
		if u.User != nil {
			// Redacted keeps a username, and on Azure DevOps a PAT is as
			// often pasted into the username slot as the password one.
			u.User = url.User("xxxxx")
		}
		return u.String()
	}
	start := 0
	if scheme := strings.Index(raw, "://"); scheme >= 0 {
		start = scheme + 3
	}
	authority := raw[start:]
	if end := strings.IndexAny(authority, "/?#"); end >= 0 {
		authority = authority[:end]
	}
	at := strings.LastIndex(authority, "@")
	if at < 0 {
		return raw
	}
	return raw[:start] + "xxxxx@" + raw[start+at+1:]
}

// isLoopback reports whether the host is this machine by name or literal
// address, without DNS: a name that merely resolves to 127.0.0.1 today is not
// a property a transport check can rely on.
func isLoopback(u *url.URL) bool {
	host := u.Hostname()
	if strings.EqualFold(host, "localhost") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}
