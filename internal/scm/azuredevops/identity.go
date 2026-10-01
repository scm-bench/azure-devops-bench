package azuredevops

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"sync"

	"github.com/scm-bench/azure-devops-bench/internal/scm"
)

// principalKind is what an identity is, as far as a count is concerned.
type principalKind int

const (
	kindHuman principalKind = iota
	kindService
	// kindGroup is an Azure DevOps group, which the scan can expand.
	kindGroup
	// kindExternalGroup is a Microsoft Entra ID or Active Directory group.
	// Azure DevOps knows its members only partly — an Entra group's members
	// appear once they have signed in, and service principals never do — so
	// anything derived from one is a lower bound.
	kindExternalGroup
)

// principal is one resolved identity.
type principal struct {
	// Descriptor is the identity descriptor, "Type;Identifier": what access
	// control entries are keyed by.
	Descriptor string
	// Subject is the Graph subject descriptor ("vssgp.…", "aad.…").
	Subject string
	// Name is what reports print: an email-shaped account for people, the
	// scoped group name ("[fabrikam]\Project Collection Administrators") for
	// groups, the display name for service identities.
	Name   string
	Kind   principalKind
	Active bool
	// Everyone marks Project Collection Valid Users and Project Valid Users,
	// whose members are every member of the organization or project.
	Everyone bool
}

func (p *principal) isGroup() bool { return p.Kind == kindGroup || p.Kind == kindExternalGroup }

// descriptorKey normalizes a descriptor for use as a map key. Identity
// descriptors are compared case-insensitively by the security service.
func descriptorKey(d string) string { return strings.ToLower(strings.TrimSpace(d)) }

// subjectPrefixes classify a Graph subject descriptor by its prefix.
var (
	externalGroupPrefixes = map[string]bool{"aadgp": true, "wingp": true}
	adoGroupPrefixes      = map[string]bool{"vssgp": true}
	servicePrefixes       = map[string]bool{"svc": true, "s2s": true, "aadsp": true, "acs": true, "agent": true}
	humanPrefixes         = map[string]bool{"aad": true, "msa": true, "win": true, "imp": true, "bnd": true}
)

// serviceDescriptorTypes are identity descriptor types that belong to
// software rather than people: build services, service principals, managed
// identities.
var serviceDescriptorTypes = map[string]bool{
	"microsoft.teamfoundation.serviceidentity":                   true,
	"microsoft.visualstudio.services.claims.aadserviceprincipal": true,
	"microsoft.teamfoundation.aggregateidentity":                 true,
}

func subjectPrefix(subject string) string {
	prefix, _, ok := strings.Cut(subject, ".")
	if !ok {
		return ""
	}
	return strings.ToLower(prefix)
}

func descriptorType(descriptor string) string {
	typ, _, _ := strings.Cut(descriptor, ";")
	return strings.ToLower(strings.TrimSpace(typ))
}

// newPrincipal classifies an IMS identity.
func newPrincipal(id apiIdentity) *principal {
	p := &principal{
		Descriptor: string(id.Descriptor),
		Subject:    id.SubjectDescriptor,
		Active:     id.IsActive,
	}
	prefix := subjectPrefix(id.SubjectDescriptor)
	typ := descriptorType(p.Descriptor)
	account := id.property("Account")
	display := id.ProviderDisplayName
	if id.CustomDisplayName != "" {
		display = id.CustomDisplayName
	}

	group := id.IsContainer || strings.EqualFold(id.property("SchemaClassName"), "Group")
	switch {
	case group && externalGroupPrefixes[prefix]:
		p.Kind = kindExternalGroup
	case group && typ == "system.security.principal.windowsidentity":
		// An Active Directory group on Azure DevOps Server: synchronized
		// periodically, never authoritatively.
		p.Kind = kindExternalGroup
	case group:
		p.Kind = kindGroup
	case servicePrefixes[prefix] || serviceDescriptorTypes[typ]:
		p.Kind = kindService
	default:
		p.Kind = kindHuman
	}

	switch {
	case p.isGroup():
		p.Name = display
		if p.Name == "" {
			p.Name = account
		}
		special := id.property("SpecialType")
		if strings.EqualFold(special, "EveryoneApplicationGroup") ||
			strings.EqualFold(account, "Project Valid Users") ||
			strings.EqualFold(account, "Project Collection Valid Users") ||
			strings.HasSuffix(display, `\Project Valid Users`) ||
			strings.HasSuffix(display, `\Project Collection Valid Users`) {
			p.Everyone = true
		}
	case p.Kind == kindService:
		p.Name = display
		if p.Name == "" {
			p.Name = account
		}
	default:
		// People are named by the account they sign in with, which is unique
		// and is what an allowlist or a directory lookup will use.
		switch {
		case strings.Contains(account, "@"):
			p.Name = account
		case id.property("Mail") != "":
			p.Name = id.property("Mail")
		case account != "" && id.property("Domain") != "" && typ == "system.security.principal.windowsidentity":
			p.Name = id.property("Domain") + `\` + account
		case account != "":
			p.Name = account
		default:
			p.Name = display
		}
	}
	if p.Name == "" {
		p.Name = p.Descriptor
	}
	return p
}

// directory resolves and expands identities, caching both: the same handful of
// groups (Contributors, Project Administrators, the build service) stand on
// every repository in a project, and resolving them once per repository is
// the single most repeated work in a large scan.
type directory struct {
	f *Fetcher

	mu         sync.Mutex
	byDesc     map[string]*principal
	bySubject  map[string]*principal
	failed     map[string]bool
	expansions map[string]*pset
}

func newDirectory(f *Fetcher) *directory {
	return &directory{
		f:          f,
		byDesc:     map[string]*principal{},
		bySubject:  map[string]*principal{},
		failed:     map[string]bool{},
		expansions: map[string]*pset{},
	}
}

func (d *directory) remember(p *principal) {
	d.byDesc[descriptorKey(p.Descriptor)] = p
	if p.Subject != "" {
		d.bySubject[strings.ToLower(p.Subject)] = p
	}
}

// maxQueryLength bounds the comma-joined descriptors in one request. IMS
// takes them in the query string, and a URL past roughly eight kilobytes is
// refused by proxies before Azure DevOps sees it.
const maxQueryLength = 6000

// chunk splits values so each comma-joined group stays under maxQueryLength.
func chunk(values []string) [][]string {
	var out [][]string
	var cur []string
	size := 0
	for _, v := range values {
		n := len(url.QueryEscape(v)) + 3
		if len(cur) > 0 && size+n > maxQueryLength {
			out = append(out, cur)
			cur, size = nil, 0
		}
		cur = append(cur, v)
		size += n
	}
	if len(cur) > 0 {
		out = append(out, cur)
	}
	return out
}

// resolve returns the principal behind each identity descriptor. Descriptors
// that could not be resolved are absent from the map; the caller decides
// whether that matters.
func (d *directory) resolve(ctx context.Context, descriptors []string) map[string]*principal {
	return d.lookup(ctx, "descriptors", descriptors)
}

// resolveSubjects is resolve keyed by Graph subject descriptors.
func (d *directory) resolveSubjects(ctx context.Context, subjects []string) map[string]*principal {
	return d.lookup(ctx, "subjectDescriptors", subjects)
}

func (d *directory) lookup(ctx context.Context, param string, keys []string) map[string]*principal {
	out := map[string]*principal{}
	var missing []string
	seen := map[string]bool{}

	d.mu.Lock()
	for _, k := range keys {
		lk := strings.ToLower(strings.TrimSpace(k))
		if lk == "" || seen[lk] {
			continue
		}
		seen[lk] = true
		cache := d.byDesc
		if param == "subjectDescriptors" {
			cache = d.bySubject
		}
		if p, ok := cache[lk]; ok {
			out[lk] = p
			continue
		}
		if d.failed[param+":"+lk] {
			continue
		}
		missing = append(missing, strings.TrimSpace(k))
	}
	d.mu.Unlock()

	for _, batch := range chunk(missing) {
		query := url.Values{
			param:             []string{strings.Join(batch, ",")},
			"queryMembership": []string{"None"},
			"api-version":     []string{d.f.client.APIVersion()},
		}
		identities, err := getAll[*apiIdentity](ctx, d.f.client, ServiceIdentity, "/_apis/identities", query, pageOptions{})
		d.mu.Lock()
		if err != nil {
			for _, k := range batch {
				d.failed[param+":"+strings.ToLower(k)] = true
			}
			d.mu.Unlock()
			d.f.identityProblem(err)
			continue
		}
		for _, id := range identities {
			// IMS answers an unknown descriptor with null in its place.
			if id == nil || id.Descriptor == "" {
				continue
			}
			p := newPrincipal(*id)
			d.remember(p)
		}
		for _, k := range batch {
			lk := strings.ToLower(k)
			cache := d.byDesc
			if param == "subjectDescriptors" {
				cache = d.bySubject
			}
			if p, ok := cache[lk]; ok {
				out[lk] = p
			} else {
				d.failed[param+":"+lk] = true
			}
		}
		d.mu.Unlock()
	}
	return out
}

// findCollectionGroup finds a collection-level group by name, such as
// Project Collection Administrators, through an IMS search — a GET that both
// Services and Server answer, unlike Graph.
func (d *directory) findCollectionGroup(ctx context.Context, name string) (*principal, error) {
	query := url.Values{
		"searchFilter":    []string{"General"},
		"filterValue":     []string{name},
		"queryMembership": []string{"None"},
		"api-version":     []string{d.f.client.APIVersion()},
	}
	identities, err := getAll[*apiIdentity](ctx, d.f.client, ServiceIdentity, "/_apis/identities", query, pageOptions{})
	if err != nil {
		return nil, err
	}
	var matches []*principal
	for _, id := range identities {
		if id == nil || !id.IsContainer {
			continue
		}
		account := id.property("Account")
		if !strings.EqualFold(account, name) && !strings.HasSuffix(strings.ToLower(id.ProviderDisplayName), `\`+strings.ToLower(name)) {
			continue
		}
		// A project can have a group by the same name; the collection's own
		// is the one not scoped to a team project.
		if strings.EqualFold(id.property("ScopeType"), "TeamProject") {
			continue
		}
		matches = append(matches, newPrincipal(*id))
	}
	if len(matches) != 1 {
		return nil, fmt.Errorf("an identity search for %q found %d collection-level groups, expected exactly one", name, len(matches))
	}
	d.mu.Lock()
	d.remember(matches[0])
	d.mu.Unlock()
	return matches[0], nil
}

// pset is a resolved principal set: people, service identities and the
// groups behind them, plus whether it is all of them.
type pset struct {
	humans   map[string]*principal
	services map[string]*principal
	groups   map[string]*principal
	complete bool
	everyone bool
}

func newPset() *pset {
	return &pset{
		humans:   map[string]*principal{},
		services: map[string]*principal{},
		groups:   map[string]*principal{},
		complete: true,
	}
}

func (s *pset) add(p *principal) {
	k := descriptorKey(p.Descriptor)
	switch p.Kind {
	case kindHuman:
		s.humans[k] = p
	case kindService:
		s.services[k] = p
	default:
		s.groups[k] = p
		if p.Everyone {
			s.everyone = true
		}
	}
}

func (s *pset) merge(o *pset) {
	for k, p := range o.humans {
		s.humans[k] = p
	}
	for k, p := range o.services {
		s.services[k] = p
	}
	for k, p := range o.groups {
		s.groups[k] = p
	}
	s.complete = s.complete && o.complete
	s.everyone = s.everyone || o.everyone
}

func (s *pset) empty() bool { return len(s.humans) == 0 && len(s.services) == 0 && !s.everyone }

// intersect is who is in both sets — a person who holds ForcePush through one
// group and "Bypass policies when pushing" through another holds both.
//
// Completeness follows the same reasoning bitbucket-bench applies across
// restrictions: a complete, empty side settles the intersection on its own,
// whatever the other side could not see; otherwise both sides must be
// complete.
func intersect(a, b *pset) *pset {
	out := newPset()
	switch {
	case a.everyone && b.everyone:
		out.everyone = true
		for k, p := range a.groups {
			out.groups[k] = p
		}
	case a.everyone:
		for k, p := range b.humans {
			out.humans[k] = p
		}
		for k, p := range b.services {
			out.services[k] = p
		}
		for k, p := range b.groups {
			out.groups[k] = p
		}
	case b.everyone:
		return intersect(b, a)
	default:
		for k, p := range a.humans {
			if _, ok := b.humans[k]; ok {
				out.humans[k] = p
			}
		}
		for k, p := range a.services {
			if _, ok := b.services[k]; ok {
				out.services[k] = p
			}
		}
		for k, p := range a.groups {
			if _, ok := b.groups[k]; ok {
				out.groups[k] = p
			}
		}
	}
	out.complete = (a.complete && b.complete) || (a.complete && a.empty()) || (b.complete && b.empty())
	return out
}

// subtract removes b's people and service identities from a. Whether the
// result is exact depends on b being complete, which the caller tracks: a
// subtraction of a partial set leaves people in who should have been taken
// out.
func subtract(a, b *pset) *pset {
	out := newPset()
	for k, p := range a.humans {
		if _, ok := b.humans[k]; !ok {
			out.humans[k] = p
		}
	}
	for k, p := range a.services {
		if _, ok := b.services[k]; !ok {
			out.services[k] = p
		}
	}
	for k, p := range a.groups {
		if _, ok := b.groups[k]; !ok {
			out.groups[k] = p
		}
	}
	out.complete = a.complete
	out.everyone = a.everyone
	return out
}

// effective renders a set for the snapshot.
func (s *pset) effective() scm.EffectivePrincipals {
	out := scm.EffectivePrincipals{Complete: s.complete, Everyone: s.everyone}
	for _, p := range s.humans {
		out.Users = append(out.Users, p.Name)
	}
	for _, p := range s.services {
		out.ServiceIdentities = append(out.ServiceIdentities, p.Name)
	}
	for _, p := range s.groups {
		out.Groups = append(out.Groups, p.Name)
	}
	out.Users = uniqueSorted(out.Users)
	out.ServiceIdentities = uniqueSorted(out.ServiceIdentities)
	out.Groups = uniqueSorted(out.Groups)
	out.Count = len(out.Users)
	return out
}

func uniqueSorted(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	sort.Strings(in)
	out := in[:0]
	for i, v := range in {
		if i == 0 || v != in[i-1] {
			out = append(out, v)
		}
	}
	return out
}

// expand returns everyone a group reaches, memoized per group.
//
// An everyone group (Project Valid Users, Project Collection Valid Users) is
// not expanded: its members are every member of the organization or project,
// listing them would mean enumerating the directory, and the answer a rule
// needs — "everyone" — is already known.
func (d *directory) expand(ctx context.Context, g *principal) *pset {
	key := descriptorKey(g.Descriptor)
	d.mu.Lock()
	if cached, ok := d.expansions[key]; ok {
		d.mu.Unlock()
		return cached
	}
	d.mu.Unlock()

	var result *pset
	switch {
	case g.Everyone:
		result = newPset()
		result.add(g)
	case d.f.client.Endpoint().Deployment == scm.DeploymentServer:
		result = d.expandIMS(ctx, g)
	default:
		result = d.expandGraph(ctx, g)
	}

	d.mu.Lock()
	d.expansions[key] = result
	d.mu.Unlock()
	return result
}

// maxGroupDepth bounds nested group traversal. Azure DevOps allows cycles in
// principle and deep nesting in practice; neither may hang a scan.
const maxGroupDepth = 32

// expandGraph walks a group's memberships through Graph, one level per call —
// Graph's Memberships API answers only depth 1 — and resolves each member
// through IMS to learn what it is.
func (d *directory) expandGraph(ctx context.Context, g *principal) *pset {
	out := newPset()
	out.groups[descriptorKey(g.Descriptor)] = g
	if g.Kind == kindExternalGroup {
		out.complete = false
	}
	if g.Subject == "" {
		out.complete = false
		d.f.warn("group %q has no Graph subject descriptor, so its members could not be listed; counts derived from it are lower bounds", g.Name)
		return out
	}

	visited := map[string]bool{strings.ToLower(g.Subject): true}
	level := []*principal{g}
	for depth := 0; len(level) > 0; depth++ {
		if depth >= maxGroupDepth {
			out.complete = false
			d.f.warn("group %q nests more than %d levels deep; its expansion stops there and counts derived from it are lower bounds", g.Name, maxGroupDepth)
			break
		}
		var next []*principal
		for _, container := range level {
			members, ok := d.graphMembers(ctx, container)
			if !ok {
				out.complete = false
				continue
			}
			for _, m := range members {
				if m.Kind != kindHuman && m.Kind != kindService {
					key := strings.ToLower(m.Subject)
					if key == "" {
						key = descriptorKey(m.Descriptor)
					}
					out.groups[descriptorKey(m.Descriptor)] = m
					if m.Everyone {
						out.everyone = true
						continue
					}
					if m.Kind == kindExternalGroup {
						// Its visible members still count — they are real
						// members — but they are not all of them.
						out.complete = false
					}
					if !visited[key] {
						visited[key] = true
						next = append(next, m)
					}
					continue
				}
				if !m.Active {
					// Deactivated accounts are never counted: an identity
					// with no membership left in the organization cannot
					// sign in to use what it was granted.
					continue
				}
				out.add(m)
			}
		}
		level = next
	}
	return out
}

// graphMembers lists a group's direct members and resolves them.
func (d *directory) graphMembers(ctx context.Context, g *principal) ([]*principal, bool) {
	query := url.Values{
		"direction":   []string{"down"},
		"api-version": []string{"7.1-preview.1"},
	}
	memberships, err := getAll[apiMembership](ctx, d.f.client, ServiceIdentity,
		"/_apis/graph/Memberships/"+url.PathEscape(g.Subject), query, pageOptions{})
	if err != nil {
		d.f.warn("group %q could not be expanded (%v); counts derived from it are lower bounds", g.Name, err)
		return nil, false
	}

	var subjects, descriptors []string
	for _, m := range memberships {
		if strings.EqualFold(m.MemberDescriptor, g.Subject) {
			continue
		}
		member := strings.TrimSpace(m.MemberDescriptor)
		if member == "" {
			continue
		}
		if subjectPrefix(member) != "" {
			subjects = append(subjects, member)
			continue
		}
		// Microsoft's published samples show bare base64 identity
		// descriptors here rather than prefixed subject descriptors. Real
		// organizations answer with the prefixed form, but a decoder that
		// accepted only that would read the documented shape as "no
		// members" — an empty group, a lower count, a wrong verdict.
		if decoded, ok := decodeBareDescriptor(member); ok {
			descriptors = append(descriptors, decoded)
			continue
		}
		subjects = append(subjects, member)
	}

	complete := true
	var out []*principal
	if len(subjects) > 0 {
		resolved := d.resolveSubjects(ctx, subjects)
		for _, s := range subjects {
			if p, ok := resolved[strings.ToLower(s)]; ok {
				out = append(out, p)
			} else {
				complete = false
			}
		}
	}
	if len(descriptors) > 0 {
		resolved := d.resolve(ctx, descriptors)
		for _, s := range descriptors {
			if p, ok := resolved[descriptorKey(s)]; ok {
				out = append(out, p)
			} else {
				complete = false
			}
		}
	}
	if !complete {
		d.f.warn("some members of group %q could not be resolved; counts derived from it are lower bounds", g.Name)
	}
	return out, complete
}

// decodeBareDescriptor reads a base64 identity descriptor ("Type;Identifier")
// with no subject-descriptor prefix.
func decodeBareDescriptor(s string) (string, bool) {
	for _, enc := range []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.StdEncoding} {
		raw, err := enc.DecodeString(s)
		if err != nil {
			continue
		}
		text := string(raw)
		if typ, id, ok := strings.Cut(text, ";"); ok && typ != "" && id != "" && strings.Contains(typ, ".") {
			return text, true
		}
	}
	return "", false
}

// expandIMS asks IMS for a group's transitive members in one call — the only
// expansion Azure DevOps Server offers, since Graph is Services-only.
func (d *directory) expandIMS(ctx context.Context, g *principal) *pset {
	out := newPset()
	out.groups[descriptorKey(g.Descriptor)] = g
	if g.Kind == kindExternalGroup {
		out.complete = false
	}
	query := url.Values{
		"descriptors":     []string{g.Descriptor},
		"queryMembership": []string{"ExpandedDown"},
		"api-version":     []string{d.f.client.APIVersion()},
	}
	identities, err := getAll[*apiIdentity](ctx, d.f.client, ServiceIdentity, "/_apis/identities", query, pageOptions{})
	if err != nil || len(identities) == 0 || identities[0] == nil {
		out.complete = false
		if err == nil {
			err = fmt.Errorf("the identity was not returned")
		}
		d.f.warn("group %q could not be expanded (%v); counts derived from it are lower bounds", g.Name, err)
		return out
	}
	var members []string
	for _, m := range identities[0].Members {
		if s := string(m); s != "" && !strings.EqualFold(s, g.Descriptor) {
			members = append(members, s)
		}
	}
	resolved := d.resolve(ctx, members)
	for _, m := range members {
		p, ok := resolved[descriptorKey(m)]
		if !ok {
			out.complete = false
			continue
		}
		switch p.Kind {
		case kindHuman, kindService:
			if p.Active {
				out.add(p)
			}
		case kindExternalGroup:
			// Active Directory membership is synchronized into Azure DevOps
			// Server on a schedule, so what the expansion shows is what the
			// last synchronization saw.
			out.groups[descriptorKey(p.Descriptor)] = p
			out.complete = false
		default:
			out.groups[descriptorKey(p.Descriptor)] = p
			if p.Everyone {
				out.everyone = true
			}
		}
	}
	if !out.complete {
		d.f.warn("group %q could not be fully expanded; counts derived from it are lower bounds", g.Name)
	}
	return out
}

// directMembers lists a group's members one level down, as granted.
func (d *directory) directMembers(ctx context.Context, g *principal) ([]*principal, bool) {
	if d.f.client.Endpoint().Deployment != scm.DeploymentServer {
		return d.graphMembers(ctx, g)
	}
	query := url.Values{
		"descriptors":     []string{g.Descriptor},
		"queryMembership": []string{"Direct"},
		"api-version":     []string{d.f.client.APIVersion()},
	}
	identities, err := getAll[*apiIdentity](ctx, d.f.client, ServiceIdentity, "/_apis/identities", query, pageOptions{})
	if err != nil || len(identities) == 0 || identities[0] == nil {
		return nil, false
	}
	var members []string
	for _, m := range identities[0].Members {
		members = append(members, string(m))
	}
	resolved := d.resolve(ctx, members)
	var out []*principal
	complete := true
	for _, m := range members {
		if p, ok := resolved[descriptorKey(m)]; ok {
			out = append(out, p)
		} else {
			complete = false
		}
	}
	return out, complete
}

// expandAll expands a list of principals as granted — people stay people,
// groups become their members — into one set.
func (d *directory) expandAll(ctx context.Context, granted []*principal) *pset {
	out := newPset()
	for _, p := range granted {
		switch p.Kind {
		case kindHuman, kindService:
			if p.Active {
				out.add(p)
			}
		default:
			out.merge(d.expand(ctx, p))
		}
	}
	return out
}
