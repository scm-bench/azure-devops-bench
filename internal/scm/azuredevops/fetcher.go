package azuredevops

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/scm-bench/azure-devops-bench/internal/config"
	"github.com/scm-bench/azure-devops-bench/internal/scm"
)

// Fetcher builds a normalized snapshot from an Azure DevOps organization.
//
// The guiding rule is that a failed fetch must never look like a passing or
// failing setting. Anything that could not be read is recorded in Available as
// false, and policies turn that into MANUAL. The fetcher decides nothing: it
// resolves what the platform says — which policies apply to a branch, who a
// group contains, who holds a permission bit — and records what it could not.
type Fetcher struct {
	client      *Client
	cfg         config.Config
	toolVersion string
	concurrency int
	now         time.Time
	dir         *directory

	// credentialsVerified records that the preflight was answered with JSON.
	// After that point a 401 can only be an authorization decision about one
	// endpoint, not a rejected credential. Set once in Fetch before any
	// goroutine starts, and only read afterwards.
	credentialsVerified bool

	// The organization-wide state below is written in Fetch before any
	// repository goroutine starts, and only read afterwards.

	// pca is Project Collection Administrators; pcaSet its expansion, nil
	// when it could not be read.
	pca    *principal
	pcaSet *pset
	// aclAvailable is false when the credential cannot read access control
	// lists at all — a PAT without vso.security_manage. Every repository
	// then reports its ACL-derived sets as unknown without asking again.
	aclAvailable bool
	aclReason    string
	// orgACEs are the identities with an entry on repoV2, the token covering
	// every repository in the organization.
	orgACEs []string
	// advsec is GitHub Advanced Security enablement by repository ID.
	advsec          map[string]apiAdvSecRepo
	advsecAvailable bool
	advsecReason    string

	warnMu   sync.Mutex
	warnings []string
	warnSeen map[string]bool

	identityWarned atomic.Bool

	unlistedMu sync.Mutex
	unlisted   []string

	progress         func(string)
	onRepositoryDone func(string)

	// repoSlots bounds repository fetches across every project at once.
	repoSlots chan struct{}
}

// FetchOptions narrows and tunes a scan.
type FetchOptions struct {
	// Projects limits the scan to these project names. Empty means all.
	Projects []string
	// Repositories limits the scan to "PROJECT/name" entries.
	Repositories []string
	// Concurrency bounds simultaneous repository fetches. Zero uses 4.
	Concurrency int
	// ToolVersion is stamped into the snapshot metadata.
	ToolVersion string
	// Now fixes the clock used for age calculations, for reproducible tests.
	Now time.Time
	// Progress receives a one-line summary each time a repository finishes.
	Progress func(string)
	// OnRepositoryDone fires once a repository's requests have all completed.
	OnRepositoryDone func(fullName string)
}

// NewFetcher returns a fetcher bound to a client and configuration.
func NewFetcher(client *Client, cfg config.Config) *Fetcher {
	f := &Fetcher{
		client:      client,
		cfg:         cfg,
		concurrency: 4,
		now:         time.Now().UTC(),
		warnSeen:    map[string]bool{},
	}
	f.dir = newDirectory(f)
	return f
}

func (f *Fetcher) logf(format string, args ...any) { f.client.logf(format, args...) }

// warn records an organization-wide problem once.
func (f *Fetcher) warn(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	f.warnMu.Lock()
	defer f.warnMu.Unlock()
	if f.warnSeen[msg] {
		return
	}
	f.warnSeen[msg] = true
	f.warnings = append(f.warnings, msg)
	f.client.warnf("%s", msg)
}

// identityProblem reports, once, that identities could not be resolved — a
// credential without vso.identity, typically — rather than once per batch.
func (f *Fetcher) identityProblem(err error) {
	if f.identityWarned.CompareAndSwap(false, true) {
		f.warn("identities could not be resolved (%v); principal sets that depend on them are lower bounds — the token needs vso.identity (and vso.graph on Azure DevOps Services)", err)
	}
}

func (f *Fetcher) markUnlisted(project string) {
	f.unlistedMu.Lock()
	f.unlisted = append(f.unlisted, project)
	f.unlistedMu.Unlock()
}

// Fetch captures the snapshot.
func (f *Fetcher) Fetch(ctx context.Context, opts FetchOptions) (*scm.Snapshot, error) {
	if opts.Concurrency > 0 {
		f.concurrency = opts.Concurrency
	}
	if !opts.Now.IsZero() {
		f.now = opts.Now.UTC()
	}
	f.toolVersion = opts.ToolVersion
	f.progress = opts.Progress
	f.onRepositoryDone = opts.OnRepositoryDone

	want, err := parseTargets(opts)
	if err != nil {
		return nil, err
	}

	// Recorded before anything is fetched, so a snapshot archived for later
	// re-evaluation still carries what the capture was exposed to.
	for _, w := range f.client.TransportWarnings() {
		f.warn("%s", w)
	}

	if err := f.verifyCredentials(ctx); err != nil {
		return nil, err
	}

	ep := f.client.Endpoint()
	snapshot := &scm.Snapshot{
		SchemaVersion: scm.SchemaVersion,
		Metadata: scm.Metadata{
			Tool:        "azure-devops-bench",
			ToolVersion: opts.ToolVersion,
			Platform:    scm.PlatformAzureDevOps,
			BaseURL:     f.client.BaseURL(),
			GeneratedAt: f.now,
			Deployment:  ep.Deployment,
			APIVersion:  f.client.APIVersion(),
			AuthMethod:  f.client.AuthMethod(),
		},
	}

	// Named targets are resolved before any work is done, so a typo in the
	// last --repository fails in a second rather than after an hour of
	// scanning the ones before it.
	plan, err := f.resolveTargets(ctx, want)
	if err != nil {
		return nil, err
	}

	org := f.fetchOrganization(ctx)
	projects, creators, allCreators := f.fetchProjects(ctx, plan)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	org.RepositoryCreators = creators
	// Only when every project was evaluated: a project missing from the list
	// would otherwise read as one where nobody may create repositories.
	org.Available["repositoryCreators"] = f.aclAvailable && allCreators
	snapshot.Organization = org
	snapshot.Projects = projects

	if countRepositories(projects) == 0 {
		f.warn("the scan covered 0 repositories, so only organization-level controls were evaluated; " +
			"check --project/--repository, and whether the token can see the repositories you expected")
	}

	f.warnMu.Lock()
	snapshot.Metadata.Warnings = append([]string(nil), f.warnings...)
	f.warnMu.Unlock()
	f.unlistedMu.Lock()
	snapshot.Metadata.Unlisted = append([]string(nil), f.unlisted...)
	sort.Strings(snapshot.Metadata.Unlisted)
	f.unlistedMu.Unlock()
	return snapshot, nil
}

// verifyCredentials fails the scan before any work is done when the
// organization rejects the credential outright.
//
// Without this, a mistyped or expired token produces a complete-looking
// report: every control MANUAL, a score of 0, exit 0. Azure DevOps makes it
// worse than most platforms, because an unaccepted credential is often
// answered with 203 and an HTML sign-in page — a success status — so
// "rejected" here means 401, 203, a redirect, or anything that is not JSON.
func (f *Fetcher) verifyCredentials(ctx context.Context) error {
	f.logf("verifying credentials")
	err := f.preflight(ctx)
	if err != nil && isAPIVersionError(err) && f.client.Endpoint().Deployment == scm.DeploymentServer {
		// Azure DevOps Server 2022 speaks 7.0; 2022.1 and later speak 7.1.
		f.logf("api-version 7.1 refused; retrying with 7.0 (Azure DevOps Server 2022)")
		f.client.setAPIVersion("7.0")
		err = f.preflight(ctx)
	}
	switch {
	case err == nil:
		f.credentialsVerified = true
		return nil
	case IsUnauthorized(err) || isSignInLike(err):
		return fmt.Errorf("credential rejected by %s: %w\n"+
			"check --token (AZURE_DEVOPS_TOKEN): a personal access token must belong to this organization and be neither expired nor revoked "+
			"(global PATs stop working on 1 December 2026), and an Entra token from `az account get-access-token --resource 499b84ac-1321-427f-aa17-267ca6975798` lasts about an hour",
			f.client.BaseURL(), err)
	case IsForbidden(err):
		return fmt.Errorf("the credential was accepted but may not list projects at %s: %w\n"+
			"the token needs at least vso.project and vso.code", f.client.BaseURL(), err)
	case IsNotFound(err):
		return fmt.Errorf("no Azure DevOps organization or collection answered at %s: %w\n"+
			"use https://dev.azure.com/{organization}, or https://{server}/{collection} for Azure DevOps Server", f.client.BaseURL(), err)
	case isAPIVersionError(err):
		return fmt.Errorf("%s does not speak REST api-version 7.0 or 7.1: %w\n"+
			"azure-devops-bench needs Azure DevOps Services or Azure DevOps Server 2022 or later", f.client.BaseURL(), err)
	case deterministic(err):
		return fmt.Errorf("could not verify the certificate of %s: %w\n"+
			"for an Azure DevOps Server behind an internal certificate authority, name its CA in scan.caFile, "+
			"a PEM bundle added to the system roots", f.client.BaseURL(), err)
	default:
		return fmt.Errorf("could not reach %s: %w", f.client.BaseURL(), err)
	}
}

func (f *Fetcher) preflight(ctx context.Context) error {
	query := url.Values{"$top": []string{"1"}, "api-version": []string{f.client.APIVersion()}}
	var probe struct {
		Value []apiProject `json:"value"`
	}
	return f.client.getJSON(ctx, ServiceCore, "/_apis/projects", query, &probe)
}

// unreadable reports whether err means "this credential could not read that",
// as opposed to "the scan cannot continue".
func (f *Fetcher) unreadable(err error) bool {
	return IsForbidden(err) || isSignInLike(err) || isNoAccess404(err) ||
		hasStatus(err, 405) || (f.credentialsVerified && IsUnauthorized(err))
}

// describe renders a fetch error for a report: what failed, and when it is an
// access problem, which scope usually fixes it.
func describe(err error) string {
	return err.Error()
}

// fetchOrganization reads what the organization-level controls need and the
// state every repository shares. Nothing here aborts the scan: each part that
// cannot be read is recorded and becomes MANUAL.
func (f *Fetcher) fetchOrganization(ctx context.Context) scm.Organization {
	org := scm.Organization{Available: map[string]bool{}}
	f.checkNamespace(ctx)
	f.fetchAdministrators(ctx, &org)
	f.fetchOrganizationACL(ctx)
	f.fetchUsers(ctx, &org)
	f.fetchAdvancedSecurity(ctx)
	return org
}

// checkNamespace compares the live Git Repositories permission table with
// the one this bench was written against. The bits are documented and have
// not moved in years; if they ever do, every ACL-derived verdict would be
// about the wrong permission, and that is worth a loud warning.
func (f *Fetcher) checkNamespace(ctx context.Context) {
	if f.client.Endpoint().Deployment == "" {
		return
	}
	var namespaces []apiNamespace
	namespaces, err := getAll[apiNamespace](ctx, f.client, ServiceCore, "/_apis/securitynamespaces/"+scm.GitNamespaceID,
		url.Values{"api-version": []string{f.client.APIVersion()}}, pageOptions{})
	if err != nil || len(namespaces) == 0 {
		f.logf("Git Repositories security namespace not readable; using the documented permission bits")
		return
	}
	live := map[string]int64{}
	for _, a := range namespaces[0].Actions {
		live[a.Name] = a.Bit
	}
	for _, want := range []int64{bitForcePush, bitPolicyExempt, bitCreateRepository, bitDeleteRepository, bitManagePermissions, bitPullRequestBypassPolicy} {
		for _, p := range scm.GitPermissions {
			if p.Bit != want {
				continue
			}
			if bit, ok := live[p.Name]; ok && bit != p.Bit {
				f.warn("the organization's Git Repositories namespace defines %s as bit %d, not the documented %d; permission-based verdicts may be about the wrong right",
					p.Name, bit, p.Bit)
			}
		}
	}
}

// fetchAdministrators reads Project Collection Administrators — the
// organization's administrators: owners are members automatically, and its
// members can do anything anywhere in the organization.
func (f *Fetcher) fetchAdministrators(ctx context.Context, org *scm.Organization) {
	f.logf("reading Project Collection Administrators")
	pca, err := f.dir.findCollectionGroup(ctx, "Project Collection Administrators")
	if err != nil {
		org.Available["admins"] = false
		org.Errors = append(org.Errors, fmt.Sprintf("Project Collection Administrators: %v", err))
		f.warn("Project Collection Administrators could not be read (%v); CIS-1.3.3 reports MANUAL, and administrator sets on repositories cannot exclude organization administrators", err)
		return
	}
	f.pca = pca

	direct, ok := f.dir.directMembers(ctx, pca)
	for _, m := range direct {
		kind := "user"
		switch m.Kind {
		case kindService:
			kind = "service"
		case kindGroup, kindExternalGroup:
			kind = "group"
		}
		org.Admins = append(org.Admins, scm.PrincipalPermission{
			Name:       m.Name,
			Type:       kind,
			Permission: "Project Collection Administrators",
			Active:     m.Active,
		})
	}
	sort.Slice(org.Admins, func(i, j int) bool { return org.Admins[i].Name < org.Admins[j].Name })

	set := f.dir.expand(ctx, pca)
	if !ok {
		// The direct listing failing and the expansion succeeding would be
		// odd, but the expansion is what the count rests on; the direct list
		// is only how the report names the grants.
		org.Errors = append(org.Errors, "Project Collection Administrators: the direct members could not all be resolved")
	}
	f.pcaSet = set
	eff := set.effective()
	// The group itself is not one of its members.
	eff.Groups = removeString(eff.Groups, pca.Name)
	org.EffectiveAdmins = eff
	org.Available["admins"] = true
}

func removeString(in []string, drop string) []string {
	var out []string
	for _, s := range in {
		if s != drop {
			out = append(out, s)
		}
	}
	return out
}

// fetchOrganizationACL reads the organization-wide Git permissions, which
// also settles whether this credential can read access control lists at all.
func (f *Fetcher) fetchOrganizationACL(ctx context.Context) {
	acls, err := f.queryACLs(ctx, "repoV2", false)
	if err != nil {
		f.aclAvailable = false
		f.aclReason = fmt.Sprintf("Git permissions are not readable (%v)", err)
		if f.unreadable(err) {
			f.aclReason = fmt.Sprintf("Git permissions are not readable (%v); the token needs vso.security_manage", err)
		}
		f.warn("%s: who can bypass policies, force push, delete branches or repositories, administer repositories or create them is unknown, "+
			"so CIS-1.1.5, 1.1.14, 1.2.2, 1.2.3, 1.3.7 report MANUAL, and CIS-1.1.15–1.1.17 and 1.3.8 can still fail but cannot pass", f.aclReason)
		return
	}
	f.aclAvailable = true
	f.orgACEs = aceDescriptors(acls, func(token string) bool { return strings.EqualFold(strings.TrimSuffix(token, "/"), "repoV2") })
}

// aceDescriptors lists the identities with an explicit entry on the tokens
// keep selects.
func aceDescriptors(acls []apiACL, keep func(token string) bool) []string {
	seen := map[string]bool{}
	var out []string
	for _, acl := range acls {
		if !keep(acl.Token) {
			continue
		}
		for key, ace := range acl.AcesDictionary {
			d := ace.Descriptor
			if d == "" {
				d = key
			}
			if k := descriptorKey(d); k != "" && !seen[k] {
				seen[k] = true
				out = append(out, d)
			}
		}
	}
	sort.Strings(out)
	return out
}

func unionDescriptors(lists ...[]string) []string {
	seen := map[string]bool{}
	var out []string
	for _, list := range lists {
		for _, d := range list {
			if k := descriptorKey(d); k != "" && !seen[k] {
				seen[k] = true
				out = append(out, d)
			}
		}
	}
	return out
}

// fetchAdvancedSecurity reads GitHub Advanced Security enablement for every
// repository in one call. Services only.
func (f *Fetcher) fetchAdvancedSecurity(ctx context.Context) {
	if !f.client.Endpoint().Has(ServiceAdvancedSecurity) {
		f.advsecReason = "GitHub Advanced Security for Azure DevOps exists only on Azure DevOps Services, not on Azure DevOps Server"
		return
	}
	var org apiAdvSecOrg
	err := f.client.getJSON(ctx, ServiceAdvancedSecurity, "/_apis/management/enablement",
		url.Values{"includeAllProperties": []string{"true"}, "api-version": []string{"7.2-preview.3"}}, &org)
	if err != nil {
		f.advsecReason = fmt.Sprintf("Advanced Security enablement is not readable (%v); the token needs vso.advsec", err)
		f.warn("%s; CIS-1.5.1 reports MANUAL", f.advsecReason)
		return
	}
	f.advsec = map[string]apiAdvSecRepo{}
	for _, r := range org.ReposEnablementStatus {
		f.advsec[strings.ToLower(r.RepositoryID)] = r
	}
	f.advsecAvailable = true
}

// projectPlan is one project to scan and, when --repository named some, the
// repositories in it.
type projectPlan struct {
	project apiProject
	// repos is nil to scan every repository; otherwise the named ones.
	repos []apiRepository
	whole bool
}

// resolveTargets turns --project/--repository into projects and repositories,
// failing on any name that does not exist. A named target that resolves to
// nothing must not become a scan of nothing that exits 0.
func (f *Fetcher) resolveTargets(ctx context.Context, want targets) ([]*projectPlan, error) {
	if len(want.projects) == 0 {
		f.logf("listing projects")
		all, err := getAll[apiProject](ctx, f.client, ServiceCore, "/_apis/projects",
			url.Values{"stateFilter": []string{"wellFormed"}, "api-version": []string{f.client.APIVersion()}},
			pageOptions{top: 100, skipFallback: true})
		if err != nil {
			return nil, fmt.Errorf("list projects: %w", err)
		}
		sort.Slice(all, func(i, j int) bool { return strings.ToLower(all[i].Name) < strings.ToLower(all[j].Name) })
		plans := make([]*projectPlan, 0, len(all))
		for _, p := range all {
			plans = append(plans, &projectPlan{project: p, whole: true})
		}
		return plans, nil
	}

	var plans []*projectPlan
	for _, name := range want.keys() {
		var p apiProject
		err := f.client.getJSON(ctx, ServiceCore, "/_apis/projects/"+url.PathEscape(name),
			url.Values{"api-version": []string{f.client.APIVersion()}}, &p)
		if err != nil {
			if IsNotFound(err) {
				return nil, fmt.Errorf("project %q not found in %s (or the token cannot see it)", name, f.client.BaseURL())
			}
			return nil, fmt.Errorf("fetch project %s: %w", name, err)
		}
		plan := &projectPlan{project: p, whole: want.wholeProjects[strings.ToLower(name)]}
		if !plan.whole {
			for _, repoName := range want.reposIn(name) {
				var r apiRepository
				err := f.client.getJSON(ctx, ServiceCore,
					"/"+url.PathEscape(p.ID)+"/_apis/git/repositories/"+url.PathEscape(repoName),
					url.Values{"api-version": []string{f.client.APIVersion()}}, &r)
				if err != nil {
					if IsNotFound(err) {
						return nil, fmt.Errorf("repository %q not found in project %s (or the token cannot see it)", repoName, p.Name)
					}
					return nil, fmt.Errorf("fetch repository %s/%s: %w", p.Name, repoName, err)
				}
				plan.repos = append(plan.repos, r)
			}
		}
		plans = append(plans, plan)
	}
	return plans, nil
}

// projectState is what a repository needs to know about the project above
// it, computed once per project.
type projectState struct {
	id, name        string
	public          bool
	visibilityKnown bool
	// aceDescriptors are the identities with an entry on repoV2/{project}.
	aceDescriptors []string
	aclKnown       bool
	aclReason      string
	// policies are every policy in the project, for the cross-check against
	// what each branch is reported to have.
	policies      []policy
	policiesKnown bool
}

// fetchProjects scans the planned projects side by side, every repository of
// every project drawing on one shared bound.
//
// One project at a time ran an organization of a thousand small projects one
// or two requests wide however high scan.concurrency was set: the bound only
// ever applied inside a project. The snapshot keeps the listing's order. It
// also reports whether repository creators were evaluated in every project,
// which is what makes their absence from the list mean "none".
func (f *Fetcher) fetchProjects(ctx context.Context, plans []*projectPlan) ([]scm.Project, []scm.ProjectPrincipals, bool) {
	f.repoSlots = make(chan struct{}, f.concurrency)
	projectSlots := make(chan struct{}, f.concurrency)
	projects := make([]scm.Project, len(plans))
	creators := make([]*scm.ProjectPrincipals, len(plans))
	done := make([]bool, len(plans))

	var wg sync.WaitGroup
	for i, plan := range plans {
		wg.Add(1)
		go func(i int, plan *projectPlan) {
			defer wg.Done()
			select {
			case projectSlots <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-projectSlots }()
			project, c := f.fetchProject(ctx, plan, scanPosition{project: i + 1, projects: len(plans)})
			projects[i], creators[i], done[i] = project, c, true
		}(i, plan)
	}
	wg.Wait()

	var out []scm.Project
	var found []scm.ProjectPrincipals
	allCreators := true
	for i := range plans {
		if !done[i] {
			continue
		}
		out = append(out, projects[i])
		if creators[i] == nil {
			allCreators = false
			continue
		}
		found = append(found, *creators[i])
	}
	return out, found, allCreators
}

// fetchProject scans one project: its shared state, who may create
// repositories in it, and its repositories.
func (f *Fetcher) fetchProject(ctx context.Context, plan *projectPlan, pos scanPosition) (scm.Project, *scm.ProjectPrincipals) {
	ps := f.prepareProject(ctx, plan.project)
	project := scm.Project{
		Key:        plan.project.Name,
		Name:       plan.project.Name,
		ID:         plan.project.ID,
		Public:     ps.public,
		Visibility: visibilityLabel(ps),
	}
	project.Permissions.PublicAccess = ps.public

	var creators *scm.ProjectPrincipals
	if c, ok := f.repositoryCreators(ctx, ps); ok {
		creators = &c
	}

	repos := plan.repos
	if plan.whole {
		f.logf("listing repositories in %s", plan.project.Name)
		listed, err := getAll[apiRepository](ctx, f.client, ServiceCore,
			"/"+url.PathEscape(plan.project.ID)+"/_apis/git/repositories",
			url.Values{"includeHidden": []string{"true"}, "api-version": []string{f.client.APIVersion()}}, pageOptions{})
		if err != nil {
			// The rest of the organization is still worth reporting, but
			// this project was not audited and the exit code must say so.
			f.markUnlisted(plan.project.Name)
			f.warn("the repositories of project %s could not be listed (%v); none of them was audited", plan.project.Name, err)
			return project, creators
		}
		sort.Slice(listed, func(a, b int) bool { return strings.ToLower(listed[a].Name) < strings.ToLower(listed[b].Name) })
		repos = listed
	}
	project.Repositories = f.fetchRepositories(ctx, ps, repos, pos)
	return project, creators
}

func visibilityLabel(ps *projectState) string {
	if !ps.visibilityKnown {
		return ""
	}
	if ps.public {
		return "public"
	}
	return "private"
}

// parseVisibility reads TeamProjectReference.visibility, which is "private"
// or "public" on current versions and a number on some older ones.
func parseVisibility(v flexString) (public, known bool) {
	switch strings.ToLower(strings.TrimSpace(string(v))) {
	case "private", "0":
		return false, true
	case "public", "2":
		return true, true
	}
	// Absent — Microsoft's own sample omits it — or "organization", a
	// preview-era value: not a visibility this bench can rank, so unknown.
	return false, false
}

func (f *Fetcher) prepareProject(ctx context.Context, p apiProject) *projectState {
	ps := &projectState{id: p.ID, name: p.Name}
	ps.public, ps.visibilityKnown = parseVisibility(p.Visibility)
	if !ps.visibilityKnown {
		f.warn("project %s did not report its visibility; whether it is public is unknown and CIS-1.3.8 cannot pass there", p.Name)
	}

	if f.aclAvailable {
		acls, err := f.queryACLs(ctx, projectToken(p.ID), false)
		descriptors := aceDescriptors(acls, func(token string) bool { return tokenCovers(token, projectToken(p.ID)) })
		switch {
		case err != nil:
			ps.aclReason = fmt.Sprintf("project %s Git permissions are not readable (%v)", p.Name, err)
			f.warn("%s", ps.aclReason)
		case len(descriptors) == 0:
			// Every project is created with entries on its All Repositories
			// token — Project Administrators, Contributors, Readers, the
			// build service — so an answer with none is not a project
			// nobody can touch: it is an answer this credential was not
			// shown in full. Read as "no grants", it would drop every
			// project-level Force push or bypass grant out of the candidate
			// set and let the controls built on them pass.
			ps.aclReason = fmt.Sprintf("project %s Git permissions came back with no entries at all, which no project has by default; "+
				"the credential cannot see them in full (it needs vso.security_manage)", p.Name)
			f.warn("%s", ps.aclReason)
		default:
			ps.aclKnown = true
			ps.aceDescriptors = descriptors
		}
	} else {
		ps.aclReason = f.aclReason
	}

	policies, err := f.fetchProjectPolicies(ctx, p.ID)
	if err != nil {
		f.warn("project %s policy list could not be read for cross-checking (%v); branch policies are taken from the per-branch answer alone", p.Name, err)
	} else {
		ps.policies, ps.policiesKnown = policies, true
	}
	return ps
}

// repositoryCreators finds who holds "Create repository" in a project without
// administering it (CIS-1.2.2).
func (f *Fetcher) repositoryCreators(ctx context.Context, ps *projectState) (scm.ProjectPrincipals, bool) {
	if !ps.aclKnown {
		return scm.ProjectPrincipals{}, false
	}
	token := projectToken(ps.id)
	candidates := unionDescriptors(f.orgACEs, ps.aceDescriptors, f.pcaDescriptor())
	eval, err := f.evaluate(ctx, token, candidates)
	if err != nil {
		f.warn("project %s: who may create repositories could not be evaluated (%v)", ps.name, err)
		return scm.ProjectPrincipals{}, false
	}
	resolved := f.dir.resolve(ctx, interesting(eval, candidates, bitCreateRepository|bitManagePermissions))
	create := f.expandHolders(ctx, holdersOf(eval, resolved, candidates, bitCreateRepository))
	admins := f.expandHolders(ctx, holdersOf(eval, resolved, candidates, bitManagePermissions))

	creators := subtract(create, admins)
	exact := admins.complete
	if f.pcaSet != nil {
		creators = subtract(creators, f.pcaSet)
		exact = exact && f.pcaSet.complete
	} else {
		exact = false
	}
	return scm.ProjectPrincipals{Project: ps.name, Principals: creators.effective(), AdminsExact: exact}, true
}

func (f *Fetcher) pcaDescriptor() []string {
	if f.pca == nil {
		return nil
	}
	return []string{f.pca.Descriptor}
}

// interesting lists the descriptors whose evaluation allows or denies any of
// bits — the only ones worth resolving to a name.
func interesting(eval aclEval, candidates []string, bits int64) []string {
	var out []string
	for _, d := range candidates {
		k := descriptorKey(d)
		if eval.allow[k]&bits != 0 || eval.deny[k]&bits != 0 {
			out = append(out, d)
		}
	}
	return out
}

// scanPosition is where the scan has got to across projects.
type scanPosition struct {
	project  int
	projects int
}

func (f *Fetcher) reportProgress(pos scanPosition, project string, done, total int) {
	if f.progress == nil {
		return
	}
	if pos.projects > 1 {
		f.progress(fmt.Sprintf("scanning · project %d/%d · %s %d/%d repositories", pos.project, pos.projects, project, done, total))
		return
	}
	f.progress(fmt.Sprintf("scanning · %s %d/%d repositories", project, done, total))
}

// fetchRepositories populates the repositories of one project, bounded by the
// configured concurrency.
func (f *Fetcher) fetchRepositories(ctx context.Context, ps *projectState, repos []apiRepository, pos scanPosition) []scm.Repository {
	selected := make([]apiRepository, 0, len(repos))
	for _, r := range repos {
		if f.cfg.SkipArchivedRepositories && r.IsDisabled {
			f.logf("skipping disabled repository %s/%s", ps.name, r.Name)
			continue
		}
		selected = append(selected, r)
	}

	out := make([]scm.Repository, len(selected))
	done := make([]bool, len(selected))
	sem := f.repoSlots
	if sem == nil {
		sem = make(chan struct{}, f.concurrency)
	}
	var wg sync.WaitGroup
	var completed atomic.Int64
	for i, r := range selected {
		wg.Add(1)
		go func(i int, r apiRepository) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()
			out[i] = f.fetchRepository(ctx, ps, r)
			done[i] = true
			f.reportProgress(pos, ps.name, int(completed.Add(1)), len(selected))
		}(i, r)
	}
	wg.Wait()

	// A cancelled scan returns what it has; the caller checks the context
	// and refuses to report on a partial snapshot.
	kept := out[:0]
	for i, r := range out {
		if done[i] {
			kept = append(kept, r)
		}
	}
	return kept
}

func countRepositories(projects []scm.Project) int {
	n := 0
	for _, p := range projects {
		n += len(p.Repositories)
	}
	return n
}

func (f *Fetcher) daysSince(t time.Time) int {
	if t.IsZero() {
		return -1
	}
	d := f.now.Sub(t.UTC())
	if d < 0 {
		// A timestamp in the future (clock skew) is best reported as fresh.
		return 0
	}
	return int(d.Hours() / 24)
}

// targets is the resolved --project/--repository selection.
//
// Both flags are additive includes: `--project A --repository B/app` scans
// all of A and one repository of B. Project names are compared
// case-insensitively, as Azure DevOps compares them.
type targets struct {
	projects      map[string]string
	wholeProjects map[string]bool
	repositories  map[string][]string
}

func (t targets) keys() []string {
	out := make([]string, 0, len(t.projects))
	for lower := range t.projects {
		out = append(out, lower)
	}
	sort.Strings(out)
	for i, lower := range out {
		out[i] = t.projects[lower]
	}
	return out
}

func (t targets) reposIn(project string) []string {
	return t.repositories[strings.ToLower(project)]
}

// parseTargets normalizes the project and repository filters.
func parseTargets(opts FetchOptions) (targets, error) {
	t := targets{
		projects:      map[string]string{},
		wholeProjects: map[string]bool{},
		repositories:  map[string][]string{},
	}
	addProject := func(name string) {
		lower := strings.ToLower(name)
		if _, seen := t.projects[lower]; !seen {
			t.projects[lower] = name
		}
	}
	for _, p := range opts.Projects {
		if p = strings.TrimSpace(p); p == "" {
			continue
		}
		addProject(p)
		t.wholeProjects[strings.ToLower(p)] = true
	}
	for _, r := range opts.Repositories {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}
		project, name, ok := strings.Cut(r, "/")
		project, name = strings.TrimSpace(project), strings.TrimSpace(name)
		if !ok || project == "" || name == "" {
			return targets{}, fmt.Errorf("--repository %q must be PROJECT/REPOSITORY", r)
		}
		addProject(project)
		lower := strings.ToLower(project)
		dup := false
		for _, existing := range t.repositories[lower] {
			if strings.EqualFold(existing, name) {
				dup = true
			}
		}
		if !dup {
			t.repositories[lower] = append(t.repositories[lower], name)
		}
	}
	return t, nil
}
