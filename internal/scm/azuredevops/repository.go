package azuredevops

import (
	"context"
	"fmt"
	"net/url"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/scm-bench/azure-devops-bench/internal/scm"
)

// fetchRepository populates every setting a policy might read for one
// repository. Sub-fetch failures are recorded, not propagated: one repository
// the token cannot fully read must not abort the scan.
func (f *Fetcher) fetchRepository(ctx context.Context, ps *projectState, r apiRepository) scm.Repository {
	full := ps.name + "/" + r.Name
	f.logf("scanning %s", full)
	ctx = withScope(ctx, full)
	if f.onRepositoryDone != nil {
		defer f.onRepositoryDone(full)
	}

	repo := scm.Repository{
		Slug:       r.Name,
		Name:       r.Name,
		ProjectKey: ps.name,
		FullName:   full,
		ID:         r.ID,
		Fork:       r.IsFork,
		Public:     ps.public,
		Available:  map[string]bool{"visibility": ps.visibilityKnown},
	}
	repo.Permissions.PublicAccess = ps.public
	if r.Parent != nil {
		repo.ParentRepository = r.Parent.Project.Name + "/" + r.Parent.Name
	}

	if r.IsDisabled {
		// A disabled repository refuses Git requests outright — most answer
		// 404 TF401019 — so none is sent. It is Azure DevOps's archive:
		// change controls are not applicable to it, and who may administer
		// or delete it is still worth knowing.
		repo.Archived, repo.Disabled = true, true
		acc := f.fetchAccess(ctx, ps, &repo, "", "")
		f.applyAccess(&repo, acc)
		return repo
	}

	creator := f.fetchBranches(ctx, ps, r, &repo)
	if repo.Empty {
		acc := f.fetchAccess(ctx, ps, &repo, "", "")
		f.applyAccess(&repo, acc)
		f.applyAdvancedSecurity(&repo)
		repo.Available["files"] = true
		return repo
	}

	applicable, policiesKnown := f.fetchPolicies(ctx, ps, &repo)
	if repo.Available["branches"] {
		f.fetchBranchAges(ctx, ps, &repo)
	}
	f.fetchSecurityPolicy(ctx, ps, &repo)
	acc := f.fetchAccess(ctx, ps, &repo, repo.DefaultBranch, creator)
	f.applyAccess(&repo, acc)
	if policiesKnown {
		f.synthesizeRestrictions(&repo, applicable, acc)
	}
	f.applyAdvancedSecurity(&repo)
	return repo
}

// fetchBranches lists the branches and settles the default branch and
// whether the repository is empty. It returns the Graph descriptor of whoever
// created the default branch, which matters: Azure Repos grants a branch's
// creator Force push on it, so the person who first pushed main can rewrite
// it unless someone took that away.
func (f *Fetcher) fetchBranches(ctx context.Context, ps *projectState, r apiRepository, repo *scm.Repository) string {
	refs, err := getAll[apiRef](ctx, f.client, ServiceCore,
		"/"+url.PathEscape(ps.id)+"/_apis/git/repositories/"+url.PathEscape(r.ID)+"/refs",
		url.Values{"filter": []string{"heads/"}, "api-version": []string{f.client.APIVersion()}},
		pageOptions{top: 1000, fullPageNeedsToken: true})
	if err != nil {
		repo.Available["branches"] = false
		repo.Available["defaultBranch"] = false
		repo.Errors = append(repo.Errors, fmt.Sprintf("branches: %s", describe(err)))
		return ""
	}
	repo.Available["branches"] = true

	// Empty is decided from the branch list, never from a configured name:
	// Azure DevOps omits defaultBranch for an empty repository, but a
	// repository can also have branches and no default, or a default that
	// no longer exists.
	if len(refs) == 0 {
		repo.Empty = true
		repo.Available["defaultBranch"] = true
		repo.Available["branchAges"] = true
		return ""
	}

	creator := ""
	found := false
	for _, ref := range refs {
		if !strings.HasPrefix(ref.Name, "refs/heads/") {
			continue
		}
		isDefault := r.DefaultBranch != "" && ref.Name == r.DefaultBranch
		if isDefault {
			found = true
			if ref.Creator != nil {
				creator = ref.Creator.Descriptor
			}
		}
		repo.Branches = append(repo.Branches, scm.Branch{
			ID:           ref.Name,
			DisplayID:    strings.TrimPrefix(ref.Name, "refs/heads/"),
			IsDefault:    isDefault,
			LatestCommit: ref.ObjectID,
			AgeDays:      -1,
		})
	}
	switch {
	case r.DefaultBranch == "":
		repo.Available["defaultBranch"] = false
		repo.Errors = append(repo.Errors, "the repository has branches but no default branch is configured")
	case !found:
		repo.Available["defaultBranch"] = false
		repo.Errors = append(repo.Errors, fmt.Sprintf("configured default branch %s does not exist", r.DefaultBranch))
	default:
		repo.Available["defaultBranch"] = true
		repo.DefaultBranch = r.DefaultBranch
		repo.DefaultBranchDisplay = strings.TrimPrefix(r.DefaultBranch, "refs/heads/")
	}
	return creator
}

// fetchBranchAges reads every branch's tip commit date in one call.
//
// The committer date is the one used, because it moves when a branch is
// rebased or amended; both dates are client-asserted, which makes this an
// estimate of activity rather than proof of it.
func (f *Fetcher) fetchBranchAges(ctx context.Context, ps *projectState, repo *scm.Repository) {
	stats, err := getAll[apiBranchStats](ctx, f.client, ServiceCore,
		"/"+url.PathEscape(ps.id)+"/_apis/git/repositories/"+url.PathEscape(repo.ID)+"/stats/branches",
		url.Values{"api-version": []string{f.client.APIVersion()}}, pageOptions{})
	if err != nil {
		repo.Available["branchAges"] = false
		repo.Errors = append(repo.Errors, fmt.Sprintf("branch commit dates: %s", describe(err)))
		return
	}
	dates := map[string]time.Time{}
	for _, s := range stats {
		raw := s.Commit.Committer.Date
		if raw == "" {
			raw = s.Commit.Author.Date
		}
		t, err := time.Parse(time.RFC3339, raw)
		if err != nil || t.Year() <= 1 {
			continue
		}
		name := s.Name
		if !strings.HasPrefix(name, "refs/") {
			name = "refs/heads/" + name
		}
		dates[name] = t
	}
	complete := true
	for i := range repo.Branches {
		b := &repo.Branches[i]
		t, ok := dates[b.ID]
		if !ok {
			complete = false
			continue
		}
		b.LatestCommitEpoch = t.Unix()
		b.AgeDays = f.daysSince(t)
	}
	repo.Available["branchAges"] = complete
	if !complete {
		repo.Errors = append(repo.Errors, "commit dates unavailable for some branches; the stale-branch rule reports MANUAL")
	}
}

// fetchPolicies reads the policies applying to the default branch and
// projects them onto the pull request settings and required checks. It
// returns the applicable policies and whether they are known.
func (f *Fetcher) fetchPolicies(ctx context.Context, ps *projectState, repo *scm.Repository) ([]policy, bool) {
	setUnknown := func(reason string) {
		for _, key := range []string{"pullRequestSettings", "mergeStrategies", "unapproveOnUpdate", "requiredBuilds", "branchRestrictions"} {
			repo.Available[key] = false
		}
		repo.Errors = append(repo.Errors, reason)
	}

	if repo.DefaultBranch == "" {
		// The default branch is unknown, so nothing can be said about which
		// policies protect it — with one exception worth the extra request:
		// a repository with no required branch policy anywhere has no
		// protected branch at all, whatever its default is.
		for _, key := range []string{"pullRequestSettings", "mergeStrategies", "unapproveOnUpdate", "requiredBuilds"} {
			repo.Available[key] = false
		}
		f.unknownDefaultBranchRestrictions(ctx, ps, repo)
		return nil, false
	}

	applicable, err := f.fetchBranchPolicies(ctx, ps.id, repo.ID, repo.DefaultBranch, ps.policies, ps.policiesKnown)
	if err != nil {
		setUnknown(fmt.Sprintf("branch policies: %s", describe(err)))
		return nil, false
	}
	repo.PullRequestSettings = derivePullRequestSettings(applicable)
	repo.RequiredBuilds = deriveRequiredBuilds(applicable, repo.DefaultBranch, repo.DefaultBranchDisplay)
	repo.Policies = policyEvidence(applicable)
	for _, key := range []string{"pullRequestSettings", "mergeStrategies", "unapproveOnUpdate", "requiredBuilds", "branchRestrictions"} {
		repo.Available[key] = true
	}
	for _, p := range applicable {
		if p.api.IsBlocking && !p.known() {
			f.warn("policy type %q (%s) is required on some branches but is not one this bench knows; it is not counted as branch protection",
				p.typeName(), p.typeID)
		}
	}
	return applicable, true
}

// unknownDefaultBranchRestrictions handles a repository whose default branch
// could not be resolved: a FAIL that does not depend on the branch is still
// reported, and everything else becomes MANUAL.
func (f *Fetcher) unknownDefaultBranchRestrictions(ctx context.Context, ps *projectState, repo *scm.Repository) {
	repoWide, err := f.fetchRepositoryPolicies(ctx, ps.id, repo.ID)
	if err != nil {
		repo.Available["branchRestrictions"] = false
		repo.Errors = append(repo.Errors, fmt.Sprintf("branch policies: %s", describe(err)))
		return
	}
	required := len(requiredBranchPolicies(repoWide)) > 0
	// The project's own list is consulted too, because whether a per-
	// repository query includes cross-repository and default-branch scoped
	// policies is exactly the kind of detail this fallback must not bet a
	// FAIL on.
	for _, p := range ps.policies {
		if !p.known() || !p.api.IsEnabled || p.api.IsDeleted || !p.api.IsBlocking {
			continue
		}
		for _, s := range p.settings.Scope {
			if s.RepositoryID == nil || strings.EqualFold(*s.RepositoryID, repo.ID) {
				required = true
			}
		}
	}
	if !ps.policiesKnown {
		required = true // cannot rule it out
	}
	repo.Available["branchRestrictions"] = true
	unknown := func(kind string) scm.BranchRestriction {
		return scm.BranchRestriction{
			Type:             kind,
			MatcherType:      "BRANCH",
			Scope:            "REPOSITORY",
			MatchUnknown:     true,
			ExemptPrincipals: scm.EffectivePrincipals{Complete: false},
			Derived:          true,
			DerivedFrom:      []string{"the default branch could not be resolved"},
		}
	}
	if required {
		repo.BranchRestrictions = append(repo.BranchRestrictions,
			unknown(scm.RestrictionPullRequestOnly), unknown(scm.RestrictionNoDeletes))
	}
	// Azure Repos denies force push unless it is granted, so the restriction
	// exists on every branch; who holds the grant on an unknown branch is
	// what cannot be said.
	repo.BranchRestrictions = append(repo.BranchRestrictions, unknown(scm.RestrictionFastForwardOnly))
}

// fetchSecurityPolicy looks for the configured security policy paths on the
// default branch, listing each parent folder once instead of probing every
// path: three requests for the six default paths, and a missing folder
// settles all of its paths at once.
func (f *Fetcher) fetchSecurityPolicy(ctx context.Context, ps *projectState, repo *scm.Repository) {
	if repo.DefaultBranch == "" {
		// The repository has branches but its default could not be resolved,
		// so nothing was browsed. Marking this available would let the rule
		// report "no security policy found" having looked nowhere.
		repo.Available["files"] = false
		repo.Errors = append(repo.Errors, "default branch unresolved, so no path could be browsed for a security policy")
		return
	}

	byDir := map[string][]string{}
	var dirs []string
	for _, p := range f.cfg.SecurityPolicyPaths {
		clean := strings.TrimPrefix(path.Clean("/"+strings.TrimSpace(p)), "/")
		dir := path.Dir("/" + clean)
		if _, ok := byDir[dir]; !ok {
			dirs = append(dirs, dir)
		}
		byDir[dir] = append(byDir[dir], clean)
		repo.Files.Probed = append(repo.Files.Probed, clean)
	}

	present := map[string]bool{}
	for _, dir := range dirs {
		items, err := getAll[apiItem](ctx, f.client, ServiceCore,
			"/"+url.PathEscape(ps.id)+"/_apis/git/repositories/"+url.PathEscape(repo.ID)+"/items",
			url.Values{
				"scopePath":                     []string{dir},
				"recursionLevel":                []string{"OneLevel"},
				"versionDescriptor.version":     []string{repo.DefaultBranchDisplay},
				"versionDescriptor.versionType": []string{"branch"},
				"api-version":                   []string{f.client.APIVersion()},
			}, pageOptions{})
		if err != nil {
			if IsNotFound(err) && !isNoAccess404(err) {
				// The folder is not there (TF401174, "the item could not be
				// found"). The repository and the branch were both read a
				// moment ago, so a 404 here is about the path, not access.
				continue
			}
			repo.Available["files"] = false
			repo.Errors = append(repo.Errors, fmt.Sprintf("browse %s: %s", dir, describe(err)))
			return
		}
		for _, it := range items {
			if it.IsFolder || strings.EqualFold(it.GitObjectType, "tree") {
				continue
			}
			present[strings.ToLower(strings.TrimPrefix(it.Path, "/"))] = true
		}
	}
	for _, dir := range dirs {
		for _, p := range byDir[dir] {
			// Case-insensitive, as GitHub reads SECURITY.md: security.md
			// serves the same reader.
			if present[strings.ToLower(p)] {
				repo.Files.SecurityPolicyPaths = append(repo.Files.SecurityPolicyPaths, p)
			}
		}
	}
	repo.Available["files"] = true
}

// repoAccess is what the access control lists say about one repository.
type repoAccess struct {
	// repoKnown and branchKnown say whether each evaluation ran at all.
	repoKnown, branchKnown bool
	// manage, deleters: holders on the repository token.
	manage, deleters *pset
	// push, pullRequest, force: holders on the default branch token.
	push, pullRequest, force *pset
	// everyone are the grants held by the every-member groups, and
	// everyoneKnown whether all of them were identified.
	everyone      []scm.PrincipalPermission
	everyoneKnown bool
	reason        string
}

// fetchAccess evaluates who holds the permissions this bench decides on, for
// one repository and its default branch.
//
// Candidates come first: every identity with an explicit entry on a token the
// branch inherits from (the organization, the project, the repository, any
// branch folder above it, the branch itself), plus Project Collection
// Administrators and the branch's creator. Then the server evaluates each
// candidate on the repository token and on the branch token — its own answer,
// inheritance and denies included — and groups are expanded to people.
func (f *Fetcher) fetchAccess(ctx context.Context, ps *projectState, repo *scm.Repository, ref, creatorSubject string) repoAccess {
	acc := repoAccess{}
	if !f.aclAvailable {
		acc.reason = f.aclReason
		return acc
	}
	if !ps.aclKnown {
		acc.reason = ps.aclReason
		return acc
	}
	rTok := repoToken(ps.id, repo.ID)
	acls, err := f.queryACLs(ctx, rTok, true)
	if err != nil {
		acc.reason = fmt.Sprintf("repository Git permissions: %s", describe(err))
		return acc
	}
	bTok := ""
	if ref != "" {
		bTok = branchToken(ps.id, repo.ID, ref)
	}
	local := aceDescriptors(acls, func(token string) bool {
		if tokenCovers(token, rTok) {
			return true
		}
		return bTok != "" && tokenCovers(token, bTok)
	})
	extra := f.pcaDescriptor()
	if creatorSubject != "" {
		resolved := f.dir.resolveSubjects(ctx, []string{creatorSubject})
		if p, ok := resolved[strings.ToLower(creatorSubject)]; ok {
			extra = append(extra, p.Descriptor)
		}
		// An unresolvable creator stays out of the candidates; if they hold
		// anything it is through an entry on one of the tokens above, which
		// already made them a candidate.
	}
	candidates := unionDescriptors(f.orgACEs, ps.aceDescriptors, local, extra)

	repoEval, err := f.evaluate(ctx, rTok, candidates)
	if err != nil {
		acc.reason = fmt.Sprintf("repository Git permissions: %s", describe(err))
		return acc
	}
	acc.repoKnown = true
	var branchEval aclEval
	if bTok != "" {
		branchEval, err = f.evaluate(ctx, bTok, candidates)
		if err != nil {
			acc.reason = fmt.Sprintf("default branch Git permissions: %s", describe(err))
		} else {
			acc.branchKnown = true
		}
	}

	// Only identities that hold or are denied something relevant are worth
	// a name; the rest are resolved only if they are every-member groups,
	// which is decided below from the repository evaluation.
	anyBit := int64(0)
	for _, p := range scm.GitPermissions {
		anyBit |= p.Bit
	}
	toResolve := interesting(repoEval, candidates, anyBit)
	if acc.branchKnown {
		toResolve = unionDescriptors(toResolve, interesting(branchEval, candidates, bitForcePush|bitPolicyExempt|bitPullRequestBypassPolicy))
	}
	resolved := f.dir.resolve(ctx, toResolve)

	acc.manage = f.expandHolders(ctx, holdersOf(repoEval, resolved, candidates, bitManagePermissions))
	acc.deleters = f.expandHolders(ctx, holdersOf(repoEval, resolved, candidates, bitDeleteRepository))
	if acc.branchKnown {
		acc.push = f.expandHolders(ctx, holdersOf(branchEval, resolved, candidates, bitPolicyExempt))
		acc.pullRequest = f.expandHolders(ctx, holdersOf(branchEval, resolved, candidates, bitPullRequestBypassPolicy))
		acc.force = f.expandHolders(ctx, holdersOf(branchEval, resolved, candidates, bitForcePush))
	}

	// The every-member groups' grants. An identity holding any bit that the
	// directory could not name might be one of them, so the set is only
	// known when every holder was identified.
	acc.everyoneKnown = repoEval.complete
	for _, d := range candidates {
		k := descriptorKey(d)
		bits := repoEval.allow[k] &^ repoEval.deny[k]
		if bits == 0 {
			continue
		}
		p, ok := resolved[k]
		if !ok {
			acc.everyoneKnown = false
			continue
		}
		if !p.Everyone {
			continue
		}
		for _, perm := range scm.GitPermissions {
			if bits&perm.Bit != 0 {
				acc.everyone = append(acc.everyone, scm.PrincipalPermission{
					Name: p.Name, Type: "group", Permission: perm.Name,
				})
			}
		}
	}
	sort.Slice(acc.everyone, func(i, j int) bool {
		if acc.everyone[i].Name != acc.everyone[j].Name {
			return acc.everyone[i].Name < acc.everyone[j].Name
		}
		return acc.everyone[i].Permission < acc.everyone[j].Permission
	})
	return acc
}

// applyAccess writes the access sets into the repository.
func (f *Fetcher) applyAccess(repo *scm.Repository, acc repoAccess) {
	unknown := scm.EffectivePrincipals{Complete: false}
	if acc.reason != "" {
		repo.Errors = append(repo.Errors, acc.reason)
	}
	pcaKnown := f.pcaSet != nil
	pcaComplete := pcaKnown && f.pcaSet.complete

	if !acc.repoKnown {
		repo.Admins, repo.Deleters = unknown, unknown
		repo.Available["admins"] = false
		repo.Available["deleters"] = false
		repo.Available["permissions"] = false
	} else {
		admins, deleters := acc.manage, acc.deleters
		if pcaKnown {
			// Organization administrators can administer and delete every
			// repository; they are CIS-1.3.3's to count, not this one's.
			admins = subtract(admins, f.pcaSet)
			deleters = subtract(deleters, f.pcaSet)
		}
		repo.Admins = admins.effective()
		repo.Deleters = deleters.effective()
		// Without the organization administrators the subtraction cannot be
		// made, and a set that should have had them removed is neither a
		// lower nor an upper bound — so the sets are unknown, not partial.
		repo.Available["admins"] = pcaKnown
		repo.Available["deleters"] = pcaKnown
		// The subtraction is exact only when the administrators were fully
		// expanded: an administrator hiding in an unexpanded Entra group is
		// still in the set above.
		repo.Available["orgAdminsExact"] = pcaComplete
		repo.Permissions.EveryoneGrants = acc.everyone
		repo.Permissions.DefaultPermissionKnown = acc.everyoneKnown
		repo.Available["permissions"] = acc.everyoneKnown
	}

	if !acc.branchKnown || acc.push == nil {
		repo.Bypass = scm.Bypass{Push: unknown, PullRequest: unknown, Admins: unknown}
		repo.ForcePushers = unknown
		repo.Available["bypass"] = false
		return
	}
	repo.Bypass.Push = acc.push.effective()
	repo.Bypass.PullRequest = acc.pullRequest.effective()
	repo.ForcePushers = acc.force.effective()
	repo.Available["bypass"] = true

	// Administrators holding a bypass: the organization's, and whoever holds
	// Manage permissions on this repository (project administrators by
	// inheritance, anyone granted it directly).
	bypassers := newPset()
	bypassers.merge(acc.push)
	bypassers.merge(acc.pullRequest)
	admins := newPset()
	admins.merge(acc.manage)
	if pcaKnown {
		admins.merge(f.pcaSet)
	} else {
		admins.complete = false
	}
	repo.Bypass.Admins = intersect(bypassers, admins).effective()
}

// synthesizeRestrictions derives the family's branch restrictions from the
// required policies and the branch's permissions.
//
// Azure Repos declares no restriction. A branch with any required branch
// policy accepts changes only through pull requests and cannot be deleted
// (Microsoft, "Branch policies"), except for holders of "Bypass policies when
// pushing"; force push is denied unless granted, and on a branch with a
// required policy a force push is a push, so it also needs the bypass.
// Deleting a branch needs Force push. Each restriction below records what it
// was derived from, so a report can explain a protection nobody configured by
// that name.
func (f *Fetcher) synthesizeRestrictions(repo *scm.Repository, applicable []policy, acc repoAccess) {
	required := requiredBranchPolicies(applicable)
	var from []string
	for _, p := range required {
		from = append(from, p.describe())
	}
	scope := "REPOSITORY"
	for _, p := range required {
		if p.scope == "PROJECT" {
			scope = "PROJECT"
		}
	}

	exempt := func(s *pset) scm.EffectivePrincipals {
		if s == nil || !acc.branchKnown {
			return scm.EffectivePrincipals{Complete: false}
		}
		return s.effective()
	}
	restriction := func(kind string, set *pset, derived []string) scm.BranchRestriction {
		eff := exempt(set)
		r := scm.BranchRestriction{
			Type:                 kind,
			MatcherID:            repo.DefaultBranch,
			MatcherType:          "BRANCH",
			MatcherText:          repo.DefaultBranchDisplay,
			Scope:                scope,
			MatchesDefaultBranch: true,
			ExemptPrincipals:     eff,
			ExemptGroups:         eff.Groups,
			Derived:              true,
			DerivedFrom:          derived,
		}
		r.ExemptUsers = append(append([]string(nil), eff.Users...), eff.ServiceIdentities...)
		return r
	}

	var forceAndPush *pset
	if acc.branchKnown {
		forceAndPush = intersect(acc.force, acc.push)
	}
	if len(required) > 0 {
		repo.BranchRestrictions = append(repo.BranchRestrictions,
			restriction(scm.RestrictionPullRequestOnly, acc.push,
				append(append([]string(nil), from...), "exempt: Bypass policies when pushing (PolicyExempt)")),
			restriction(scm.RestrictionNoDeletes, forceAndPush,
				append(append([]string(nil), from...), "exempt: Force push (ForcePush) together with Bypass policies when pushing (PolicyExempt)")),
			restriction(scm.RestrictionFastForwardOnly, forceAndPush,
				append(append([]string(nil), from...), "Azure Repos denies force push unless granted; exempt: Force push (ForcePush) together with Bypass policies when pushing (PolicyExempt)")),
		)
		return
	}
	ffo := restriction(scm.RestrictionFastForwardOnly, acc.force,
		[]string{"Azure Repos denies force push unless granted; exempt: Force push (ForcePush)"})
	ffo.Scope = "REPOSITORY"
	repo.BranchRestrictions = append(repo.BranchRestrictions, ffo)
}

// applyAdvancedSecurity copies the repository's GitHub Advanced Security
// enablement from the organization-wide answer.
func (f *Fetcher) applyAdvancedSecurity(repo *scm.Repository) {
	if !f.advsecAvailable {
		repo.Available["advancedSecurity"] = false
		if f.advsecReason != "" {
			repo.Errors = append(repo.Errors, f.advsecReason)
		}
		return
	}
	entry, ok := f.advsec[strings.ToLower(repo.ID)]
	if !ok || entry.SecretProtectionFeatures == nil || entry.SecretProtectionFeatures.SecretProtectionEnabled == nil {
		repo.Available["advancedSecurity"] = false
		repo.Errors = append(repo.Errors, "the repository is not listed in the organization's Advanced Security enablement")
		return
	}
	sp := entry.SecretProtectionFeatures
	repo.AdvancedSecurity.SecretProtection = *sp.SecretProtectionEnabled
	if sp.BlockPushes != nil {
		repo.AdvancedSecurity.BlockPushes = *sp.BlockPushes
		repo.AdvancedSecurity.BlockPushesKnown = true
	}
	if cs := entry.CodeSecurityFeatures; cs != nil {
		repo.AdvancedSecurity.CodeSecurity = cs.CodeSecurityEnabled != nil && *cs.CodeSecurityEnabled
		repo.AdvancedSecurity.CodeQL = cs.CodeQLEnabled != nil && *cs.CodeQLEnabled
		repo.AdvancedSecurity.DependencyScanning = cs.DependencyScanningInjectionEnabled != nil && *cs.DependencyScanningInjectionEnabled
	}
	repo.Available["advancedSecurity"] = true
}
