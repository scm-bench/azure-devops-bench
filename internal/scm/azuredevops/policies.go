package azuredevops

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/scm-bench/azure-devops-bench/internal/scm"
)

// Branch policy type IDs, as Microsoft's Terraform provider and Azure CLI
// extension name them and the REST samples carry them.
const (
	typeMinReviewers        = "fa4e907d-c16b-4a4c-9dfa-4906e5d171dd"
	typeBuild               = "0609b952-1397-4640-95ec-e00a01b2c241"
	typeRequiredReviewers   = "fd2167ab-b0be-447a-8ec8-39368250530e"
	typeWorkItemLinking     = "40e92b44-2fe1-4dd6-b3d8-74a9c21d0c6e"
	typeCommentRequirements = "c6a1889d-b943-4856-b76f-9e46bb6b0df2"
	typeMergeStrategy       = "fa4e907d-c16b-4a4c-9dfa-4916e5d171ab"
	typeStatus              = "cbdc66da-9728-4af8-aada-9a5a32e4a226"
)

// branchPolicyTypes are the policy types that protect a branch. A required one
// of these is what makes Azure Repos refuse direct pushes and deletion.
//
// Repository-wide push policies (file size, path length, reserved names, case
// enforcement) are deliberately absent: they apply at push time to every
// branch and do not make any branch require a pull request. A type this list
// does not know is not counted as protection either — an unknown blocking
// type is reported, and the branch is judged on the types whose effect is
// documented, which can only under-state protection, never invent it.
var branchPolicyTypes = map[string]string{
	typeMinReviewers:        "Minimum number of reviewers",
	typeBuild:               "Build",
	typeRequiredReviewers:   "Required reviewers",
	typeWorkItemLinking:     "Work item linking",
	typeCommentRequirements: "Comment requirements",
	typeMergeStrategy:       "Require a merge strategy",
	typeStatus:              "Status",
}

// policy is one decoded policy configuration.
type policy struct {
	api      apiPolicy
	settings policySettings
	typeID   string
	// scope and matchKind describe the scope element that made it apply.
	scope     string
	matchKind string
}

func (p policy) known() bool { return branchPolicyTypes[p.typeID] != "" }

func (p policy) typeName() string {
	if name := branchPolicyTypes[p.typeID]; name != "" {
		return name
	}
	if p.api.Type.DisplayName != "" {
		return p.api.Type.DisplayName
	}
	return p.typeID
}

func (p policy) describe() string {
	state := "optional"
	if p.api.IsBlocking {
		state = "required"
	}
	where := ""
	if p.scope == "PROJECT" {
		where = ", project-wide"
	}
	return fmt.Sprintf("policy %d %s (%s%s)", p.api.ID, p.typeName(), state, where)
}

func decodePolicy(api apiPolicy) (policy, error) {
	p := policy{api: api, typeID: strings.ToLower(strings.TrimSpace(api.Type.ID))}
	if len(api.Settings) > 0 && string(api.Settings) != "null" {
		if err := json.Unmarshal(api.Settings, &p.settings); err != nil {
			return p, fmt.Errorf("policy %d settings: %w", api.ID, err)
		}
	}
	return p, nil
}

// scopeMatch is the outcome of evaluating a policy's scope locally.
type scopeMatch int

const (
	scopeMatches scopeMatch = iota
	scopeMisses
	// scopeUnknown is a scope this bench cannot evaluate: an unfamiliar
	// matchKind, or a ref-less element (a repository-wide setting).
	scopeUnknown
)

// matchScope evaluates a policy's scope against one repository's branch,
// following the documented semantics: the scope is an OR list; a null
// repositoryId means every repository in the project; Exact and Prefix
// compare the ref case-sensitively; DefaultBranch matches the default branch
// of every repository it covers.
func matchScope(scopes []policyScope, repoID, ref string) (scopeMatch, string, string) {
	if len(scopes) == 0 {
		return scopeUnknown, "", ""
	}
	result := scopeMisses
	for _, s := range scopes {
		repoMatches := s.RepositoryID == nil || strings.EqualFold(strings.TrimSpace(*s.RepositoryID), repoID)
		scope := "REPOSITORY"
		if s.RepositoryID == nil {
			scope = "PROJECT"
		}
		kind := strings.ToLower(strings.TrimSpace(s.MatchKind))
		switch kind {
		case "defaultbranch":
			if repoMatches {
				return scopeMatches, scope, "DefaultBranch"
			}
		case "exact", "prefix":
			if s.RefName == nil {
				result = scopeUnknown
				continue
			}
			refName := *s.RefName
			hit := (kind == "exact" && refName == ref) || (kind == "prefix" && strings.HasPrefix(ref, refName))
			if repoMatches && hit {
				label := "Exact"
				if kind == "prefix" {
					label = "Prefix"
				}
				return scopeMatches, scope, label
			}
		default:
			result = scopeUnknown
		}
	}
	return result, "", ""
}

// fetchProjectPolicies reads every policy configuration in a project, once,
// for the cross-check below.
func (f *Fetcher) fetchProjectPolicies(ctx context.Context, projectID string) ([]policy, error) {
	apis, err := getAll[apiPolicy](ctx, f.client, ServiceCore,
		"/"+url.PathEscape(projectID)+"/_apis/policy/configurations",
		url.Values{"api-version": []string{f.client.APIVersion()}},
		pageOptions{top: 100, fullPageNeedsToken: true})
	if err != nil {
		return nil, err
	}
	out := make([]policy, 0, len(apis))
	for _, a := range apis {
		p, err := decodePolicy(a)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

// fetchBranchPolicies returns the enabled policies that apply to a
// repository's branch.
//
// The server answers the question: GET git/policy/configurations with a
// repository and a ref returns "all policy configurations that apply to a
// particular branch in a repository", project-wide and prefix scopes included,
// which is the resolution this bench would otherwise have to re-implement.
// The answer is then checked against the documented scope semantics both
// ways — every returned policy must match locally, and every policy in the
// project that matches locally must have been returned. A disagreement means
// either the documentation or the server is not what this bench assumes, and
// the repository's policy-derived verdicts become MANUAL rather than resting
// on whichever side happens to be wrong.
func (f *Fetcher) fetchBranchPolicies(ctx context.Context, projectID, repoID, ref string, project []policy, projectKnown bool) ([]policy, error) {
	query := url.Values{
		"repositoryId": []string{repoID},
		"refName":      []string{ref},
		"api-version":  []string{f.client.APIVersion()},
	}
	apis, err := getAll[apiPolicy](ctx, f.client, ServiceCore,
		"/"+url.PathEscape(projectID)+"/_apis/git/policy/configurations", query,
		pageOptions{top: 100, fullPageNeedsToken: true})
	if err != nil {
		return nil, err
	}

	returned := map[int]bool{}
	var out []policy
	var contradictions []string
	for _, a := range apis {
		p, err := decodePolicy(a)
		if err != nil {
			return nil, err
		}
		returned[a.ID] = true
		if !a.IsEnabled || a.IsDeleted {
			continue
		}
		match, scope, kind := matchScope(p.settings.Scope, repoID, ref)
		p.scope, p.matchKind = scope, kind
		if match == scopeMisses && p.known() {
			contradictions = append(contradictions, fmt.Sprintf("policy %d was returned for %s but its scope does not cover it", a.ID, ref))
		}
		if match == scopeUnknown && !p.known() {
			// A repository-wide setting (file size, case enforcement): it
			// applies to every branch and protects none.
			p.scope = "REPOSITORY"
		}
		out = append(out, p)
	}

	if projectKnown {
		for _, p := range project {
			if !p.known() || !p.api.IsEnabled || p.api.IsDeleted || returned[p.api.ID] {
				continue
			}
			if match, _, _ := matchScope(p.settings.Scope, repoID, ref); match == scopeMatches {
				contradictions = append(contradictions, fmt.Sprintf("%s covers %s but was not returned for it", p.describe(), ref))
			}
		}
	}
	if len(contradictions) > 0 {
		sort.Strings(contradictions)
		return nil, fmt.Errorf("the policies Azure DevOps reports for this branch disagree with their own scopes (%s); "+
			"policy-based controls report MANUAL rather than trust either side", strings.Join(contradictions, "; "))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].api.ID < out[j].api.ID })
	return out, nil
}

// fetchRepositoryPolicies returns whether any required branch policy exists
// anywhere in a repository — the one question that can still be answered
// when the default branch cannot be resolved. None at all means no branch of
// the repository is protected, which is conclusive whatever its default
// branch is.
func (f *Fetcher) fetchRepositoryPolicies(ctx context.Context, projectID, repoID string) ([]policy, error) {
	query := url.Values{
		"repositoryId": []string{repoID},
		"api-version":  []string{f.client.APIVersion()},
	}
	apis, err := getAll[apiPolicy](ctx, f.client, ServiceCore,
		"/"+url.PathEscape(projectID)+"/_apis/git/policy/configurations", query,
		pageOptions{top: 100, fullPageNeedsToken: true})
	if err != nil {
		return nil, err
	}
	var out []policy
	for _, a := range apis {
		p, err := decodePolicy(a)
		if err != nil {
			return nil, err
		}
		if a.IsEnabled && !a.IsDeleted {
			out = append(out, p)
		}
	}
	return out, nil
}

// requiredBranchPolicies are the enabled, blocking policies of a known branch
// type.
func requiredBranchPolicies(ps []policy) []policy {
	var out []policy
	for _, p := range ps {
		if p.api.IsBlocking && p.known() {
			out = append(out, p)
		}
	}
	return out
}

// Merge strategy IDs, in the family's vocabulary, so one
// nonLinearMergeStrategies list means the same thing in every bench.
const (
	mergeNoFastForward = "no-ff"          // "Basic merge (no fast-forward)"
	mergeSquash        = "squash"         // "Squash merge"
	mergeRebaseFF      = "rebase-ff-only" // "Rebase and fast-forward"
	mergeRebaseMerge   = "rebase-no-ff"   // "Semi-linear merge" (rebase with merge commit)
)

var mergeStrategyNames = map[string]string{
	mergeNoFastForward: "Basic merge (no fast-forward)",
	mergeSquash:        "Squash merge",
	mergeRebaseFF:      "Rebase and fast-forward",
	mergeRebaseMerge:   "Semi-linear merge",
}

// derivePullRequestSettings projects the required policies applying to the
// default branch onto the family's pull request settings.
func derivePullRequestSettings(applicable []policy) scm.PullRequestSettings {
	var s scm.PullRequestSettings
	allowed := map[string]bool{mergeNoFastForward: true, mergeSquash: true, mergeRebaseFF: true, mergeRebaseMerge: true}

	for _, p := range applicable {
		if !p.api.IsBlocking {
			if p.typeID == typeRequiredReviewers {
				s.RequiredReviewers = append(s.RequiredReviewers, requiredReviewer(p))
			}
			continue
		}
		st := p.settings
		switch p.typeID {
		case typeMinReviewers:
			count := int(st.MinimumApproverCount)
			// The author's own approval is not an independent one. A policy
			// letting it count needs one approval fewer from anybody else,
			// so two approvers with "Allow requestors to approve their own
			// changes" is one reviewer and the author.
			independent := count
			if st.CreatorVoteCounts {
				independent--
			}
			if independent < 0 {
				independent = 0
			}
			// All required policies must pass, so the strictest one binds.
			if independent > s.RequiredApprovers {
				s.RequiredApprovers = independent
			}
			if count > s.MinimumApproverCount {
				s.MinimumApproverCount = count
			}
			s.AuthorApprovalCounts = s.AuthorApprovalCounts || bool(st.CreatorVoteCounts)
			// Only "Reset all approval votes" dismisses an approval.
			// "Reset all code reviewer votes" on rejections leaves every
			// approval standing, so it does not count here.
			s.UnapproveOnUpdate = s.UnapproveOnUpdate || bool(st.ResetOnSourcePush)
			s.ResetRejectionsOnSourcePush = s.ResetRejectionsOnSourcePush || bool(st.ResetRejectionsOnSourcePush)
			s.RequireVoteOnLastIteration = s.RequireVoteOnLastIteration || bool(st.RequireVoteOnLastIteration)
			s.LastPusherCannotApprove = s.LastPusherCannotApprove || bool(st.BlockLastPusherVote)
			s.AllowDownvotes = s.AllowDownvotes || bool(st.AllowDownvotes)
		case typeCommentRequirements:
			s.RequiredAllTasksComplete = true
		case typeWorkItemLinking:
			s.WorkItemLinkingRequired = true
		case typeMergeStrategy:
			this := map[string]bool{
				mergeNoFastForward: bool(st.AllowNoFastForward),
				mergeSquash:        bool(st.AllowSquash) || bool(st.UseSquashMerge),
				mergeRebaseFF:      bool(st.AllowRebase),
				mergeRebaseMerge:   bool(st.AllowRebaseMerge),
			}
			// Every required merge-strategy policy must be satisfied, so
			// only the types all of them allow remain.
			for id := range allowed {
				allowed[id] = allowed[id] && this[id]
			}
		case typeRequiredReviewers:
			s.RequiredReviewers = append(s.RequiredReviewers, requiredReviewer(p))
		case typeBuild, typeStatus:
			if !checkConditional(p) {
				s.RequiredSuccessfulBuilds++
			}
		}
	}
	for _, id := range []string{mergeNoFastForward, mergeRebaseFF, mergeRebaseMerge, mergeSquash} {
		s.MergeStrategies = append(s.MergeStrategies, scm.MergeStrategy{ID: id, Name: mergeStrategyNames[id], Enabled: allowed[id]})
	}
	return s
}

func requiredReviewer(p policy) scm.RequiredReviewer {
	return scm.RequiredReviewer{
		ID:               p.api.ID,
		Blocking:         p.api.IsBlocking,
		MinimumApprovers: int(p.settings.MinimumApproverCount),
		PathFilters:      append([]string(nil), p.settings.FilenamePatterns...),
		Reviewers:        append([]string(nil), p.settings.RequiredReviewerIDs...),
	}
}

// checkConditional reports a build or status check that gates only some
// pull requests: one with a path filter, or a status policy that applies only
// once the status has been posted.
func checkConditional(p policy) bool {
	if len(p.settings.FilenamePatterns) > 0 {
		return true
	}
	if p.typeID == typeStatus && p.settings.PolicyApplicability != nil && int(*p.settings.PolicyApplicability) == 1 {
		return true
	}
	return false
}

// checkName names a build or status check the way Azure DevOps shows it.
func checkName(p policy) string {
	st := p.settings
	if p.typeID == typeStatus {
		if st.StatusGenre != "" {
			return st.StatusGenre + "/" + st.StatusName
		}
		return st.StatusName
	}
	if st.DisplayName != "" {
		return st.DisplayName
	}
	return fmt.Sprintf("build definition %d", int(st.BuildDefinitionID))
}

// deriveRequiredBuilds lists the required build and status checks.
func deriveRequiredBuilds(applicable []policy, ref, display string) []scm.RequiredBuild {
	var out []scm.RequiredBuild
	for _, p := range applicable {
		if !p.api.IsBlocking || (p.typeID != typeBuild && p.typeID != typeStatus) {
			continue
		}
		rb := scm.RequiredBuild{
			ID:                   p.api.ID,
			MatcherID:            ref,
			MatcherType:          "BRANCH",
			MatcherText:          display,
			MatchesDefaultBranch: true,
			Kind:                 "build",
			Name:                 checkName(p),
			Conditional:          checkConditional(p),
			PathFilters:          append([]string(nil), p.settings.FilenamePatterns...),
		}
		if p.typeID == typeStatus {
			rb.Kind = "status"
		} else {
			// "Build expiration": immediately when the target branch is
			// updated (queueOnSourceUpdateOnly false), after a set time if it
			// has been updated (true with a duration), or never (true with
			// zero). The mapping is Microsoft's CLI constraint read together
			// with the UI labels; it is evidence here, not a verdict.
			rb.ExpiresOnTargetUpdate = !(bool(p.settings.QueueOnSourceUpdateOnly) && float64(p.settings.ValidDuration) == 0)
			rb.BuildParentKeys = []string{fmt.Sprintf("%d", int(p.settings.BuildDefinitionID))}
		}
		out = append(out, rb)
	}
	return out
}

// policyEvidence keeps every applicable policy for the report.
func policyEvidence(applicable []policy) []scm.Policy {
	out := make([]scm.Policy, 0, len(applicable))
	for _, p := range applicable {
		out = append(out, scm.Policy{
			ID:        p.api.ID,
			Type:      p.typeName(),
			TypeID:    p.typeID,
			Blocking:  p.api.IsBlocking,
			Scope:     p.scope,
			MatchKind: p.matchKind,
		})
	}
	return out
}
