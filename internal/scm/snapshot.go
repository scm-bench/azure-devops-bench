// Package scm defines the platform-neutral snapshot that fetchers produce and
// policies consume. Nothing in this package talks HTTP: a fetcher fills these
// structs in, they are marshalled to JSON, and every rule decision is made by
// Rego reading that JSON. Keeping the shape stable is what lets a snapshot be
// captured once and re-evaluated later, offline.
//
// The shape is the family's SCM snapshot schema, version 2, shared with
// bitbucket-bench by copy rather than by import. Fields marked "Azure DevOps"
// below are additive: bitbucket-bench ignores them, and they exist because
// Azure DevOps answers questions Bitbucket cannot (who may bypass a policy,
// who may delete a repository) or phrases one differently (branch protection
// that emerges from required policies rather than being declared).
package scm

import "time"

// SchemaVersion is bumped whenever the snapshot shape changes, and a reader
// refuses any version it was not built for.
//
// The weaker rule — bump only when a policy would *misread* the older shape —
// was tempting for additive fields, since a rule that finds a new key absent
// can report MANUAL and carry on. That is a graceful degradation, and it is
// the wrong default for an audit tool: the report would look like a scan of
// the instance while quietly being a scan of what an old file happened to
// record, and the reader has no way to tell those apart. Refusing is louder,
// costs one re-capture, and cannot be mistaken for a result.
const SchemaVersion = "2"

// PlatformAzureDevOps is the platform identifier this bench writes into
// Metadata.Platform and that every bundled control declares.
const PlatformAzureDevOps = "azure-devops"

// Deployment kinds recorded in Metadata.Deployment.
const (
	// DeploymentServices is Azure DevOps Services (dev.azure.com or
	// *.visualstudio.com).
	DeploymentServices = "services"
	// DeploymentServer is a self-hosted Azure DevOps Server collection, where
	// the Graph, user-entitlement and Advanced Security APIs do not exist.
	DeploymentServer = "server"
)

// Snapshot is the complete, normalized view of an SCM instance.
type Snapshot struct {
	SchemaVersion string       `json:"schemaVersion"`
	Metadata      Metadata     `json:"metadata"`
	Organization  Organization `json:"organization"`
	Projects      []Project    `json:"projects,omitempty"`
}

// Metadata records how and when the snapshot was captured.
type Metadata struct {
	Tool        string    `json:"tool"`
	ToolVersion string    `json:"toolVersion"`
	Platform    string    `json:"platform"`
	BaseURL     string    `json:"baseUrl"`
	GeneratedAt time.Time `json:"generatedAt"`
	// Warnings collects instance-wide fetch problems (permission denied on an
	// admin endpoint, an API missing on Azure DevOps Server, ...). Rules turn
	// the corresponding gaps into MANUAL rather than FAIL.
	Warnings []string `json:"warnings,omitempty"`

	// Unlisted names the projects whose repositories could not be listed.
	// Their repositories are not in the snapshot at all, so no rule can
	// report them MANUAL: the gap is only visible here, and a scan with one
	// is incomplete — it exits 2 unless scan.allowIncomplete accepts it.
	Unlisted []string `json:"unlisted,omitempty"`

	// Azure DevOps: services or server.
	Deployment string `json:"deployment,omitempty"`
	// Azure DevOps: the REST api-version the core APIs answered to. Server
	// collections are negotiated down from 7.1, and a capture says which one
	// it was taken with.
	APIVersion string `json:"apiVersion,omitempty"`
	// Azure DevOps: "pat" or "entra" — how the scan authenticated, never the
	// credential.
	AuthMethod string `json:"authMethod,omitempty"`
}

// Organization is the instance-level view: who administers it and who can log in.
type Organization struct {
	// Admins holds the principals granted organization administration as
	// granted — groups appear as groups. On Azure DevOps these are the direct
	// members of Project Collection Administrators.
	Admins []PrincipalPermission `json:"admins,omitempty"`
	// EffectiveAdmins is the same set with groups expanded to the people in
	// them, which is what an administrator count has to be based on.
	EffectiveAdmins EffectivePrincipals `json:"effectiveAdmins"`
	// Users is the user directory, when readable.
	Users []User `json:"users,omitempty"`
	// Available marks which instance-level fetches succeeded.
	Available map[string]bool `json:"available"`
	// Errors records why an organization-level fetch failed.
	Errors []string `json:"errors,omitempty"`

	// RepositoryCreators is Azure DevOps-only: per project, who holds "Create
	// repository" beyond the project's and the organization's administrators.
	RepositoryCreators []ProjectPrincipals `json:"repositoryCreators,omitempty"`
}

// ProjectPrincipals is a principal set scoped to one project.
type ProjectPrincipals struct {
	Project    string              `json:"project"`
	Principals EffectivePrincipals `json:"principals"`
	// AdminsExact is true when the administrators taken out of Principals
	// were themselves fully known. Principals.Complete says whether everyone
	// in the set was seen; this says whether everyone who should have been
	// removed from it was. A count is a lower bound only with both.
	AdminsExact bool `json:"adminsExact"`
}

// User is a directory entry.
type User struct {
	Name         string `json:"name"`
	DisplayName  string `json:"displayName,omitempty"`
	EmailAddress string `json:"emailAddress,omitempty"`
	// Active is false for an account the platform has deactivated.
	Active bool `json:"active"`
	// Licensed is true when the account can sign in and use the platform: on
	// Azure DevOps, an entitlement whose access level status is not none,
	// disabled or deleted. Licensed users are CIS-1.3.1's population — the
	// account set the organization pays for and an attacker can use.
	Licensed bool `json:"licensed"`
	// CreatedEpoch is account creation time in Unix seconds; 0 is unknown.
	CreatedEpoch int64 `json:"createdEpoch"`
	// AgeDays is days since CreatedEpoch at capture time; -1 when unknown.
	// It is what tells a dormant account that never signed in from one
	// created this morning.
	AgeDays int `json:"ageDays"`
	// NeverSignedIn is true only when the platform states the account has
	// never authenticated — Azure DevOps reports a last access date of
	// 0001-01-01 or a pending status. LastActivityEpoch == 0 without it still
	// means "unknown", never "never".
	NeverSignedIn bool `json:"neverSignedIn"`
	// LastActivityEpoch is the last access time in Unix seconds. 0 means the
	// platform did not report one, and rules must treat it as unknown.
	LastActivityEpoch int64 `json:"lastActivityEpoch"`
	// InactiveDays is derived from LastActivityEpoch at capture time.
	// -1 means unknown.
	InactiveDays int `json:"inactiveDays"`

	// Azure DevOps: the access level (license) name, e.g. "express" (Basic)
	// or "stakeholder", and whether the account is a guest in the directory.
	AccessLevel string `json:"accessLevel,omitempty"`
	Guest       bool   `json:"guest,omitempty"`
}

// Project is a grouping of repositories: a Bitbucket project, an Azure DevOps
// project.
type Project struct {
	Key          string       `json:"key"`
	Name         string       `json:"name"`
	Type         string       `json:"type,omitempty"`
	Public       bool         `json:"public"`
	Permissions  Permissions  `json:"permissions"`
	Repositories []Repository `json:"repositories,omitempty"`

	// Azure DevOps: the project ID and its visibility as reported ("private"
	// or "public"); empty when the API did not report one.
	ID         string `json:"id,omitempty"`
	Visibility string `json:"visibility,omitempty"`
}

// Repository is a single repository plus every setting the rules need.
type Repository struct {
	Slug       string `json:"slug"`
	Name       string `json:"name"`
	ProjectKey string `json:"projectKey"`
	// FullName is "PROJECT/name" and is what reports show.
	FullName string `json:"fullName"`
	Public   bool   `json:"public"`
	// Archived is true for a repository no change can reach. Azure DevOps has
	// no archive; a disabled repository is the analogue and sets both this
	// and Disabled. Change-related controls report NA on it.
	Archived bool `json:"archived"`
	Forkable bool `json:"forkable"`
	// DefaultBranch is the full ref ("refs/heads/main"); DefaultBranchDisplay
	// is the short form ("main"). Empty for an empty repository.
	DefaultBranch        string `json:"defaultBranch"`
	DefaultBranchDisplay string `json:"defaultBranchDisplay"`
	// Empty is decided from the branch list (no branches ⇒ empty), never from
	// a configured default-branch name.
	Empty bool `json:"empty"`

	PullRequestSettings PullRequestSettings `json:"pullRequestSettings"`
	BranchRestrictions  []BranchRestriction `json:"branchRestrictions,omitempty"`
	RequiredBuilds      []RequiredBuild     `json:"requiredBuilds,omitempty"`
	Hooks               []Hook              `json:"hooks,omitempty"`
	Branches            []Branch            `json:"branches,omitempty"`
	Files               Files               `json:"files"`
	Permissions         Permissions         `json:"permissions"`
	// Admins is the set of people designated to administer this repository:
	// repository- and project-level administrators with groups expanded,
	// EXCLUDING organization administrators, who can administer everything
	// and are counted by CIS-1.3.3 instead. Counting them here made CIS-1.3.7
	// pass on every repository of any organization that satisfies CIS-1.3.3.
	Admins EffectivePrincipals `json:"admins"`

	// Available marks which per-repository fetches succeeded. A missing or
	// false entry means "unknown", and rules downgrade to MANUAL.
	Available map[string]bool `json:"available"`
	// Errors records why a fetch failed, for the report's manual guidance.
	Errors []string `json:"errors,omitempty"`

	// Azure DevOps: the repository ID, whether it is a fork and of what, and
	// whether it is disabled.
	ID               string `json:"id,omitempty"`
	Fork             bool   `json:"fork,omitempty"`
	ParentRepository string `json:"parentRepository,omitempty"`
	Disabled         bool   `json:"disabled,omitempty"`
	// Azure DevOps: who holds each bypass on the default branch, groups
	// expanded. Push is "Bypass policies when pushing", PullRequest is "Bypass
	// policies when completing pull requests".
	Bypass Bypass `json:"bypass"`
	// Azure DevOps: holders of "Force push (rewrite history and delete
	// branches)" on the default branch, as granted, before any policy is
	// taken into account.
	ForcePushers EffectivePrincipals `json:"forcePushers"`
	// Azure DevOps: holders of "Delete repository" on this repository,
	// excluding organization administrators, like Admins.
	Deleters EffectivePrincipals `json:"deleters"`
	// Azure DevOps: GitHub Advanced Security for Azure DevOps enablement.
	AdvancedSecurity AdvancedSecurity `json:"advancedSecurity"`
	// Azure DevOps: every enabled policy that applies to the default branch,
	// required or not, as evidence of what the derived settings came from.
	Policies []Policy `json:"policies,omitempty"`
}

// Bypass names who can get past the branch policies on the default branch.
type Bypass struct {
	Push        EffectivePrincipals `json:"push"`
	PullRequest EffectivePrincipals `json:"pullRequest"`
	// Admins is the part of Push ∪ PullRequest made of administrators:
	// organization administrators and holders of Manage permissions on the
	// repository. CIS-1.1.14 asks whether protection binds them.
	Admins EffectivePrincipals `json:"admins"`
}

// AdvancedSecurity is the GitHub Advanced Security enablement of a repository.
type AdvancedSecurity struct {
	// SecretProtection is true when secret scanning is enabled.
	SecretProtection bool `json:"secretProtection"`
	// BlockPushes is true when pushes containing secrets are rejected.
	BlockPushes bool `json:"blockPushes"`
	// BlockPushesKnown distinguishes "pushes are not blocked" from "the
	// platform returned no value", which Azure DevOps does whenever the
	// request did not ask for every property.
	BlockPushesKnown bool `json:"blockPushesKnown"`
	CodeSecurity     bool `json:"codeSecurity"`
	CodeQL           bool `json:"codeQL"`
	// DependencyScanning is dependency scanning injection.
	DependencyScanning bool `json:"dependencyScanning"`
}

// Policy is one Azure DevOps policy configuration applying to the default
// branch, kept as evidence.
type Policy struct {
	ID       int    `json:"id"`
	Type     string `json:"type"`
	TypeID   string `json:"typeId"`
	Blocking bool   `json:"blocking"`
	// Scope is PROJECT for a cross-repository policy (no repository in its
	// scope), REPOSITORY otherwise.
	Scope string `json:"scope,omitempty"`
	// MatchKind is how its scope matched the branch: Exact, Prefix or
	// DefaultBranch.
	MatchKind string `json:"matchKind,omitempty"`
}

// PullRequestSettings mirrors the repository's pull request merge checks. On
// Azure DevOps there are no repository-level pull request settings: these are
// projected from the required policies that apply to the default branch.
type PullRequestSettings struct {
	// RequiredApprovers counts independent approvals: on Azure DevOps the
	// highest minimum-reviewer count over the required policies, less one for
	// a policy that lets the author's own vote count.
	RequiredApprovers        int  `json:"requiredApprovers"`
	RequiredAllApprovers     bool `json:"requiredAllApprovers"`
	RequiredAllTasksComplete bool `json:"requiredAllTasksComplete"`
	RequiredSuccessfulBuilds int  `json:"requiredSuccessfulBuilds"`
	// UnapproveOnUpdate drops existing approvals when the source branch moves.
	UnapproveOnUpdate bool            `json:"unapproveOnUpdate"`
	MergeStrategies   []MergeStrategy `json:"mergeStrategies,omitempty"`
	DefaultStrategy   string          `json:"defaultStrategy,omitempty"`

	// Azure DevOps: the raw minimum-reviewer settings behind
	// RequiredApprovers and UnapproveOnUpdate.
	MinimumApproverCount        int  `json:"minimumApproverCount,omitempty"`
	AuthorApprovalCounts        bool `json:"authorApprovalCounts,omitempty"`
	LastPusherCannotApprove     bool `json:"lastPusherCannotApprove,omitempty"`
	ResetRejectionsOnSourcePush bool `json:"resetRejectionsOnSourcePush,omitempty"`
	RequireVoteOnLastIteration  bool `json:"requireVoteOnLastIteration,omitempty"`
	AllowDownvotes              bool `json:"allowDownvotes,omitempty"`
	// WorkItemLinkingRequired is a required work item linking policy.
	WorkItemLinkingRequired bool `json:"workItemLinkingRequired,omitempty"`
	// RequiredReviewers lists the automatically included reviewer policies.
	RequiredReviewers []RequiredReviewer `json:"requiredReviewers,omitempty"`
}

// RequiredReviewer is one "automatically included reviewers" policy.
type RequiredReviewer struct {
	ID               int      `json:"id"`
	Blocking         bool     `json:"blocking"`
	MinimumApprovers int      `json:"minimumApprovers,omitempty"`
	PathFilters      []string `json:"pathFilters,omitempty"`
	Reviewers        []string `json:"reviewers,omitempty"`
}

// MergeStrategy is one selectable merge behaviour, e.g. "no-ff" or "squash".
type MergeStrategy struct {
	ID      string `json:"id"`
	Name    string `json:"name,omitempty"`
	Enabled bool   `json:"enabled"`
}

// Branch restriction types.
const (
	RestrictionReadOnly        = "read-only"         // "Prevent all changes"
	RestrictionNoDeletes       = "no-deletes"        // "Prevent deletion"
	RestrictionFastForwardOnly = "fast-forward-only" // "Prevent rewriting history"
	RestrictionPullRequestOnly = "pull-request-only" // "Prevent changes without a pull request"
)

// BranchRestriction is one branch permission entry. On Azure DevOps none is
// declared: the fetcher derives them from the required policies and the
// branch's access control list, and marks them Derived.
type BranchRestriction struct {
	ID          int    `json:"id"`
	Type        string `json:"type"`
	MatcherID   string `json:"matcherId"`
	MatcherType string `json:"matcherType"`
	MatcherText string `json:"matcherText,omitempty"`
	// Scope is REPOSITORY or PROJECT.
	Scope string `json:"scope,omitempty"`
	// MatchesDefaultBranch is resolved by the fetcher. Policies read this
	// boolean instead of re-implementing matching in Rego.
	MatchesDefaultBranch bool `json:"matchesDefaultBranch"`
	// MatchUnknown is true when the fetcher could not resolve whether the
	// restriction covers the default branch; MatchesDefaultBranch is false
	// then, and a rule whose only candidates are unknown reports MANUAL.
	MatchUnknown bool `json:"matchUnknown,omitempty"`
	// Exempt principals can bypass the restriction, as granted — groups
	// appear as groups.
	ExemptUsers      []string `json:"exemptUsers,omitempty"`
	ExemptGroups     []string `json:"exemptGroups,omitempty"`
	ExemptAccessKeys int      `json:"exemptAccessKeys,omitempty"`
	// ExemptPrincipals is the same set with groups expanded to their members,
	// which is what deciding whether a restriction still binds has to be based
	// on. Complete is false when a group could not be expanded, or the access
	// control list could not be read, making the set a lower bound.
	ExemptPrincipals EffectivePrincipals `json:"exemptPrincipals"`
	// ExemptAccessKeyIDs identifies the keys ExemptAccessKeys counts
	// (Bitbucket only).
	ExemptAccessKeyIDs []int `json:"exemptAccessKeyIds,omitempty"`

	// Azure DevOps: the restriction was synthesized rather than read, and
	// DerivedFrom names the policies and permission bits behind it.
	Derived     bool     `json:"derived,omitempty"`
	DerivedFrom []string `json:"derivedFrom,omitempty"`
}

// RequiredBuild is one required check before merge. On Azure DevOps it is a
// required build validation or status policy.
type RequiredBuild struct {
	ID                   int      `json:"id"`
	BuildParentKeys      []string `json:"buildParentKeys,omitempty"`
	MatcherID            string   `json:"matcherId"`
	MatcherType          string   `json:"matcherType"`
	MatcherText          string   `json:"matcherText,omitempty"`
	ExemptMatcherID      string   `json:"exemptMatcherId,omitempty"`
	MatchesDefaultBranch bool     `json:"matchesDefaultBranch"`
	MatchUnknown         bool     `json:"matchUnknown,omitempty"`

	// Azure DevOps: "build" or "status", the check's name ("genre/name" for a
	// status), whether it gates only some pull requests (a path filter, or a
	// status that applies only once posted), and whether it expires when the
	// target branch moves.
	Kind                  string   `json:"kind,omitempty"`
	Name                  string   `json:"name,omitempty"`
	Conditional           bool     `json:"conditional,omitempty"`
	PathFilters           []string `json:"pathFilters,omitempty"`
	ExpiresOnTargetUpdate bool     `json:"expiresOnTargetUpdate,omitempty"`
}

// Hook is a repository hook (pre- or post-receive), enabled or not. Azure
// DevOps has none; the type stays because the shape is shared.
type Hook struct {
	Key        string `json:"key"`
	Name       string `json:"name,omitempty"`
	Type       string `json:"type,omitempty"`
	Enabled    bool   `json:"enabled"`
	Configured bool   `json:"configured"`
	Scope      string `json:"scope,omitempty"`
}

// Branch is a ref plus the age of its tip, used to find abandoned branches.
type Branch struct {
	ID           string `json:"id"`
	DisplayID    string `json:"displayId"`
	IsDefault    bool   `json:"isDefault"`
	LatestCommit string `json:"latestCommit,omitempty"`
	// LatestCommitEpoch is Unix seconds; 0 when the commit date was not fetched.
	LatestCommitEpoch int64 `json:"latestCommitEpoch"`
	// AgeDays is days since the tip commit at capture time; -1 when unknown.
	AgeDays int `json:"ageDays"`
}

// Files records the outcome of probing the default branch for known paths.
type Files struct {
	// SecurityPolicyPaths lists the security policy files that were found.
	SecurityPolicyPaths []string `json:"securityPolicyPaths,omitempty"`
	// Probed lists every path that was checked, so an empty result is
	// distinguishable from "we never looked".
	Probed []string `json:"probed,omitempty"`
}

// Permissions is a grant table for a project or repository.
type Permissions struct {
	Users  []PrincipalPermission `json:"users,omitempty"`
	Groups []PrincipalPermission `json:"groups,omitempty"`
	// DefaultPermission is the permission handed to every authenticated user,
	// or "" when none is granted.
	DefaultPermission string `json:"defaultPermission,omitempty"`
	// DefaultPermissionKnown distinguishes "no default permission is granted"
	// from "the probe could not run", which look identical in the field above.
	// On Azure DevOps it is true once the access control list has been read
	// for the groups every member belongs to.
	DefaultPermissionKnown bool `json:"defaultPermissionKnown"`
	// PublicAccess is true when anonymous users can read.
	PublicAccess bool `json:"publicAccess"`

	// Azure DevOps: Git permissions held, on this repository, by the groups
	// every member of the organization or project belongs to (Project
	// Collection Valid Users, Project Valid Users), one entry per group and
	// permission name. Read access is included; the rule decides what is
	// too much.
	EveryoneGrants []PrincipalPermission `json:"everyoneGrants,omitempty"`
}

// PrincipalPermission is one grant: a user or group and the permission held.
type PrincipalPermission struct {
	Name        string `json:"name"`
	DisplayName string `json:"displayName,omitempty"`
	Type        string `json:"type"` // "user", "group" or "service"
	Permission  string `json:"permission"`
	Active      bool   `json:"active,omitempty"`
}

// EffectivePrincipals is a resolved principal set plus a completeness flag.
// Complete is false when a group could not be expanded, which means the set is
// a lower bound and rules should report MANUAL instead of a hard verdict.
type EffectivePrincipals struct {
	// Users are the people in the set; Count is how many.
	Users  []string `json:"users,omitempty"`
	Groups []string `json:"groups,omitempty"`
	Count  int      `json:"count"`
	// Complete is false when any group behind the set could not be fully
	// expanded — an Entra ID or Active Directory group above all, whose
	// members Azure DevOps only partly knows.
	Complete bool `json:"complete"`
	// ServiceIdentities is Azure DevOps-only: build services, service
	// principals and managed identities in the set. They are not in Count,
	// because a count of administrators is a count of people; a rule about
	// who can bypass a policy reads them alongside Users.
	ServiceIdentities []string `json:"serviceIdentities,omitempty"`
	// Everyone is Azure DevOps-only: the set includes a group every member of
	// the organization or project belongs to (Project Collection Valid Users,
	// Project Valid Users). It is not expanded — its members are everyone —
	// and a rule must read it as "every member", never as the handful of
	// names beside it.
	Everyone bool `json:"everyone,omitempty"`
}
