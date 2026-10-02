package scm

// GitNamespaceID is the Azure DevOps "Git Repositories" security namespace.
// Every permission below is a bit in its access control entries.
const GitNamespaceID = "2e9eb7ed-3c0a-47d4-87c1-0ffdd275fd87"

// GitPermission is one bit of the Git Repositories namespace, named as the
// namespace names it.
type GitPermission struct {
	Bit  int64
	Name string
	// DisplayName is the label the Azure DevOps security page shows, which
	// is what an operator searches for when acting on a finding.
	DisplayName string
}

// GitPermissions is the namespace's action table, as Microsoft documents it
// (Security namespace and permission reference) and as
// GET _apis/securitynamespaces/2e9eb7ed-... returns it.
//
// It lives here, beside the snapshot, because its names are snapshot
// vocabulary: Permissions.EveryoneGrants records them, and the configuration
// validates everyoneAllowedPermissions against them at startup rather than
// letting a typo silently allow nothing. The fetcher reads the live table at
// scan time and warns when the organization disagrees with this one.
var GitPermissions = []GitPermission{
	{1, "Administer", "Administer"},
	{2, "GenericRead", "Read"},
	{4, "GenericContribute", "Contribute"},
	{8, "ForcePush", "Force push (rewrite history and delete branches)"},
	{16, "CreateBranch", "Create branch"},
	{32, "CreateTag", "Create tag"},
	{64, "ManageNote", "Manage notes"},
	{128, "PolicyExempt", "Bypass policies when pushing"},
	{256, "CreateRepository", "Create repository"},
	{512, "DeleteRepository", "Delete or disable repository"},
	{1024, "RenameRepository", "Rename repository"},
	{2048, "EditPolicies", "Edit policies"},
	{4096, "RemoveOthersLocks", "Remove others' locks"},
	{8192, "ManagePermissions", "Manage permissions"},
	{16384, "PullRequestContribute", "Contribute to pull requests"},
	{32768, "PullRequestBypassPolicy", "Bypass policies when completing pull requests"},
	{65536, "ViewAdvSecAlerts", "Advanced Security: view alerts"},
	{131072, "DismissAdvSecAlerts", "Advanced Security: manage and dismiss alerts"},
	{262144, "ManageAdvSecScanning", "Advanced Security: manage settings"},
}

// GitPermissionNamed returns the permission with the given name.
func GitPermissionNamed(name string) (GitPermission, bool) {
	for _, p := range GitPermissions {
		if p.Name == name {
			return p, true
		}
	}
	return GitPermission{}, false
}
