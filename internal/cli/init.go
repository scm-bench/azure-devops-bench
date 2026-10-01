package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/scm-bench/azure-devops-bench/internal/console"
)

// configTemplate is the file init writes. Every key is present with its
// default and a comment, because the file is how a user discovers what can be
// configured — a template that only shows two keys teaches two keys. Values
// match config.Default(); TestInitTemplateMatchesTheDefaults holds them
// together.
const configTemplate = `# azure-devops-bench configuration.
#
# scan finds this file on its own: azure-devops-bench.yaml (or
# .azure-devops-bench.yaml) in the working directory first, then config.yaml in
# the user config directory (AZURE_DEVOPS_BENCH_CONFIG_DIR, or the platform
# default). --config overrides the search, and every scan names the file it
# used on stderr. Every key is optional; an absent key keeps the default shown
# here. Maps merge with the defaults; lists replace them wholesale.
# A single run can override any key without touching the file:
#   azure-devops-bench scan --set scan.failOn=none

# Settings that describe the deployment rather than any one run.
scan:
  # Exit 1 when a failure at or above this severity exists:
  # high, medium, low, or none.
  failOn: high
  # Exit 1 when the score is below this; 0 disables.
  failUnder: 0
  # Exit 1 when more than this percent of automatable findings could not be
  # evaluated; -1 disables. Useful in CI so a token that lost a scope fails the
  # run instead of producing a high score from a small sample.
  maxManual: -1
  # How many repositories to fetch in parallel. Azure DevOps Services throttles
  # per identity; the scan honours Retry-After, but fewer in flight trips it
  # less.
  concurrency: 4
  # Per-request HTTP timeout.
  timeout: 30s
  # Abandon the scan after this long; 0s means no limit.
  maxDuration: 0s
  # A PEM bundle added to the system roots, for an Azure DevOps Server behind
  # an internal certificate authority. Prefer this to insecure.
  caFile: ""
  # Skip TLS certificate verification. Almost always caFile is the answer.
  insecure: false
  # Permit an http:// URL to a non-loopback host, sending the token in clear.
  allowPlaintext: false
  # Exit on the findings rather than with 2 when a project's repositories
  # could not be listed. The report says what was missed either way.
  allowIncomplete: false
  # What to show while scanning: full (every request), compact (one line),
  # or off (only the closing accounting line).
  progress: compact
  # Keep each scan's snapshot (0600, under the user config directory) so
  # scan --last can re-render it without another scan. The snapshot maps the
  # organization's weak points; false keeps it off disk.
  cache: true

# Numeric knobs the policies read. Uncomment to change.
#thresholds:
#  minApprovers: 2          # independent approvals a pull request must collect (CIS-1.1.3)
#  minRepositoryAdmins: 2   # fewer is a bus-factor risk (CIS-1.3.7)
#  minOrgAdmins: 2          # Project Collection Administrators lower bound (CIS-1.3.3)
#  maxOrgAdmins: 5          # ... and upper bound; 0 means unbounded
#  staleBranchDays: 90      # days untouched before a branch counts as abandoned (CIS-1.1.8)
#  maxStaleBranches: 0      # how many abandoned branches a repository may carry
#  inactiveUserDays: 90     # days without access before review (CIS-1.3.1)
#  maxBypassPrincipals: 0   # who may bypass policies or force push; -1 turns it off (CIS-1.1.5, 1.1.15-1.1.17)
#  maxRepositoryCreators: 0 # non-administrators per project who may create repositories (CIS-1.2.2)

# Status checks that verify commit signatures, as "genre/name" or "name"
# (CIS-1.1.12). Azure Repos cannot verify signatures itself, so until one is
# named here that control fails.
#signatureStatusChecks: [security/verify-signatures]

# Merge strategies that break linear history (CIS-1.1.13): no-ff is Basic
# merge, rebase-no-ff the semi-linear merge. ff has no Azure DevOps merge type;
# it is in the family's shared default.
#nonLinearMergeStrategies: [no-ff, rebase-no-ff, ff]

# Paths probed on the default branch for a security policy (CIS-1.2.1).
#securityPolicyPaths: [SECURITY.md, .github/SECURITY.md, docs/SECURITY.md, SECURITY.rst, SECURITY.txt, SECURITY]

# Git permissions the groups every member belongs to may hold (CIS-1.3.8).
#everyoneAllowedPermissions: [GenericRead]

# Service identities expected to hold a bypass, as the report prints them.
#allowedBypassPrincipals: []

# For organizations that intentionally publish code.
#allowPublicRepositories: false

# Drop disabled repositories from the scan.
#skipArchivedRepositories: true

# Accept findings your organization has decided to live with, for a stated
# reason and until a stated date. An accepted finding is still reported and
# still counts in the score; it just does not fail the run on scan.failOn (or,
# if MANUAL, count against scan.maxManual). It lapses after its expiry date.
# resources are globs over PROJECT/repository — * does not cross "/" — or
# "instance" for an organization-level control.
#exceptions:
#  - control: CIS-1.1.13
#    resources: [Fabrikam/legacy-*]
#    reason: Release tooling needs merge commits until the migration lands
#    owner: platform-team@example.com
#    expires: 2027-03-31

# Leave controls out of the run, or restrict the run to a list.
#exclude: [CIS-1.1.8]
#include: []
`

func newInitCommand() *cobra.Command {
	var path string

	cmd := &cobra.Command{
		Use:   "init",
		Short: "Write a commented azure-devops-bench.yaml into the working directory",
		Long: `Init writes a configuration template with every key present, commented, and
set to its default, so the file doubles as the documentation of what can be
configured. scan discovers it in the working directory without --config.

An existing file is never overwritten: a config that changes how an audit
judges an organization is not something a scaffolding command should replace.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// O_EXCL does the refusing atomically: stat-then-write would race,
			// and racing towards overwriting someone's thresholds is the worst
			// direction to race in.
			f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
			if err != nil {
				if os.IsExist(err) {
					return fmt.Errorf("%s already exists; edit it, or pass --path to write the template elsewhere", path)
				}
				return fmt.Errorf("create %s: %w", path, err)
			}
			if _, err := f.WriteString(configTemplate); err != nil {
				f.Close()
				return fmt.Errorf("write %s: %w", path, err)
			}
			if err := f.Close(); err != nil {
				return fmt.Errorf("write %s: %w", path, err)
			}

			stderr := cmd.ErrOrStderr()
			console.Writer{W: stderr, P: console.Painter{Enabled: isTerminal(stderr) && !hasNoColorEnv()}}.
				Line(console.Info, "wrote %s; scan will find it here without --config", path)
			return nil
		},
	}

	cmd.Flags().StringVar(&path, "path", "azure-devops-bench.yaml", "where to write the template")
	return cmd
}
