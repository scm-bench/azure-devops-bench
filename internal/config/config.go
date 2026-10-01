// Package config holds the tunable thresholds that policies read. Every value
// here is handed to Rego as `input.config`, so a rule never hard-codes a number
// that a user might reasonably disagree with.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/scm-bench/azure-devops-bench/internal/scm"
)

// Config is the full evaluation configuration.
type Config struct {
	// Scan holds the settings that describe the deployment rather than any
	// one run: how to reach the organization, how hard to drive it, and what
	// its exit thresholds are. Excluded from the policy input (json:"-"): no
	// rule reads them, and a verdict must not depend on how the scan ran.
	Scan Scan `yaml:"scan" json:"-"`
	// Thresholds are the numeric knobs used by the policies.
	Thresholds Thresholds `yaml:"thresholds" json:"thresholds"`
	// SignatureStatusChecks names the status checks that verify commit
	// signatures, as "genre/name" or "name". Azure Repos cannot verify a
	// signature itself, so the only enforcement there is a required status
	// policy fed by a service that does — and which service that is, is a
	// fact about the deployment. Empty by default, which makes CIS-1.1.12
	// fail until someone names one.
	SignatureStatusChecks []string `yaml:"signatureStatusChecks" json:"signatureStatusChecks"`
	// NonLinearMergeStrategies are merge strategy IDs that can introduce a
	// merge commit and therefore break linear history. Azure DevOps merge
	// types map onto the family's IDs: basic merge is no-ff, squash is
	// squash, rebase and fast-forward is rebase-ff-only, semi-linear merge is
	// rebase-no-ff.
	NonLinearMergeStrategies []string `yaml:"nonLinearMergeStrategies" json:"nonLinearMergeStrategies"`
	// SecurityPolicyPaths are the paths probed on the default branch for a
	// security policy, in priority order.
	SecurityPolicyPaths []string `yaml:"securityPolicyPaths" json:"securityPolicyPaths"`
	// EveryoneAllowedPermissions are the Git permissions the groups every
	// member belongs to (Project Collection Valid Users, Project Valid Users)
	// may hold on a repository. Anything beyond is a blanket grant CIS-1.3.8
	// fails on.
	EveryoneAllowedPermissions []string `yaml:"everyoneAllowedPermissions" json:"everyoneAllowedPermissions"`
	// AllowPublicRepositories relaxes the public-access rule, for
	// organizations that intentionally publish code.
	AllowPublicRepositories bool `yaml:"allowPublicRepositories" json:"allowPublicRepositories"`
	// SkipArchivedRepositories drops disabled repositories from the scan.
	SkipArchivedRepositories bool `yaml:"skipArchivedRepositories" json:"skipArchivedRepositories"`
	// AllowedBypassPrincipals names accounts that may hold a bypass without
	// counting against maxBypassPrincipals: the build and release identities
	// that genuinely have to push past a policy. Without this list the
	// threshold has to be set high enough to cover the service accounts,
	// which is high enough to hide the people. Matched case-insensitively
	// against the names the report prints.
	AllowedBypassPrincipals []string `yaml:"allowedBypassPrincipals" json:"allowedBypassPrincipals"`
	// Exclude lists check IDs (e.g. "CIS-1.1.8") to leave out of the run.
	Exclude []string `yaml:"exclude" json:"exclude"`
	// Include, when non-empty, restricts the run to these check IDs.
	Include []string `yaml:"include" json:"include"`
	// Exceptions accept findings an organization has decided to live with,
	// for a stated reason and until a stated date. They are applied after
	// evaluation, so no rule sees them (json:"-").
	Exceptions []Exception `yaml:"exceptions" json:"-"`
}

// Exception accepts the findings of one control on matching resources.
//
// An accepted finding is still reported, still FAIL, and still counts in the
// score — the score describes the organization, and accepting a finding does
// not change the organization. What it stops doing is failing the run on
// scan.failOn (or, for a MANUAL finding, counting against scan.maxManual). It
// lapses at the end of its expiry day and the finding fails the run again;
// there is no exception without one.
type Exception struct {
	// Control is the control ID, e.g. CIS-1.1.13.
	Control string `yaml:"control"`
	// Resources are glob patterns over resource names: PROJECT/repository
	// for a repository, "instance" for an organization-level control. *
	// does not cross a "/", so Fabrikam/* is every repository in Fabrikam.
	Resources []string `yaml:"resources"`
	// Reason is why the finding is accepted; it is printed beside it.
	Reason string `yaml:"reason"`
	// Owner is who answers for it.
	Owner string `yaml:"owner"`
	// Expires is the last day the exception applies, YYYY-MM-DD.
	Expires string `yaml:"expires"`
}

// ExpiresAt is the moment the exception stops applying: the end of its
// expiry day, UTC.
func (e Exception) ExpiresAt() time.Time {
	day, err := time.Parse("2006-01-02", e.Expires)
	if err != nil {
		return time.Time{}
	}
	return day.Add(24 * time.Hour)
}

// validate checks an exception has everything it needs to be one. An
// exception without a reason or an end date is how accepted risk turns into
// forgotten risk, so neither is optional.
func (e Exception) validate() error {
	if strings.TrimSpace(e.Control) == "" {
		return fmt.Errorf("control is required, e.g. control: CIS-1.1.13")
	}
	if len(e.Resources) == 0 {
		return fmt.Errorf("%s: resources is required: the repositories (PROJECT/repository, globs allowed) or \"instance\" it applies to", e.Control)
	}
	for _, pattern := range e.Resources {
		if strings.TrimSpace(pattern) == "" {
			return fmt.Errorf("%s: an empty resource pattern; remove it", e.Control)
		}
		if _, err := path.Match(pattern, ""); err != nil {
			return fmt.Errorf("%s: resource pattern %q: %w", e.Control, pattern, err)
		}
	}
	if strings.TrimSpace(e.Reason) == "" {
		return fmt.Errorf("%s: reason is required: it is printed beside every finding the exception accepts", e.Control)
	}
	if strings.TrimSpace(e.Expires) == "" {
		return fmt.Errorf("%s: expires is required (YYYY-MM-DD): an exception without an end date is a finding nobody will look at again", e.Control)
	}
	if e.ExpiresAt().IsZero() {
		return fmt.Errorf("%s: expires %q is not a date; use YYYY-MM-DD", e.Control, e.Expires)
	}
	return nil
}

// Scan is the deployment-stable half of a scan's configuration.
type Scan struct {
	// FailOn exits 1 when a failure at or above this severity exists:
	// high, medium, low, or none.
	FailOn string `yaml:"failOn"`
	// FailUnder exits 1 when the score is below it; 0 disables.
	FailUnder int `yaml:"failUnder"`
	// MaxManual exits 1 when more than this percent of controls need manual
	// review; -1 disables. It defaults to off because how much of an
	// organization a token can read is a property of the deployment, and a
	// guess here would fail scans that are working as well as they can.
	MaxManual int `yaml:"maxManual"`
	// Concurrency is how many repositories to fetch in parallel. Four, not
	// bitbucket-bench's eight: Azure DevOps Services throttles per identity
	// over a sliding five-minute window, and a scan that trips it spends
	// longer sleeping than it saved.
	Concurrency int `yaml:"concurrency"`
	// Timeout bounds a single HTTP request, e.g. "30s".
	Timeout Duration `yaml:"timeout"`
	// MaxDuration abandons the scan after this long; 0 means no limit.
	MaxDuration Duration `yaml:"maxDuration"`
	// Insecure skips TLS certificate verification. caFile is almost always
	// the right answer instead.
	Insecure bool `yaml:"insecure"`
	// AllowPlaintext permits an http:// URL to a non-loopback host, sending
	// credentials in the clear.
	AllowPlaintext bool `yaml:"allowPlaintext"`
	// CAFile is a PEM bundle added to the system roots — not replacing them —
	// for an Azure DevOps Server behind an internal certificate authority.
	CAFile string `yaml:"caFile"`
	// AllowIncomplete lets a scan whose enumeration was partial (a project
	// whose repositories could not be listed) exit on its findings rather
	// than with 2. The report says what was missed either way.
	AllowIncomplete bool `yaml:"allowIncomplete"`
	// Progress is what to show while scanning: full, compact, or off.
	Progress string `yaml:"progress"`
	// Cache keeps each network scan's snapshot (0600, under the user config
	// directory) so `scan --last` can re-render it without contacting the
	// organization again. The snapshot is a map of the organization's weak
	// points, which is why this is a config key at all: false keeps it off
	// disk.
	Cache bool `yaml:"cache"`
}

// Duration is time.Duration that reads YAML the way people write durations:
// "30s", "2m", "1h30m". A bare number would be nanoseconds, which nobody
// means, so it is rejected with the spelling that works.
type Duration time.Duration

func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err != nil {
		return fmt.Errorf("a duration is a string like \"30s\" or \"5m\", got %s", value.Value)
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("parse duration %q: %w", s, err)
	}
	*d = Duration(v)
	return nil
}

func (d Duration) Get() time.Duration { return time.Duration(d) }

// Thresholds are the numeric policy knobs.
type Thresholds struct {
	// MinApprovers is the number of independent approvals a pull request
	// must collect.
	MinApprovers int `yaml:"minApprovers" json:"minApprovers"`
	// MinRepositoryAdmins guards against a repository with a single owner.
	MinRepositoryAdmins int `yaml:"minRepositoryAdmins" json:"minRepositoryAdmins"`
	// MinOrgAdmins / MaxOrgAdmins bracket the organization administrator
	// count: too few is a bus-factor risk, too many is an oversized blast
	// radius. Zero means "no bound on this side".
	MinOrgAdmins int `yaml:"minOrgAdmins" json:"minOrgAdmins"`
	MaxOrgAdmins int `yaml:"maxOrgAdmins" json:"maxOrgAdmins"`
	// StaleBranchDays is how long a branch may sit untouched before it counts
	// as abandoned.
	StaleBranchDays int `yaml:"staleBranchDays" json:"staleBranchDays"`
	// MaxStaleBranches is how many abandoned branches a repository may carry.
	MaxStaleBranches int `yaml:"maxStaleBranches" json:"maxStaleBranches"`
	// InactiveUserDays is how long a user may go without accessing the
	// organization before their access should be reviewed.
	InactiveUserDays int `yaml:"inactiveUserDays" json:"inactiveUserDays"`
	// MaxBypassPrincipals is how many principals may hold a bypass of the
	// protection on the default branch — how many people the protection
	// does not actually bind. -1 disables the check.
	MaxBypassPrincipals int `yaml:"maxBypassPrincipals" json:"maxBypassPrincipals"`
	// MaxRepositoryCreators is how many people per project may create
	// repositories without being a project or organization administrator.
	MaxRepositoryCreators int `yaml:"maxRepositoryCreators" json:"maxRepositoryCreators"`
}

// Default returns the configuration used when the user supplies none. The
// values follow the CIS Software Supply Chain Security Guide where it is
// specific, and common practice where it is not.
func Default() Config {
	return Config{
		Scan: Scan{
			FailOn:      "high",
			FailUnder:   0,
			MaxManual:   -1,
			Concurrency: 4,
			Timeout:     Duration(30 * time.Second),
			MaxDuration: 0,
			Progress:    "compact",
			Cache:       true,
		},
		Thresholds: Thresholds{
			MinApprovers:          2,
			MinRepositoryAdmins:   2,
			MinOrgAdmins:          2,
			MaxOrgAdmins:          5,
			StaleBranchDays:       90,
			MaxStaleBranches:      0,
			InactiveUserDays:      90,
			MaxBypassPrincipals:   0,
			MaxRepositoryCreators: 0,
		},
		SignatureStatusChecks: []string{},
		// The family's shared list. "ff" has no Azure DevOps merge type behind
		// it; it is here so one nonLinearMergeStrategies value means the same
		// thing in every bench's config, not because this platform offers it.
		NonLinearMergeStrategies: []string{"no-ff", "rebase-no-ff", "ff"},
		SecurityPolicyPaths: []string{
			"SECURITY.md",
			".github/SECURITY.md",
			"docs/SECURITY.md",
			"SECURITY.rst",
			"SECURITY.txt",
			"SECURITY",
		},
		EveryoneAllowedPermissions: []string{"GenericRead"},
		AllowPublicRepositories:    false,
		SkipArchivedRepositories:   true,
	}
}

// Load reads a YAML config from path and overlays it on the defaults, so a
// user file only needs to mention what it changes.
func Load(path string) (Config, error) {
	return LoadWithOverrides(path, nil)
}

// LoadWithOverrides is Load plus per-run overrides: each set entry is a
// "key=value" naming a config key by its dotted YAML path, applied over
// whatever the file said. Validation runs once, at the end, so an override
// is checked exactly as hard as the file it overrides.
func LoadWithOverrides(path string, sets []string) (Config, error) {
	cfg := Default()
	if path != "" {
		raw, err := os.ReadFile(path)
		if err != nil {
			return cfg, fmt.Errorf("read config %s: %w", path, err)
		}
		// Decoding onto the populated struct leaves absent keys at their default.
		// Sequences are the exception: YAML replaces them wholesale, which is what
		// a user who lists signature status checks expects.
		//
		// KnownFields is on because the failure mode without it is silent and
		// wrong: `minApprover` for `minApprovers` parses cleanly, changes nothing,
		// and produces a report the user believes was evaluated at their threshold.
		// An audit tool that quietly ignores its own configuration is worse than
		// one that refuses to start.
		decoder := yaml.NewDecoder(bytes.NewReader(raw))
		decoder.KnownFields(true)
		if err := decoder.Decode(&cfg); err != nil {
			// An empty file is not an error: it means "keep every default".
			if !errors.Is(err, io.EOF) {
				return cfg, fmt.Errorf("parse config %s: %w", path, err)
			}
		}
	}
	for _, set := range sets {
		if err := applyOverride(&cfg, set); err != nil {
			return cfg, err
		}
	}
	if err := cfg.Validate(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

// keySegment is what a piece of a dotted config key may look like. Anything
// else is refused before it can reach the YAML text an override is turned
// into.
var keySegment = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]*$`)

// applyOverride applies one "key=value" onto the config.
//
// It works by writing the override as the YAML document it is shorthand for —
// scan.failOn=none becomes "scan:\n  failOn: none\n" — and decoding that onto
// the config with the same strict decoder the file gets. Everything then
// comes for free and cannot drift from the file's behaviour: the value
// parsing (ints, bools, "30s" durations, [flow, sequences]), the overlay
// semantics, and the refusal of unknown keys.
func applyOverride(cfg *Config, set string) error {
	key, value, ok := strings.Cut(set, "=")
	if !ok {
		return fmt.Errorf("--set %q is not key=value; e.g. --set scan.failOn=none", set)
	}
	if strings.ContainsAny(value, "\n\r") {
		return fmt.Errorf("--set %q: the value must be a single line", set)
	}
	segments := strings.Split(key, ".")
	var doc strings.Builder
	for i, seg := range segments {
		if !keySegment.MatchString(seg) {
			return fmt.Errorf("--set %q: %q is not a config key", set, key)
		}
		indent := strings.Repeat("  ", i)
		if i < len(segments)-1 {
			fmt.Fprintf(&doc, "%s%s:\n", indent, seg)
		} else {
			fmt.Fprintf(&doc, "%s%s: %s\n", indent, seg, value)
		}
	}

	decoder := yaml.NewDecoder(strings.NewReader(doc.String()))
	decoder.KnownFields(true)
	if err := decoder.Decode(cfg); err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("--set %q: %w", set, err)
	}
	return nil
}

// Validate rejects thresholds that would make a policy meaningless.
func (c Config) Validate() error {
	s := c.Scan
	switch strings.ToLower(s.FailOn) {
	case "high", "medium", "low", "none":
	default:
		return fmt.Errorf("scan.failOn %q: want high, medium, low or none", s.FailOn)
	}
	switch strings.ToLower(s.Progress) {
	case "full", "compact", "off":
	default:
		return fmt.Errorf("scan.progress %q: want full, compact or off", s.Progress)
	}
	if s.Concurrency < 1 {
		return fmt.Errorf("scan.concurrency must be at least 1, got %d", s.Concurrency)
	}
	if s.FailUnder < 0 || s.FailUnder > 100 {
		return fmt.Errorf("scan.failUnder must be between 0 and 100, got %d", s.FailUnder)
	}
	if s.MaxManual < -1 || s.MaxManual > 100 {
		return fmt.Errorf("scan.maxManual must be between 0 and 100, or -1 to disable, got %d", s.MaxManual)
	}
	if s.Timeout.Get() < 0 || s.MaxDuration.Get() < 0 {
		return fmt.Errorf("scan.timeout and scan.maxDuration must not be negative")
	}
	// A CA bundle is how an internal CA is trusted without giving up
	// verification; with insecure on, the bundle would be quietly ignored and
	// the reader of this file would believe the certificate was checked.
	if s.CAFile != "" && s.Insecure {
		return fmt.Errorf("scan.caFile and scan.insecure are mutually exclusive: the CA bundle verifies the server's certificate, insecure skips verification; drop insecure")
	}

	// Every threshold is checked, not just the ones that looked risky.
	//
	// A negative threshold does not merely produce an odd number: it silently
	// inverts the control it feeds. `minRepositoryAdmins: -1` makes
	// `count >= minimum` true for a repository with zero administrators, so
	// CIS-1.3.7 reports PASS while saying "0 administrators". Either way a
	// single typo reconfigures a control into something that is not a control
	// any more, and nothing in the report says so — which is why this is a
	// startup error rather than a warning.
	t := c.Thresholds
	for _, f := range []struct {
		name  string
		value int
	}{
		{"minApprovers", t.MinApprovers},
		{"minRepositoryAdmins", t.MinRepositoryAdmins},
		{"minOrgAdmins", t.MinOrgAdmins},
		{"maxOrgAdmins", t.MaxOrgAdmins},
		{"staleBranchDays", t.StaleBranchDays},
		{"maxStaleBranches", t.MaxStaleBranches},
		{"inactiveUserDays", t.InactiveUserDays},
		{"maxRepositoryCreators", t.MaxRepositoryCreators},
	} {
		if f.value < 0 {
			return fmt.Errorf("thresholds.%s must be >= 0, got %d", f.name, f.value)
		}
	}
	// maxBypassPrincipals is checked apart from the loop above because -1 is
	// meaningful here — it turns the bypass check off.
	if t.MaxBypassPrincipals < -1 {
		return fmt.Errorf("thresholds.maxBypassPrincipals must be >= 0, or -1 to disable, got %d", t.MaxBypassPrincipals)
	}
	if t.MinOrgAdmins > 0 && t.MaxOrgAdmins > 0 && t.MinOrgAdmins > t.MaxOrgAdmins {
		return fmt.Errorf("thresholds.minOrgAdmins (%d) must not exceed maxOrgAdmins (%d)", t.MinOrgAdmins, t.MaxOrgAdmins)
	}

	// A blank entry in any of these lists either matches everything or
	// names nothing, and both quietly change a verdict. A blank signature
	// status check would let the rule's comparison against a status with an
	// empty name succeed; a blank allowed permission would make a typo look
	// like a deliberate allowance.
	for _, list := range []struct {
		field string
		items []string
	}{
		{"signatureStatusChecks", c.SignatureStatusChecks},
		{"nonLinearMergeStrategies", c.NonLinearMergeStrategies},
		{"securityPolicyPaths", c.SecurityPolicyPaths},
		{"everyoneAllowedPermissions", c.EveryoneAllowedPermissions},
		{"allowedBypassPrincipals", c.AllowedBypassPrincipals},
		{"exclude", c.Exclude},
		{"include", c.Include},
	} {
		for i, item := range list.items {
			if strings.TrimSpace(item) == "" {
				return fmt.Errorf("%s[%d] is empty; remove the entry rather than leaving it blank", list.field, i)
			}
		}
	}

	for i, ex := range c.Exceptions {
		if err := ex.validate(); err != nil {
			return fmt.Errorf("exceptions[%d]: %w", i, err)
		}
	}

	// A permission name the namespace does not define can only be a typo, and
	// reading it as "allowed" would mean "nothing extra is allowed" while the
	// operator believed they had allowed something — or, worse, the reverse
	// for a name that merely looks like one the rule checks. Rejected here,
	// where the person who wrote it is still looking.
	for i, name := range c.EveryoneAllowedPermissions {
		if _, ok := scm.GitPermissionNamed(strings.TrimSpace(name)); !ok {
			return fmt.Errorf("everyoneAllowedPermissions[%d] %q is not a Git Repositories permission; want one of %s",
				i, name, strings.Join(gitPermissionNames(), ", "))
		}
	}
	return nil
}

func gitPermissionNames() []string {
	names := make([]string, 0, len(scm.GitPermissions))
	for _, p := range scm.GitPermissions {
		names = append(names, p.Name)
	}
	return names
}

// Selects reports whether a check ID should run under this configuration.
func (c Config) Selects(id string) bool {
	for _, ex := range c.Exclude {
		if strings.EqualFold(strings.TrimSpace(ex), id) {
			return false
		}
	}
	if len(c.Include) == 0 {
		return true
	}
	for _, in := range c.Include {
		if strings.EqualFold(strings.TrimSpace(in), id) {
			return true
		}
	}
	return false
}
