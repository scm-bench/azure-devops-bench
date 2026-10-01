package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func TestLoadWithoutPathReturnsDefaults(t *testing.T) {
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Thresholds.MinApprovers != 2 {
		t.Errorf("minApprovers = %d, want 2", cfg.Thresholds.MinApprovers)
	}
}

// A partial file must only change what it mentions; everything else keeps its
// default, so a user does not have to restate the whole benchmark to move one
// number.
func TestPartialConfigOverlaysDefaults(t *testing.T) {
	path := writeConfig(t, "thresholds:\n  minApprovers: 1\n")

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Thresholds.MinApprovers != 1 {
		t.Errorf("minApprovers = %d, want 1", cfg.Thresholds.MinApprovers)
	}
	if cfg.Thresholds.StaleBranchDays != 90 {
		t.Errorf("staleBranchDays = %d, want the default 90", cfg.Thresholds.StaleBranchDays)
	}
	if len(cfg.SecurityPolicyPaths) == 0 {
		t.Error("securityPolicyPaths should retain its defaults")
	}
	if len(cfg.EveryoneAllowedPermissions) != 1 || cfg.EveryoneAllowedPermissions[0] != "GenericRead" {
		t.Errorf("everyoneAllowedPermissions = %v, want the default [GenericRead]", cfg.EveryoneAllowedPermissions)
	}
}

func TestListsAreReplacedNotMerged(t *testing.T) {
	path := writeConfig(t, "nonLinearMergeStrategies:\n  - no-ff\n")

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.NonLinearMergeStrategies) != 1 || cfg.NonLinearMergeStrategies[0] != "no-ff" {
		t.Errorf("nonLinearMergeStrategies = %v, want the user's list verbatim", cfg.NonLinearMergeStrategies)
	}
}

// The family shares one default merge-strategy list, so a config file moved
// between benches means the same thing in each.
func TestNonLinearMergeStrategiesMatchTheFamilyDefault(t *testing.T) {
	got := Default().NonLinearMergeStrategies
	want := []string{"no-ff", "rebase-no-ff", "ff"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("nonLinearMergeStrategies = %v, want %v", got, want)
	}
}

// Azure Repos cannot verify a signature, so nothing counts as verification
// until the operator names the status check that does it. A default naming
// some vendor's check would hand CIS-1.1.12 a PASS for a service nobody runs.
func TestSignatureStatusChecksDefaultToNone(t *testing.T) {
	if got := Default().SignatureStatusChecks; len(got) != 0 {
		t.Errorf("signatureStatusChecks = %v, want none by default", got)
	}
}

func TestDefaultConcurrencyIsGentle(t *testing.T) {
	if got := Default().Scan.Concurrency; got != 4 {
		t.Errorf("scan.concurrency = %d, want 4", got)
	}
}

func TestInvalidConfigIsRejected(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{"negative approvers", "thresholds:\n  minApprovers: -1\n"},
		{"inverted admin range", "thresholds:\n  minOrgAdmins: 9\n  maxOrgAdmins: 2\n"},
		{"negative stale window", "thresholds:\n  staleBranchDays: -5\n"},
		{"unknown everyone permission", "everyoneAllowedPermissions: [GenericRaed]\n"},
		{"malformed yaml", "thresholds: [\n"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Load(writeConfig(t, tc.body)); err == nil {
				t.Error("expected an error")
			}
		})
	}
}

func TestMissingFileIsAnError(t *testing.T) {
	if _, err := Load("/nonexistent/config.yaml"); err == nil {
		t.Error("a config path that does not exist should be an error, not a silent default")
	}
}

// A misspelled key is the dangerous failure: it parses, changes nothing, and
// produces a report the user believes was evaluated at their threshold. Both
// levels of the document have to reject it.
func TestUnknownKeysAreRejected(t *testing.T) {
	for name, body := range map[string]string{
		"misspelled threshold": "thresholds:\n  minApprover: 5\n",
		"unknown top level":    "typoKey: true\n",
		"unknown nested":       "thresholds:\n  minApprovers: 2\n  maxApprovers: 9\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Load(writeConfig(t, body)); err == nil {
				t.Errorf("Load(%q) succeeded; an unrecognised key must be an error", body)
			}
		})
	}
}

// Rejecting unknown keys must not turn "change nothing" into an error: a file
// that is empty, or only comments, is a valid way to say "keep every default".
func TestEmptyConfigKeepsDefaults(t *testing.T) {
	for name, body := range map[string]string{
		"empty":         "",
		"comments only": "# nothing to change here\n",
	} {
		t.Run(name, func(t *testing.T) {
			cfg, err := Load(writeConfig(t, body))
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if cfg.Thresholds.MinApprovers != Default().Thresholds.MinApprovers {
				t.Errorf("minApprovers = %d, want the default", cfg.Thresholds.MinApprovers)
			}
		})
	}
}

func TestSelectsHonoursIncludeAndExclude(t *testing.T) {
	cfg := Default()
	if !cfg.Selects("CIS-1.1.3") {
		t.Error("everything should be selected by default")
	}

	cfg.Exclude = []string{"cis-1.1.3"}
	if cfg.Selects("CIS-1.1.3") {
		t.Error("exclude should match case-insensitively")
	}

	cfg = Default()
	cfg.Include = []string{"CIS-1.1.15"}
	if cfg.Selects("CIS-1.1.3") {
		t.Error("a non-empty include list should exclude everything else")
	}
	if !cfg.Selects("CIS-1.1.15") {
		t.Error("an included check should be selected")
	}

	// Exclude wins over include, so a user can pin a list and drop one entry.
	cfg.Exclude = []string{"CIS-1.1.15"}
	if cfg.Selects("CIS-1.1.15") {
		t.Error("exclude should take precedence over include")
	}
}

// A blank entry is matched by every string, so it does not narrow a list — it
// disables the check the list drives. signatureHookKeys is the dangerous one:
// `contains(haystack, "")` is true for any hook, so one stray blank turns
// CIS-1.1.12 into a PASS that verified nothing.
func TestBlankListEntriesAreRejected(t *testing.T) {
	for _, tc := range []struct{ name, yaml, want string }{
		{"signature status check", "signatureStatusChecks:\n  - \"\"\n  - sec/signed\n", "signatureStatusChecks[0]"},
		{"whitespace only", "signatureStatusChecks:\n  - sec/signed\n  - \"   \"\n", "signatureStatusChecks[1]"},
		{"everyone permission", "everyoneAllowedPermissions:\n  - \"\"\n", "everyoneAllowedPermissions[0]"},
		{"bypass principal", "allowedBypassPrincipals:\n  - \"\"\n", "allowedBypassPrincipals[0]"},
		{"merge strategy", "nonLinearMergeStrategies:\n  - \"\"\n", "nonLinearMergeStrategies[0]"},
		{"security policy path", "securityPolicyPaths:\n  - SECURITY.md\n  - \"\"\n", "securityPolicyPaths[1]"},
		{"exclude", "exclude:\n  - \"\"\n", "exclude[0]"},
		{"include", "include:\n  - \"\"\n", "include[0]"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Load(writeConfig(t, tc.yaml))
			if err == nil {
				t.Fatalf("Load accepted a blank entry in %s", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not name %s", err, tc.want)
			}
		})
	}
}

// A negative threshold does not produce an odd number, it inverts the control.
// `minRepositoryAdmins: -1` made `count >= minimum` true for a repository with
// no administrators at all, so CIS-1.3.7 reported PASS — and said "0
// administrator(s) can manage this repository" while doing it. Every threshold
// is covered, so a field added later is not left out by omission.
func TestNegativeThresholdsAreRejected(t *testing.T) {
	for _, field := range []string{
		"minApprovers",
		"minRepositoryAdmins",
		"minOrgAdmins",
		"maxOrgAdmins",
		"staleBranchDays",
		"maxStaleBranches",
		"inactiveUserDays",
		"maxRepositoryCreators",
	} {
		t.Run(field, func(t *testing.T) {
			_, err := Load(writeConfig(t, "thresholds:\n  "+field+": -1\n"))
			if err == nil {
				t.Fatalf("Load accepted thresholds.%s = -1", field)
			}
			if !strings.Contains(err.Error(), field) {
				t.Errorf("error %q does not name the field", err)
			}
		})
	}
}

// disablingThresholds are the thresholds where -1 is a documented value rather
// than a typo, so the sweep below has to probe them one step further down. The
// map is deliberately explicit: a threshold that quietly accepts a negative is
// the failure this test exists to catch, and an exception has to be written
// down to be granted.
var disablingThresholds = map[string]bool{"maxBypassPrincipals": true}

// Every threshold in the struct must appear in the check above; a new one that
// nobody adds is exactly how the first four came to be missing.
func TestEveryThresholdIsValidated(t *testing.T) {
	fields := reflect.VisibleFields(reflect.TypeOf(Thresholds{}))
	for _, f := range fields {
		if f.Type.Kind() != reflect.Int {
			continue
		}
		name := strings.Split(f.Tag.Get("yaml"), ",")[0]
		if name == "" {
			t.Errorf("Thresholds.%s has no yaml tag", f.Name)
			continue
		}
		probe := "-1"
		if disablingThresholds[name] {
			probe = "-2"
		}
		if _, err := Load(writeConfig(t, "thresholds:\n  "+name+": "+probe+"\n")); err == nil {
			t.Errorf("thresholds.%s accepts %s; add it to Config.Validate", name, probe)
		}
	}
}

// -1 is how the bypass check is turned off, and a config that says so has to
// load. The sweep above can only prove the field rejects nonsense.
func TestMaxBypassPrincipalsAcceptsMinusOne(t *testing.T) {
	cfg, err := Load(writeConfig(t, "thresholds:\n  maxBypassPrincipals: -1\n"))
	if err != nil {
		t.Fatalf("Load rejected the documented disable value: %v", err)
	}
	if cfg.Thresholds.MaxBypassPrincipals != -1 {
		t.Errorf("maxBypassPrincipals = %d, want -1", cfg.Thresholds.MaxBypassPrincipals)
	}
}

func TestScanSectionLoadsAndValidates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cfg.yaml")
	write := func(content string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
	}

	write("scan:\n  failOn: none\n  concurrency: 3\n  timeout: 5s\n  maxDuration: 2m\n")
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Scan.FailOn != "none" || cfg.Scan.Concurrency != 3 {
		t.Errorf("scan section did not load: %+v", cfg.Scan)
	}
	if cfg.Scan.Timeout.Get() != 5*time.Second || cfg.Scan.MaxDuration.Get() != 2*time.Minute {
		t.Errorf("durations did not parse: %+v", cfg.Scan)
	}
	// Absent keys keep their defaults.
	if cfg.Scan.Progress != "compact" || cfg.Scan.MaxManual != -1 {
		t.Errorf("absent keys lost their defaults: %+v", cfg.Scan)
	}

	// The validations that moved here with the settings.
	for _, tc := range []struct{ name, content string }{
		{"bad failOn", "scan:\n  failOn: critical\n"},
		{"bad progress", "scan:\n  progress: loud\n"},
		{"zero concurrency", "scan:\n  concurrency: 0\n"},
		{"failUnder out of range", "scan:\n  failUnder: 101\n"},
		{"maxManual out of range", "scan:\n  maxManual: -2\n"},
		{"bare-number duration", "scan:\n  timeout: 30\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			write(tc.content)
			if _, err := Load(path); err == nil {
				t.Errorf("Load accepted %q", tc.content)
			}
		})
	}
}

func TestDiscoverPrefersTheWorkingDirectory(t *testing.T) {
	userDir := t.TempDir()
	t.Setenv("AZURE_DEVOPS_BENCH_CONFIG_DIR", userDir)
	work := t.TempDir()
	t.Chdir(work)

	// Nothing anywhere: no path, no error.
	path, err := Discover()
	if err != nil || path != "" {
		t.Fatalf("Discover() = %q, %v; want none", path, err)
	}

	// User config alone is found...
	userCfg := filepath.Join(userDir, "config.yaml")
	if err := os.WriteFile(userCfg, []byte(""), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if path, _ = Discover(); path != userCfg {
		t.Errorf("Discover() = %q, want %q", path, userCfg)
	}

	// ...but the working directory wins, hidden name included.
	if err := os.WriteFile(filepath.Join(work, ".azure-devops-bench.yaml"), []byte(""), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if path, _ = Discover(); path != ".azure-devops-bench.yaml" {
		t.Errorf("Discover() = %q, want the hidden working-directory file", path)
	}
	if err := os.WriteFile(filepath.Join(work, "azure-devops-bench.yaml"), []byte(""), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if path, _ = Discover(); path != "azure-devops-bench.yaml" {
		t.Errorf("Discover() = %q, want the visible name first", path)
	}
}

// --set is shorthand for the YAML document it names, decoded by the same
// strict decoder the file gets — so values type themselves and unknown keys
// are refused, exactly as in the file.
func TestOverridesApplyOverTheFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cfg.yaml")
	if err := os.WriteFile(path, []byte("scan:\n  failOn: none\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	cfg, err := LoadWithOverrides(path, []string{
		"scan.failOn=high", // beats the file
		"scan.timeout=5s",
		"scan.insecure=true",
		"thresholds.minApprovers=3",
		"allowPublicRepositories=true",
		"exclude=[CIS-1.1.8, CIS-1.1.13]",
	})
	if err != nil {
		t.Fatalf("LoadWithOverrides: %v", err)
	}
	if cfg.Scan.FailOn != "high" {
		t.Errorf("failOn = %q; --set should beat the file", cfg.Scan.FailOn)
	}
	if cfg.Scan.Timeout.Get() != 5*time.Second || !cfg.Scan.Insecure {
		t.Errorf("scan overrides did not land: %+v", cfg.Scan)
	}
	if cfg.Thresholds.MinApprovers != 3 || !cfg.AllowPublicRepositories {
		t.Errorf("non-scan overrides did not land")
	}
	if len(cfg.Exclude) != 2 || cfg.Exclude[0] != "CIS-1.1.8" {
		t.Errorf("flow-sequence override did not land: %v", cfg.Exclude)
	}
}

func TestOverridesAreRefusedWhenMalformed(t *testing.T) {
	for _, tc := range []struct{ name, set, want string }{
		{"no equals", "scan.failOn", "key=value"},
		{"unknown key", "scan.failsOn=none", `--set "scan.failsOn=none"`},
		{"unknown top-level", "bogus=1", `--set "bogus=1"`},
		{"invalid key segment", "scan.fail-On=none", "not a config key"},
		{"multiline value", "scan.failOn=a\nb", "single line"},
		{"bad value type", "scan.concurrency=abc", `--set "scan.concurrency=abc"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := LoadWithOverrides("", []string{tc.set})
			if err == nil {
				t.Fatalf("--set %q was accepted", tc.set)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

// Validation runs after the overrides, so a --set is checked exactly as hard
// as the file it overrides.
func TestOverridesStillGoThroughValidation(t *testing.T) {
	if _, err := LoadWithOverrides("", []string{"scan.concurrency=0"}); err == nil {
		t.Error("an out-of-range override was accepted")
	}
}

// The --set key grammar admits underscores, so a key that carries one is
// reachable without a file.
func TestSetReachesListKeys(t *testing.T) {
	cfg, err := LoadWithOverrides("", []string{"everyoneAllowedPermissions=[GenericRead, PullRequestContribute]"})
	if err != nil {
		t.Fatalf("LoadWithOverrides: %v", err)
	}
	if len(cfg.EveryoneAllowedPermissions) != 2 || cfg.EveryoneAllowedPermissions[1] != "PullRequestContribute" {
		t.Errorf("everyoneAllowedPermissions = %v", cfg.EveryoneAllowedPermissions)
	}
}

// A misspelled permission name allows nothing while looking like it allows
// something; the error names the valid ones so the fix is in the message.
func TestUnknownEveryonePermissionNamesTheValidOnes(t *testing.T) {
	_, err := LoadWithOverrides("", []string{"everyoneAllowedPermissions=[Contribute]"})
	if err == nil {
		t.Fatal("an unknown Git permission name was accepted")
	}
	if !strings.Contains(err.Error(), "GenericContribute") {
		t.Errorf("error %q does not list the valid names", err)
	}
}

func TestScanSectionCarriesTheTransportKeys(t *testing.T) {
	cfg, err := LoadWithOverrides("", []string{"scan.caFile=/etc/ssl/corp.pem", "scan.allowIncomplete=true"})
	if err != nil {
		t.Fatalf("LoadWithOverrides: %v", err)
	}
	if cfg.Scan.CAFile != "/etc/ssl/corp.pem" || !cfg.Scan.AllowIncomplete {
		t.Errorf("scan keys did not land: %+v", cfg.Scan)
	}
}

// An exception without a reason or an end date is how accepted risk becomes
// forgotten risk, so neither is optional, and a malformed one is refused at
// load rather than silently matching nothing.
func TestExceptionsAreValidated(t *testing.T) {
	valid := "exceptions:\n  - control: CIS-1.1.13\n    resources: [Fabrikam/*]\n    reason: release tooling\n    expires: 2027-03-31\n"
	cfg, err := Load(writeConfig(t, valid))
	if err != nil {
		t.Fatalf("a complete exception was refused: %v", err)
	}
	if got := cfg.Exceptions[0].ExpiresAt(); !got.Equal(time.Date(2027, 4, 1, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("expires at %v, want the end of 2027-03-31", got)
	}
	for _, tc := range []struct{ name, yaml, want string }{
		{"no control", "exceptions:\n  - resources: [P/*]\n    reason: r\n    expires: 2027-03-31\n", "control is required"},
		{"no resources", "exceptions:\n  - control: CIS-1.1.13\n    reason: r\n    expires: 2027-03-31\n", "resources is required"},
		{"empty resource", "exceptions:\n  - control: CIS-1.1.13\n    resources: [' ']\n    reason: r\n    expires: 2027-03-31\n", "empty resource pattern"},
		{"bad glob", "exceptions:\n  - control: CIS-1.1.13\n    resources: ['P/[']\n    reason: r\n    expires: 2027-03-31\n", "P/["},
		{"no reason", "exceptions:\n  - control: CIS-1.1.13\n    resources: [P/*]\n    expires: 2027-03-31\n", "reason is required"},
		{"no expiry", "exceptions:\n  - control: CIS-1.1.13\n    resources: [P/*]\n    reason: r\n", "expires is required"},
		{"bad expiry", "exceptions:\n  - control: CIS-1.1.13\n    resources: [P/*]\n    reason: r\n    expires: next spring\n", "not a date"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Load(writeConfig(t, tc.yaml))
			if err == nil || !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), "exceptions[0]") {
				t.Errorf("err = %v, want it to mention exceptions[0] and %q", err, tc.want)
			}
		})
	}
	if (Exception{Expires: "garbage"}).ExpiresAt() != (time.Time{}) {
		t.Error("an unparseable expiry has no moment")
	}
}

// With insecure on, a CA bundle would be quietly ignored and the reader of the
// file would believe the certificate was checked.
func TestCAFileAndInsecureAreMutuallyExclusive(t *testing.T) {
	_, err := LoadWithOverrides("", []string{"scan.caFile=/etc/ssl/corp.pem", "scan.insecure=true"})
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("err = %v, want caFile and insecure refused together", err)
	}
}
