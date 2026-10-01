package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/scm-bench/azure-devops-bench/internal/config"
	"github.com/scm-bench/azure-devops-bench/internal/engine"
	"github.com/scm-bench/azure-devops-bench/internal/scm"
)

// The table report wraps to console.Width, which reads COLUMNS. Pinning it
// keeps assertions about the rendered output from depending on the width of
// whatever terminal the suite runs under.
//
// AZURE_DEVOPS_BENCH_CONFIG_DIR is pinned for the same reason: a scan with no URL now
// consults the saved instance file, and without the pin this suite would read
// — and could write — the real one belonging to whoever runs the tests.
func TestMain(m *testing.M) {
	os.Setenv("COLUMNS", "80")
	dir, err := os.MkdirTemp("", "azure-devops-bench-test-config")
	if err != nil {
		panic(err)
	}
	os.Setenv("AZURE_DEVOPS_BENCH_CONFIG_DIR", dir)
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// writeSnapshotFixture saves a snapshot with one badly configured repository,
// so the CLI has something with a known verdict to report on.
func writeSnapshotFixture(t *testing.T) string {
	t.Helper()
	return writeSnapshotWith(t, nil)
}

// writeSnapshotWith writes the fixture with an optional mutation applied, so a test
// that needs one field different does not have to restate the whole instance.
func writeSnapshotWith(t *testing.T, mutate func(*scm.Snapshot)) string {
	t.Helper()

	snapshot := scm.Snapshot{
		SchemaVersion: scm.SchemaVersion,
		Metadata: scm.Metadata{
			Tool:        "azure-devops-bench",
			Platform:    scm.PlatformAzureDevOps,
			BaseURL:     "https://dev.azure.com/fabrikam",
			GeneratedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		},
		Organization: scm.Organization{
			EffectiveAdmins: scm.EffectivePrincipals{Users: []string{"alice", "bob"}, Count: 2, Complete: true},
			Users: []scm.User{
				{Name: "alice", Active: true, Licensed: true, InactiveDays: 1, LastActivityEpoch: 1, AgeDays: 400},
			},
			Available: map[string]bool{"admins": true, "users": true, "userActivity": true, "licensedUsers": true, "repositoryCreators": true},
		},
		Projects: []scm.Project{{
			Key:  "PRJ",
			Name: "Project",
			Repositories: []scm.Repository{{
				Slug:                 "app",
				Name:                 "app",
				ProjectKey:           "PRJ",
				FullName:             "PRJ/app",
				DefaultBranch:        "refs/heads/main",
				DefaultBranchDisplay: "main",
				// No approvals, no required policy: a guaranteed HIGH failure.
				PullRequestSettings: scm.PullRequestSettings{
					MergeStrategies: []scm.MergeStrategy{{ID: "no-ff", Enabled: true}},
				},
				BranchRestrictions: []scm.BranchRestriction{{
					Type: "fast-forward-only", MatchesDefaultBranch: true, Derived: true,
					ExemptPrincipals: scm.EffectivePrincipals{Users: []string{"creator"}, Count: 1, Complete: true},
				}},
				Branches:    []scm.Branch{{ID: "refs/heads/main", DisplayID: "main", IsDefault: true, AgeDays: 1}},
				Files:       scm.Files{Probed: []string{"SECURITY.md"}},
				Permissions: scm.Permissions{DefaultPermissionKnown: true},
				Admins:      scm.EffectivePrincipals{Users: []string{"alice", "bob"}, Count: 2, Complete: true},
				Deleters:    scm.EffectivePrincipals{Users: []string{"alice"}, Count: 1, Complete: true},
				Bypass: scm.Bypass{
					Push:        scm.EffectivePrincipals{Complete: true},
					PullRequest: scm.EffectivePrincipals{Complete: true},
					Admins:      scm.EffectivePrincipals{Complete: true},
				},
				AdvancedSecurity: scm.AdvancedSecurity{SecretProtection: true, BlockPushes: true, BlockPushesKnown: true},
				Available: map[string]bool{
					"visibility": true, "defaultBranch": true, "branches": true, "branchAges": true,
					"pullRequestSettings": true, "mergeStrategies": true, "unapproveOnUpdate": true,
					"requiredBuilds": true, "branchRestrictions": true, "files": true, "permissions": true,
					"admins": true, "orgAdminsExact": true, "deleters": true, "bypass": true, "advancedSecurity": true,
				},
			}},
		}},
	}

	if mutate != nil {
		mutate(&snapshot)
	}

	raw, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	path := filepath.Join(t.TempDir(), "snapshot.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return path
}

// run executes the CLI and returns stdout, stderr and the process exit code.
func run(t *testing.T, args ...string) (string, string, int) {
	t.Helper()
	var stdout, stderr bytes.Buffer

	root := NewRootCommand()
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	// A closed stdin, explicitly. Without it InOrStdin returns os.Stdin, and
	// `go test` runs with fd 0 on /dev/null — a character device, so the
	// first-run menu's terminal check would be answered by what the test
	// runner happened to inherit rather than by this suite.
	root.SetIn(strings.NewReader(""))
	root.SetArgs(args)

	err := root.Execute()
	return stdout.String(), stderr.String(), ExitCode(err)
}

// configWithScan writes a config file with the given scan-section lines,
// standing in for the retired scan flags.
func configWithScan(t *testing.T, lines ...string) string {
	t.Helper()
	content := "scan:\n"
	for _, l := range lines {
		content += "  " + l + "\n"
	}
	path := filepath.Join(t.TempDir(), "azure-devops-bench.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func configWithFailOn(t *testing.T, failOn string) string {
	t.Helper()
	return configWithScan(t, "failOn: "+failOn)
}

func TestScanFromSnapshotProducesJSONReport(t *testing.T) {
	fixture := writeSnapshotFixture(t)
	stdout, _, code := run(t, "scan", "--snapshot-in", fixture, "-o", "json", "-c", configWithFailOn(t, "none"))

	if code != ExitOK {
		t.Fatalf("exit code = %d, want %d with --fail-on none", code, ExitOK)
	}

	var report engine.Report
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, stdout)
	}
	if len(report.Findings) == 0 {
		t.Fatal("report contains no findings")
	}
	if report.Metadata.BaseURL != "https://dev.azure.com/fabrikam" {
		t.Errorf("metadata did not survive: %+v", report.Metadata)
	}

	var found bool
	for _, f := range report.Findings {
		if f.CheckID == "CIS-1.1.15" && f.Resource == "PRJ/app" {
			found = true
			if f.Status != engine.StatusFail {
				t.Errorf("CIS-1.1.15 = %s, want FAIL", f.Status)
			}
			if f.Remediation == "" {
				t.Error("a failing finding must carry remediation text")
			}
			// Details says what this repository does and Remediation says what
			// to change; neither answers why the control is worth acting on.
			// That is what the metadata's description is for, and it used to
			// stop at the bundle instead of reaching the report.
			if f.Description == "" {
				t.Error("a finding must carry the control's description")
			}
		}
	}
	if !found {
		t.Error("CIS-1.1.15 produced no finding for PRJ/app")
	}
}

// A scan that runs and finds HIGH failures exits 1: that is the CI contract.
func TestFailOnSeverityDrivesExitCode(t *testing.T) {
	fixture := writeSnapshotFixture(t)

	if _, _, code := run(t, "scan", "--snapshot-in", fixture, "-o", "json", "-c", configWithFailOn(t, "high")); code != ExitFindings {
		t.Errorf("exit code = %d, want %d for HIGH failures", code, ExitFindings)
	}
	if _, _, code := run(t, "scan", "--snapshot-in", fixture, "-o", "json", "-c", configWithFailOn(t, "none")); code != ExitOK {
		t.Errorf("exit code = %d, want %d with --fail-on none", code, ExitOK)
	}
}

func TestScanWritesReportToFile(t *testing.T) {
	fixture := writeSnapshotFixture(t)
	out := filepath.Join(t.TempDir(), "nested", "report.sarif")

	if _, _, code := run(t, "scan", "--snapshot-in", fixture, "-o", "sarif", "--output-file", out, "-c", configWithFailOn(t, "none")); code != ExitOK {
		t.Fatalf("exit code = %d", code)
	}

	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("report file was not created: %v", err)
	}
	var log map[string]any
	if err := json.Unmarshal(raw, &log); err != nil {
		t.Fatalf("SARIF file does not parse: %v", err)
	}
	if log["version"] != "2.1.0" {
		t.Errorf("SARIF version = %v", log["version"])
	}

	// A rendered report names every repository that can be force-pushed and
	// every account that should have been deactivated. That is the same map of
	// weak points the snapshot is, so it gets the same permissions.
	assertOwnerOnly(t, out, "report")
}

// assertOwnerOnly checks that a file the tool wrote is readable by its owner
// alone.
//
// It is a no-op on Windows, and that is a statement about the platform rather
// than a way of getting the test to pass. Windows has no Unix permission bits:
// Go's os package maps the mode argument to the read-only attribute and
// nothing else, so a file created with 0600 reports 0666 and its real access
// control comes from the ACL it inherits from its directory. Restricting it
// properly means writing a Windows ACL through golang.org/x/sys/windows, which
// is a feature this has not implemented — so the honest thing is to skip the
// assertion here and say so in the documentation, rather than assert something
// weaker and let the promise look kept.
func assertOwnerOnly(t *testing.T, path, what string) {
	t.Helper()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", what, err)
	}
	if runtime.GOOS == "windows" {
		t.Logf("%s permissions are not enforced on Windows (got %o); see the note in the README",
			what, info.Mode().Perm())
		return
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("%s permissions = %o, want 600", what, perm)
	}
}

func TestScanRoundTripsSnapshotOut(t *testing.T) {
	fixture := writeSnapshotFixture(t)
	out := filepath.Join(t.TempDir(), "copy.json")

	if _, _, code := run(t, "scan", "--snapshot-in", fixture, "--snapshot-out", out, "-o", "json", "-c", configWithFailOn(t, "none")); code != ExitOK {
		t.Fatalf("exit code = %d", code)
	}

	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("snapshot was not written: %v", err)
	}
	var snapshot scm.Snapshot
	if err := json.Unmarshal(raw, &snapshot); err != nil {
		t.Fatalf("written snapshot does not parse: %v", err)
	}
	if snapshot.SchemaVersion != scm.SchemaVersion {
		t.Errorf("schema version = %q", snapshot.SchemaVersion)
	}

	// A snapshot records an instance's weak points; it must not be world-readable.
	assertOwnerOnly(t, out, "snapshot")
}

func TestScanRejectsBadArguments(t *testing.T) {
	fixture := writeSnapshotFixture(t)

	tests := []struct {
		name string
		args []string
	}{
		{"no url and no snapshot", []string{"scan"}},
		{"unknown format", []string{"scan", "--snapshot-in", fixture, "-o", "yaml"}},
		{"unknown fail-on in the config", []string{"scan", "--snapshot-in", fixture, "-c", configWithFailOn(t, "critical")}},
		{"zero concurrency in the config", []string{"scan", "--snapshot-in", fixture, "-c", configWithScan(t, "concurrency: 0")}},
		{"missing snapshot file", []string{"scan", "--snapshot-in", "/nonexistent/snapshot.json"}},
		// A repository that names no project left the filter empty, and an
		// empty filter is not "that one repository", it is no filter at all —
		// so the scan quietly covered the whole instance.
		{"repository without a project", []string{"scan", "--url", "https://example.invalid", "--token", "t", "-r", "payments-api"}},
		{"repository with no slug", []string{"scan", "--url", "https://example.invalid", "--token", "t", "-r", "PRJ/"}},
		// Narrowing flags against a snapshot had nothing to act on and were
		// ignored in silence: the report covered every repository in the file
		// and looked exactly like the narrowed scan that had been asked for.
		{"project against a snapshot", []string{"scan", "--snapshot-in", fixture, "-p", "PRJ"}},
		{"repository against a snapshot", []string{"scan", "--snapshot-in", fixture, "-r", "PRJ/app"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, code := run(t, tc.args...); code != ExitError {
				t.Errorf("exit code = %d, want %d", code, ExitError)
			}
		})
	}
}

func TestScanRejectsSnapshotWithWrongSchemaVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.json")
	if err := os.WriteFile(path, []byte(`{"schemaVersion":"0","metadata":{"platform":"azure-devops"}}`), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, _, code := run(t, "scan", "--snapshot-in", path); code != ExitError {
		t.Error("a snapshot from an incompatible schema version should be rejected, not misread")
	}
}

// The refusal is the only thing the reader gets — refusing rather than
// degrading means there is no partial report to fall back on — so it has to
// say what to do about it. --last lands here on the first run after an upgrade
// without having picked the file, and a bare version mismatch strands that
// person with a path they did not choose.
func TestSchemaVersionRefusalSaysHowToRecover(t *testing.T) {
	_, err := parseSnapshot([]byte(`{"schemaVersion":"0","metadata":{"platform":"azure-devops"}}`), "the snapshot")
	if err == nil {
		t.Fatal("an incompatible schema version was accepted")
	}
	for _, want := range []string{"schema version", "Capture it again with this build"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not mention %q:\n%s", want, err)
		}
	}
}

func TestTableOutputIsHumanReadable(t *testing.T) {
	fixture := writeSnapshotFixture(t)
	stdout, _, _ := run(t, "scan", "--snapshot-in", fixture, "-c", configWithFailOn(t, "none"))

	// Line-oriented: each failure carries its resource, control, reason and
	// one-line fix; the score block closes the report. "Branch permissions"
	// is in a fix line.
	for _, want := range []string{"SCORE", "11 failed", "PRJ/app", "fix: ", "Project settings -> Repositories", "--details"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("table output is missing %q\n---\n%s", want, stdout)
		}
	}
	// The per-resource sections and the full remediation paragraphs are
	// --details territory. Wrapping can split a phrase across lines, so the
	// paragraph is looked for in the flattened text.
	if strings.Contains(stdout, "Total: ") {
		t.Errorf("the default output should be the overview, not per-resource sections\n---\n%s", stdout)
	}
	if strings.Contains(flatten(stdout), "which makes Azure Repos accept changes only through pull requests") {
		t.Errorf("the full remediation paragraph leaked into the overview\n---\n%s", stdout)
	}
	// Colour is off when stdout is not a terminal.
	if strings.Contains(stdout, "\033[") {
		t.Error("ANSI escapes leaked into non-terminal output")
	}
}

func TestScanDetailsRestoresPerResourceSections(t *testing.T) {
	fixture := writeSnapshotFixture(t)
	stdout, _, code := run(t, "scan", "--snapshot-in", fixture, "-c", configWithFailOn(t, "none"), "--details")

	if code != ExitOK {
		t.Fatalf("exit code = %d, want %d", code, ExitOK)
	}
	// Per-resource sections, and the remediation paragraphs at full length.
	// The paragraph is matched against flattened text because wrapping may
	// split it anywhere.
	for _, want := range []string{"PRJ/app", "Total: "} {
		if !strings.Contains(stdout, want) {
			t.Errorf("--details output is missing %q\n---\n%s", want, stdout)
		}
	}
	if !strings.Contains(flatten(stdout), "which makes Azure Repos accept changes only through pull requests") {
		t.Errorf("--details output is missing the full remediation paragraph\n---\n%s", stdout)
	}
}

// flatten collapses all whitespace to single spaces, so a phrase can be found
// no matter where the renderer wrapped it.
func flatten(s string) string { return strings.Join(strings.Fields(s), " ") }

func TestScanDetailsFilter(t *testing.T) {
	fixture := writeSnapshotFixture(t)

	stdout, _, code := run(t, "scan", "--snapshot-in", fixture, "-c", configWithFailOn(t, "none"), "--details=CIS-1.1.15")
	if code != ExitOK {
		t.Fatalf("exit code = %d, want %d", code, ExitOK)
	}
	if !strings.Contains(stdout, "Total: ") {
		t.Errorf("the named control got no section\n---\n%s", stdout)
	}

	// The wording of the error is pinned by the report package's own tests;
	// what matters here is that nothing rendered and the exit code says broken
	// scan rather than clean one.
	out, _, code := run(t, "scan", "--snapshot-in", fixture, "-c", configWithFailOn(t, "none"), "--details=bogus")
	if code != ExitError {
		t.Errorf("a filter matching nothing should exit %d, got %d", ExitError, code)
	}
	if strings.Contains(out, "SCORE") {
		t.Errorf("a rejected filter still rendered a report\n---\n%s", out)
	}
}

func TestScanDetailsFlagValidation(t *testing.T) {
	fixture := writeSnapshotFixture(t)

	if _, stderr, code := run(t, "scan", "--snapshot-in", fixture, "--details", "-o", "json"); code != ExitError {
		t.Errorf("--details with -o json should be refused, got exit %d\n---\n%s", code, stderr)
	}
	if _, stderr, code := run(t, "scan", "--snapshot-in", fixture, "--max-resources", "1"); code != ExitError {
		t.Errorf("--max-resources without --details should be refused, got exit %d\n---\n%s", code, stderr)
	}
	if _, stderr, code := run(t, "scan", "--snapshot-in", fixture, "-c", configWithFailOn(t, "none"), "--max-resources", "1", "--details"); code != ExitOK {
		t.Errorf("--max-resources with --details should be accepted, got exit %d\n---\n%s", code, stderr)
	}
}

func TestListChecksCoversTheBundle(t *testing.T) {
	stdout, _, code := run(t, "list-checks")
	if code != ExitOK {
		t.Fatalf("exit code = %d", code)
	}
	for _, want := range []string{"CIS-1.1.3", "CIS-1.3.9", "SEVERITY", "controls"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("list-checks output is missing %q", want)
		}
	}

	jsonOut, _, _ := run(t, "list-checks", "--json")
	var loaded []map[string]any
	if err := json.Unmarshal([]byte(jsonOut), &loaded); err != nil {
		t.Fatalf("list-checks --json does not parse: %v", err)
	}
	if len(loaded) < 20 {
		t.Errorf("bundle exposes %d checks, want at least 20", len(loaded))
	}
}

func TestVersionCommand(t *testing.T) {
	stdout, _, code := run(t, "version")
	if code != ExitOK {
		t.Fatalf("exit code = %d", code)
	}
	if !strings.Contains(stdout, "azure-devops-bench") {
		t.Errorf("version output = %q", stdout)
	}
}

// The reported symptom: a twenty-repository scan announced "130 control(s)
// failed" when the whole bundle holds twenty controls. Score.Failed counts
// findings — one control per resource — and calling those "controls" made a
// number that could not be true.
func TestFailureSummaryCountsControlsAndFindingsSeparately(t *testing.T) {
	rep := &engine.Report{
		Findings: []engine.Finding{
			{CheckID: "CIS-1.1.15", Status: engine.StatusFail, Resource: "PRJ/a"},
			{CheckID: "CIS-1.1.15", Status: engine.StatusFail, Resource: "PRJ/b"},
			{CheckID: "CIS-1.1.15", Status: engine.StatusFail, Resource: "PRJ/c"},
			{CheckID: "CIS-1.1.16", Status: engine.StatusFail, Resource: "PRJ/a"},
			{CheckID: "CIS-1.1.3", Status: engine.StatusPass, Resource: "PRJ/a"},
		},
	}
	rep.Score = engine.Compute(rep.Findings)

	got := failureSummary(rep, "high")
	if !strings.Contains(got, "2 controls failed") {
		t.Errorf("summary = %q, want it to name 2 controls, not 4", got)
	}
	if !strings.Contains(got, "across 4 findings") {
		t.Errorf("summary = %q, want the spread reported as findings", got)
	}
}

// One control failing on one resource should not read as "1 control failed
// across 1 finding", which is noise dressed up as precision.
func TestFailureSummaryOmitsTheSpreadWhenThereIsNone(t *testing.T) {
	rep := &engine.Report{
		Findings: []engine.Finding{{CheckID: "CIS-1.1.15", Status: engine.StatusFail, Resource: "PRJ/a"}},
	}
	rep.Score = engine.Compute(rep.Findings)

	got := failureSummary(rep, "high")
	if strings.Contains(got, "across") {
		t.Errorf("summary = %q, want no spread clause for a single finding", got)
	}
	if !strings.Contains(got, "1 control failed") {
		t.Errorf("summary = %q, want the singular", got)
	}
}

// The default output is the result, not an account of what the tool did. The
// request log describes the tool; someone running a benchmark wants to know
// what it found, and only reaches for the requests when something looks wrong
// — which is when --verbose gets typed.
func TestRequestLogIsOffByDefaultAndOnWithVerbose(t *testing.T) {
	fixture := writeSnapshotFixture(t)

	// --snapshot-in makes no requests at all, so the flag wiring is what is
	// under test here: which progress mode each invocation resolves to.
	if got := config.Default().Scan.Progress; got != ProgressCompact {
		t.Errorf("scan.progress defaults to %q, want %q — full is a wall of GET lines", got, ProgressCompact)
	}

	_, stderr, _ := run(t, "scan", "--snapshot-in", fixture, "-c", configWithFailOn(t, "none"))
	if strings.Contains(stderr, "GET ") {
		t.Errorf("the request log appeared without --verbose:\n%s", stderr)
	}
}

// The findings message is what a user reads when a scan exits 1, and nothing
// exercised it: the tests took the exit code and dropped the error.
func TestExitCodeErrorCarriesBothTheCodeAndTheMessage(t *testing.T) {
	err := &exitCodeError{code: ExitFindings, msg: "2 controls failed"}

	if got := err.Error(); got != "2 controls failed" {
		t.Errorf("Error() = %q, want the message a user reads", got)
	}
	if got := ExitCode(err); got != ExitFindings {
		t.Errorf("ExitCode = %d, want %d", got, ExitFindings)
	}
	// Wrapped is the shape it actually travels in, out through cobra's RunE.
	if got := ExitCode(fmt.Errorf("scan: %w", err)); got != ExitFindings {
		t.Errorf("ExitCode through a wrap = %d, want %d", got, ExitFindings)
	}
	// Anything else is a scan that failed, not findings.
	if got := ExitCode(errors.New("boom")); got != ExitError {
		t.Errorf("ExitCode of a plain error = %d, want %d", got, ExitError)
	}
}

// StderrWriter is what main uses for the process's last line. It is only
// reachable from main, so nothing here had ever constructed it.
func TestStderrWriterHonoursNoColor(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	if StderrWriter().P.Enabled {
		t.Error("NO_COLOR set but the final line would still be coloured")
	}

	t.Setenv("NO_COLOR", "")
	// Still false here, because the test process's stderr is not a terminal —
	// which is the other half of the rule and the case CI runs in.
	if StderrWriter().P.Enabled {
		t.Error("colour enabled while stderr is not a terminal")
	}
}

// MANUAL is excluded from both sides of the score, which is right control by
// control — an organization should not be marked down for a question its API
// cannot answer — and perverse in aggregate, because it shrinks the
// denominator. The fixture below makes the point: with almost nothing
// readable, two controls stay decidable, both pass, and a scan that saw almost
// nothing reports a perfect 100 and exits 0.
//
// Note which threshold catches it. scan.failUnder cannot: the score is 100.
// Only scan.maxManual asks the question that matters here, which is not "is
// the score good" but "did the scan see enough for the score to mean
// anything".
func TestScanThresholds(t *testing.T) {
	normal := writeSnapshotFixture(t)
	blind := writeSnapshotWith(t, func(s *scm.Snapshot) {
		s.Organization.Available = map[string]bool{}
		for i := range s.Projects {
			for j := range s.Projects[i].Repositories {
				r := &s.Projects[i].Repositories[j]
				r.Available = map[string]bool{"mergeStrategies": true, "files": true}
				r.PullRequestSettings.MergeStrategies = []scm.MergeStrategy{{ID: "squash", Enabled: true}}
				r.Files = scm.Files{SecurityPolicyPaths: []string{"SECURITY.md"}, Probed: []string{"SECURITY.md"}}
			}
		}
	})

	// Stated rather than assumed, because every expectation below rests on it.
	if got := scoreOf(t, blind); got != 100 {
		t.Fatalf("blind fixture scores %d, want 100; the rest of this test assumes it", got)
	}
	if got := scoreOf(t, normal); got != 46 {
		t.Fatalf("readable fixture scores %d, want 46", got)
	}

	for _, tc := range []struct {
		name string
		args []string
		want int
	}{
		{"failures trip fail-on", []string{"scan", "--snapshot-in", normal}, ExitFindings},
		{"fail-on none clears them", []string{"scan", "--snapshot-in", normal, "-c", configWithFailOn(t, "none")}, ExitOK},
		{"score below failUnder", []string{"scan", "--snapshot-in", normal, "-c", configWithScan(t, "failOn: none", "failUnder: 50")}, ExitFindings},
		{"score above failUnder", []string{"scan", "--snapshot-in", normal, "-c", configWithScan(t, "failOn: none", "failUnder: 20")}, ExitOK},

		// The pathology, and the only thing that catches it.
		{"blind scan passes by default", []string{"scan", "--snapshot-in", blind}, ExitOK},
		{"failUnder cannot catch a blind scan", []string{"scan", "--snapshot-in", blind, "-c", configWithScan(t, "failUnder: 100")}, ExitOK},
		{"maxManual catches it", []string{"scan", "--snapshot-in", blind, "-c", configWithScan(t, "maxManual: 50")}, ExitFindings},
		{"maxManual generous enough", []string{"scan", "--snapshot-in", blind, "-c", configWithScan(t, "maxManual: 95")}, ExitOK},

		{"failUnder out of range", []string{"scan", "--snapshot-in", normal, "-c", configWithScan(t, "failUnder: 101")}, ExitError},
		{"maxManual out of range", []string{"scan", "--snapshot-in", normal, "-c", configWithScan(t, "maxManual: -2")}, ExitError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, code := run(t, tc.args...); code != tc.want {
				t.Errorf("exit code = %d, want %d", code, tc.want)
			}
		})
	}
}

func scoreOf(t *testing.T, snapshotPath string) int {
	t.Helper()
	out, _, _ := run(t, "scan", "--snapshot-in", snapshotPath, "-o", "json", "-c", configWithFailOn(t, "none"))
	var rep struct {
		Score struct {
			Value int `json:"value"`
		} `json:"score"`
	}
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("decode report: %v", err)
	}
	return rep.Score.Value
}

// A policy that could not run is a broken tool, not a finding about the
// instance. It degrades to MANUAL so the rest of the report survives, but
// MANUAL leaves the score's denominator — so a bundle that failed to evaluate
// raises the score and used to exit 0. A green pipeline is the one thing that
// must not come out of a scan that did not work.
func TestPolicyErrorsFailTheScan(t *testing.T) {
	rep := &engine.Report{
		Score:  engine.Score{Value: 100, Passed: 1},
		Errors: []string{"CIS-1.1.15 on PRJ/app: policy produced no result"},
	}
	err := exitStatus(rep, &scanOptions{scan: config.Scan{FailOn: "high", MaxManual: -1}})
	if err == nil {
		t.Fatal("exitStatus returned nil for a report carrying policy errors")
	}
	if code := ExitCode(err); code != ExitError {
		t.Errorf("exit code = %d, want %d", code, ExitError)
	}
	if !strings.Contains(err.Error(), "policy produced no result") {
		t.Errorf("error does not carry the reason: %v", err)
	}
}

// A typed --token beats the exported AZURE_DEVOPS_TOKEN, and the exported one
// is still used when nothing is typed: cobra fills the flag default from the
// environment at construction, which is the whole mechanism.
func TestTypedTokenBeatsTheEnvironment(t *testing.T) {
	for _, tc := range []struct {
		name string
		env  string
		args []string
		want string
	}{
		{"typed wins", "stale", []string{"--token", "fresh"}, "fresh"},
		{"inherited is used", "inherited", nil, "inherited"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("AZURE_DEVOPS_TOKEN", tc.env)
			var got string
			cmd := newScanCommand()
			cmd.RunE = func(c *cobra.Command, _ []string) error {
				got, _ = c.Flags().GetString("token")
				return nil
			}
			cmd.SetArgs(tc.args)
			cmd.SetOut(io.Discard)
			cmd.SetErr(io.Discard)
			if err := cmd.Execute(); err != nil {
				t.Fatalf("execute: %v", err)
			}
			if got != tc.want {
				t.Errorf("token = %q, want %q", got, tc.want)
			}
		})
	}
}

// The retired flags answer with directions, not cobra's bare "unknown flag":
// muscle memory and old pipelines both deserve to be told where the setting
// went.
func TestMovedFlagsAreAnsweredWithTheConfigKey(t *testing.T) {
	// The error text travels in the returned error — the root command
	// silences cobra's own printing and main renders it — so it is read
	// from Execute directly rather than from the captured stderr.
	execute := func(args ...string) error {
		root := NewRootCommand()
		root.SetOut(io.Discard)
		root.SetErr(io.Discard)
		root.SetIn(strings.NewReader(""))
		root.SetArgs(args)
		return root.Execute()
	}

	fixture := writeSnapshotFixture(t)
	err := execute("scan", "--snapshot-in", fixture, "--fail-on", "none")
	if err == nil {
		t.Fatal("a retired flag was accepted")
	}
	for _, want := range []string{"scan.failOn", "azure-devops-bench init", "--set scan.failOn="} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error does not mention %q: %v", want, err)
		}
	}

	// A genuinely unknown flag keeps cobra's own message.
	if err := execute("scan", "--no-such-flag"); err == nil || strings.Contains(err.Error(), "moved to the config file") {
		t.Errorf("an unknown flag was claimed to have moved: %v", err)
	}
}

// An unadorned scan finds the project's config on its own and says so; an
// explicit --config wins over anything discoverable.
func TestScanDiscoversTheWorkingDirectoryConfig(t *testing.T) {
	fixture := writeSnapshotFixture(t)

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "azure-devops-bench.yaml"), []byte("scan:\n  failOn: none\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	t.Chdir(dir)

	_, stderr, code := run(t, "scan", "--snapshot-in", fixture)
	if code != ExitOK {
		t.Fatalf("exit code = %d, want %d via the discovered failOn: none\n%s", code, ExitOK, stderr)
	}
	if !strings.Contains(stderr, "using config azure-devops-bench.yaml") {
		t.Errorf("stderr never says which config was discovered:\n%s", stderr)
	}

	// --config beats discovery: the working directory says none, the named
	// file says high, and high is what must decide the exit code.
	_, stderr, code = run(t, "scan", "--snapshot-in", fixture, "-c", configWithFailOn(t, "high"))
	if code != ExitFindings {
		t.Errorf("exit code = %d, want %d from the explicit config", code, ExitFindings)
	}
	if strings.Contains(stderr, "using config azure-devops-bench.yaml") {
		t.Errorf("an explicit --config still triggered discovery:\n%s", stderr)
	}
}

// The user-level config is the fallback when the working directory has none.
func TestScanDiscoversTheUserConfig(t *testing.T) {
	fixture := writeSnapshotFixture(t)
	t.Chdir(t.TempDir()) // an empty working directory

	// AZURE_DEVOPS_BENCH_CONFIG_DIR is pinned by TestMain; config.yaml inside it is
	// the user-level file.
	path := filepath.Join(os.Getenv("AZURE_DEVOPS_BENCH_CONFIG_DIR"), "config.yaml")
	if err := os.WriteFile(path, []byte("scan:\n  failOn: none\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	t.Cleanup(func() { os.Remove(path) })

	_, stderr, code := run(t, "scan", "--snapshot-in", fixture)
	if code != ExitOK {
		t.Fatalf("exit code = %d, want %d via the user config\n%s", code, ExitOK, stderr)
	}
	if !strings.Contains(stderr, "using config "+path) {
		t.Errorf("stderr never names the user config:\n%s", stderr)
	}
}

func TestInitWritesTheTemplateAndRefusesToOverwrite(t *testing.T) {
	t.Chdir(t.TempDir())

	_, stderr, code := run(t, "init")
	if code != ExitOK {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}
	if !strings.Contains(stderr, "wrote azure-devops-bench.yaml") {
		t.Errorf("init never says what it wrote:\n%s", stderr)
	}
	raw, err := os.ReadFile("azure-devops-bench.yaml")
	if err != nil {
		t.Fatalf("the template was not written: %v", err)
	}
	for _, want := range []string{"scan:", "failOn: high", "concurrency: 4", "#thresholds:"} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("template is missing %q", want)
		}
	}

	// The template must load cleanly and reproduce the defaults exactly —
	// otherwise init writes a file that silently changes behaviour.
	cfg, err := config.Load("azure-devops-bench.yaml")
	if err != nil {
		t.Fatalf("the template does not load: %v", err)
	}
	if def := config.Default(); cfg.Scan != def.Scan {
		t.Errorf("template scan section = %+v, want the defaults %+v", cfg.Scan, def.Scan)
	}

	// Refuse the second run: a config that changes how an audit judges an
	// instance is not something scaffolding should replace.
	if err := os.WriteFile("azure-devops-bench.yaml", []byte("scan:\n  failOn: none\n"), 0o600); err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	if _, _, code := run(t, "init"); code != ExitError {
		t.Errorf("exit code = %d, want %d for an existing file", code, ExitError)
	}
	raw, _ = os.ReadFile("azure-devops-bench.yaml")
	if !strings.Contains(string(raw), "failOn: none") {
		t.Error("init overwrote an existing config")
	}
}

// --set is the one-off path: any config key, no file.
func TestSetOverridesConfigForOneRun(t *testing.T) {
	fixture := writeSnapshotFixture(t)

	// No config anywhere; the fixture carries HIGH failures, so only the
	// override can produce exit 0.
	if _, _, code := run(t, "scan", "--snapshot-in", fixture, "--set", "scan.failOn=none"); code != ExitOK {
		t.Errorf("exit code = %d, want %d via --set", code, ExitOK)
	}

	// --set beats the file it rides with.
	if _, _, code := run(t, "scan", "--snapshot-in", fixture, "-c", configWithFailOn(t, "none"), "--set", "scan.failOn=high"); code != ExitFindings {
		t.Errorf("exit code = %d, want %d: --set should beat the file", code, ExitFindings)
	}

	// A bad key refuses the scan rather than being shrugged off.
	if _, _, code := run(t, "scan", "--snapshot-in", fixture, "--set", "scan.failsOn=none"); code != ExitError {
		t.Errorf("exit code = %d, want %d for an unknown key", code, ExitError)
	}
}

// seedSnapshotCache plants a snapshot in the --last cache, exactly as a
// finished network scan would have left it. The caller must have pinned
// AZURE_DEVOPS_BENCH_CONFIG_DIR to a fresh directory first.
func seedSnapshotCache(t *testing.T, baseURL string, mutate func(*scm.Snapshot)) string {
	t.Helper()
	fixture := writeSnapshotWith(t, mutate)
	raw, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	path, err := config.SnapshotCachePath(baseURL)
	if err != nil {
		t.Fatalf("cache path: %v", err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("seed cache: %v", err)
	}
	return path
}

// executeErr runs the CLI for its error, for tests about the message rather
// than the report.
func executeErr(t *testing.T, args ...string) error {
	t.Helper()
	root := NewRootCommand()
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	root.SetIn(strings.NewReader(""))
	root.SetArgs(args)
	return root.Execute()
}

func TestScanLastRendersTheCachedSnapshot(t *testing.T) {
	t.Setenv("AZURE_DEVOPS_BENCH_CONFIG_DIR", t.TempDir())
	seedSnapshotCache(t, "https://dev.azure.com/fabrikam", func(s *scm.Snapshot) {
		s.Metadata.GeneratedAt = time.Now().Add(-30 * time.Minute)
	})

	stdout, stderr, code := run(t, "scan", "--last", "-o", "json", "-c", configWithFailOn(t, "none"))
	if code != ExitOK {
		t.Fatalf("exit code = %d, want %d; stderr:\n%s", code, ExitOK, stderr)
	}
	if !strings.Contains(stdout, "PRJ/app") {
		t.Errorf("the report does not cover the cached snapshot's repository:\n%s", stdout)
	}
	if !strings.Contains(stderr, "captured 30m ago") {
		t.Errorf("stderr does not state the snapshot's age: %q", stderr)
	}
	if strings.Contains(stderr, "scan again for current state") {
		t.Errorf("a half-hour-old snapshot was warned about as stale: %q", stderr)
	}
}

func TestScanLastWarnsWhenTheSnapshotIsStale(t *testing.T) {
	t.Setenv("AZURE_DEVOPS_BENCH_CONFIG_DIR", t.TempDir())
	// The fixture's GeneratedAt is fixed in the past, well over the
	// staleness threshold.
	seedSnapshotCache(t, "https://dev.azure.com/fabrikam", nil)

	_, stderr, code := run(t, "scan", "--last", "-o", "json", "-c", configWithFailOn(t, "none"))
	if code != ExitOK {
		t.Fatalf("exit code = %d, want %d; stderr:\n%s", code, ExitOK, stderr)
	}
	if !strings.Contains(stderr, "scan again for current state") {
		t.Errorf("an old snapshot came with no staleness warning: %q", stderr)
	}
}

func TestScanLastPicksTheNewestCache(t *testing.T) {
	t.Setenv("AZURE_DEVOPS_BENCH_CONFIG_DIR", t.TempDir())
	older := seedSnapshotCache(t, "https://old.example.com", func(s *scm.Snapshot) {
		s.Metadata.BaseURL = "https://old.example.com"
	})
	past := time.Now().Add(-time.Hour)
	if err := os.Chtimes(older, past, past); err != nil {
		t.Fatalf("age cache file: %v", err)
	}
	seedSnapshotCache(t, "https://new.example.com", func(s *scm.Snapshot) {
		s.Metadata.BaseURL = "https://new.example.com"
	})

	_, stderr, code := run(t, "scan", "--last", "-o", "json", "-c", configWithFailOn(t, "none"))
	if code != ExitOK {
		t.Fatalf("exit code = %d, want %d; stderr:\n%s", code, ExitOK, stderr)
	}
	if !strings.Contains(stderr, "https://new.example.com") {
		t.Errorf("--last did not render the most recent scan: %q", stderr)
	}
}

func TestScanLastWithNothingCached(t *testing.T) {
	t.Setenv("AZURE_DEVOPS_BENCH_CONFIG_DIR", t.TempDir())

	err := executeErr(t, "scan", "--last")
	if err == nil {
		t.Fatal("--last with an empty cache did not error")
	}
	for _, want := range []string{"none has been cached yet", "scan.cache"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error does not mention %q: %v", want, err)
		}
	}
}

func TestScanLastRefusesCaptureFlags(t *testing.T) {
	t.Setenv("AZURE_DEVOPS_BENCH_CONFIG_DIR", t.TempDir())
	fixture := writeSnapshotFixture(t)
	cases := [][]string{
		{"--url", "https://dev.azure.com/fabrikam"},
		{"--token", "t"},
		{"--project", "PRJ"},
		{"--snapshot-in", fixture},
	}
	for _, extra := range cases {
		err := executeErr(t, append([]string{"scan", "--last"}, extra...)...)
		if err == nil || !strings.Contains(err.Error(), "--last renders") {
			t.Errorf("--last with %s: err = %v, want the has-nothing-to-act-on refusal", extra[0], err)
		}
	}

	if err := executeErr(t, "scan", "--demo", "--last"); err == nil || !strings.Contains(err.Error(), "--last has nothing to act on") {
		t.Errorf("--demo --last: err = %v, want the demo refusal", err)
	}
}

// The demo must never populate the cache: --last would then pass off the
// bundled example as somebody's instance. A replayed snapshot is excluded
// for a quieter reason — it would only rewrite what it just read.
func TestScanDemoAndReplayLeaveNoCache(t *testing.T) {
	t.Setenv("AZURE_DEVOPS_BENCH_CONFIG_DIR", t.TempDir())

	if _, _, code := run(t, "scan", "--demo", "-c", configWithFailOn(t, "none")); code != ExitOK {
		t.Fatalf("demo exit code = %d, want %d", code, ExitOK)
	}
	fixture := writeSnapshotFixture(t)
	if _, _, code := run(t, "scan", "--snapshot-in", fixture, "-c", configWithFailOn(t, "none")); code != ExitOK {
		t.Fatalf("replay exit code = %d, want %d", code, ExitOK)
	}

	if path, err := config.LatestSnapshotCache(); err != nil || path != "" {
		t.Errorf("cache after demo and replay: path = %q, err = %v; want none", path, err)
	}
}
