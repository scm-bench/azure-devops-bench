package cli

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/scm-bench/azure-devops-bench/internal/scm"
)

// runRoot executes the CLI and returns the error itself, for the tests that
// read its message.
func runRoot(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	root := NewRootCommand()
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetIn(strings.NewReader(""))
	root.SetArgs(args)
	err := root.Execute()
	return stdout.String(), stderr.String(), err
}

// A scan that evaluated no repository audited nothing the repository controls
// cover, and a scan that could not list a project's repositories is missing
// them without a trace in any finding. The report is still written; the exit
// code is what a pipeline reads.
func TestScansThatCannotVouchForTheirCoverageExitTwo(t *testing.T) {
	empty := writeSnapshotWith(t, func(s *scm.Snapshot) { s.Projects = nil })
	allDisabled := writeSnapshotWith(t, func(s *scm.Snapshot) {
		s.Projects[0].Repositories[0].Archived = true
		s.Projects[0].Repositories[0].Disabled = true
	})
	partial := writeSnapshotWith(t, func(s *scm.Snapshot) { s.Metadata.Unlisted = []string{"Locked-Project"} })

	for _, tc := range []struct {
		name string
		args []string
		want int
		msg  string
	}{
		{"no repository", []string{"scan", "--snapshot-in", empty, "-c", configWithFailOn(t, "none")}, ExitError, "no repository was evaluated"},
		{"every repository skipped", []string{"scan", "--snapshot-in", allDisabled, "-c", configWithFailOn(t, "none")}, ExitError, "skipArchivedRepositories"},
		{"unlisted project", []string{"scan", "--snapshot-in", partial, "-c", configWithFailOn(t, "none")}, ExitError, "Locked-Project"},
		{"unlisted project accepted", []string{"scan", "--snapshot-in", partial, "-c", configWithScan(t, "failOn: none", "allowIncomplete: true")}, ExitOK, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stdout, _, err := runRoot(t, tc.args...)
			if code := ExitCode(err); code != tc.want {
				t.Errorf("exit code = %d, want %d (err %v)", code, tc.want, err)
			}
			if tc.msg != "" && (err == nil || !strings.Contains(err.Error(), tc.msg)) {
				t.Errorf("error %v does not mention %q", err, tc.msg)
			}
			if strings.TrimSpace(stdout) == "" {
				t.Error("the report must still be written")
			}
		})
	}
}

// A report or snapshot written over an existing world-readable file used to
// keep the old mode. On a shared CI agent that left a map of the
// organization's weak points readable by everyone.
func TestOutputsOverwriteExistingFilesAsPrivate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits")
	}
	dir := t.TempDir()
	report := filepath.Join(dir, "report.json")
	snapshot := filepath.Join(dir, "snapshot.json")
	for _, path := range []string{report, snapshot} {
		if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
			t.Fatal(err)
		}
		os.Chmod(path, 0o644)
	}
	src := writeSnapshotFixture(t)
	run(t, "scan", "--snapshot-in", src, "-o", "json", "--output-file", report, "-c", configWithFailOn(t, "none"))
	s, err := readSnapshot(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeSnapshot(snapshot, s); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{report, snapshot} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if mode := info.Mode().Perm(); mode != 0o600 {
			t.Errorf("%s mode = %o, want 600", filepath.Base(path), mode)
		}
		if raw, _ := os.ReadFile(path); string(raw) == "old" {
			t.Errorf("%s was not rewritten", filepath.Base(path))
		}
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 2 {
		t.Errorf("directory holds %d entries, want only the two outputs", len(entries))
	}
}

// A config file a pull request drops into the working directory changes how
// the CI gate judges the organization; a scan names the file it used, whether
// it found it or was handed it.
func TestScanNamesTheConfigItWasGiven(t *testing.T) {
	cfg := configWithFailOn(t, "none")
	_, stderr, _ := run(t, "scan", "--snapshot-in", writeSnapshotFixture(t), "-c", cfg)
	if !strings.Contains(stderr, "using config "+cfg) {
		t.Errorf("stderr does not name the config:\n%s", stderr)
	}
}

// A CA bundle that cannot be used is a configuration error found at startup,
// not a certificate failure found mid-scan.
func TestAnUnusableCAFileFailsAtStartup(t *testing.T) {
	bundle := filepath.Join(t.TempDir(), "ca.pem")
	os.WriteFile(bundle, []byte("not a certificate"), 0o600)
	_, _, err := runRoot(t, "scan", "--snapshot-in", writeSnapshotFixture(t), "-c", configWithScan(t, "caFile: "+bundle))
	if ExitCode(err) != ExitError || err == nil || !strings.Contains(err.Error(), "no PEM certificate") {
		t.Errorf("err = %v", err)
	}
}

// A Bitbucket snapshot parses — the schema is shared — and would then be
// evaluated by controls written for Azure DevOps that find nothing to report.
func TestASnapshotFromAnotherPlatformIsRefused(t *testing.T) {
	other := writeSnapshotWith(t, func(s *scm.Snapshot) { s.Metadata.Platform = "bitbucket-dc" })
	_, _, err := runRoot(t, "scan", "--snapshot-in", other)
	if err == nil || !strings.Contains(err.Error(), "bitbucket-dc") {
		t.Errorf("err = %v", err)
	}
}

func configWithExceptions(t *testing.T, exceptions string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "azure-devops-bench.yaml")
	if err := os.WriteFile(path, []byte("scan:\n  failOn: high\n  cache: false\nexceptions:\n"+exceptions), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// The fixture's repository fails every HIGH control. Accepting all of them
// clears the gate; the findings are still in the report, under their own
// heading, and still in the score.
func TestExceptionsClearTheGateButNotTheReport(t *testing.T) {
	snapshot := writeSnapshotFixture(t)
	var accept strings.Builder
	for _, id := range []string{"CIS-1.1.3", "CIS-1.1.9", "CIS-1.1.15", "CIS-1.1.16"} {
		fmt.Fprintf(&accept, "  - control: %s\n    resources: [PRJ/*]\n    reason: migration in progress\n    owner: platform\n    expires: 2999-12-31\n", id)
	}
	stdout, stderr, code := run(t, "scan", "--snapshot-in", snapshot, "-c", configWithExceptions(t, accept.String()))
	if code != ExitOK {
		t.Fatalf("exit code = %d, want %d with every HIGH failure accepted\n%s", code, ExitOK, stderr)
	}
	flat := strings.Join(strings.Fields(stdout), " ")
	for _, want := range []string{"Accepted by exceptions", "accepted until 2999-12-31: migration in progress (platform)", "accepted by exceptions, counted here and in the score"} {
		if !strings.Contains(flat, want) {
			t.Errorf("report does not say %q\n%s", want, stdout)
		}
	}

	// The same exceptions, lapsed: the run fails again and says why, whatever
	// the verbosity.
	lapsed := strings.ReplaceAll(accept.String(), "2999-12-31", "2001-01-01")
	_, stderr, code = run(t, "scan", "--snapshot-in", snapshot, "-c", configWithExceptions(t, lapsed))
	if code != ExitFindings {
		t.Errorf("exit code = %d, want %d once the exceptions lapse", code, ExitFindings)
	}
	if !strings.Contains(stderr, "lapsed on 2001-01-01") {
		t.Errorf("stderr does not report the lapse:\n%s", stderr)
	}
}

// An accepted MANUAL finding has been reviewed by a person; it no longer
// counts as a gap against scan.maxManual. The exceptions are derived from the
// blind scan itself, so the test follows the bundle as controls are added.
func TestAcceptedManualFindingsDoNotCountAgainstMaxManual(t *testing.T) {
	blind := writeSnapshotWith(t, func(s *scm.Snapshot) {
		s.Organization.Available = map[string]bool{}
		r := &s.Projects[0].Repositories[0]
		r.Available = map[string]bool{"mergeStrategies": true, "files": true}
		r.PullRequestSettings.MergeStrategies = []scm.MergeStrategy{{ID: "squash", Enabled: true}}
		r.Files = scm.Files{SecurityPolicyPaths: []string{"SECURITY.md"}, Probed: []string{"SECURITY.md"}}
	})
	out, _, _ := run(t, "scan", "--snapshot-in", blind, "-o", "json", "-c", configWithFailOn(t, "none"))
	var rep struct {
		Findings []struct {
			CheckID   string `json:"checkId"`
			Resource  string `json:"resource"`
			Status    string `json:"status"`
			Automated bool   `json:"automated"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("decode report: %v", err)
	}
	var accept strings.Builder
	for _, f := range rep.Findings {
		if f.Status == "MANUAL" && f.Automated {
			fmt.Fprintf(&accept, "  - control: %s\n    resources: [%q]\n    reason: reviewed by hand\n    expires: 2999-12-31\n", f.CheckID, f.Resource)
		}
	}
	if accept.Len() == 0 {
		t.Fatal("the blind fixture produced no automated MANUAL finding; the test assumes it does")
	}
	gate := "scan:\n  failOn: none\n  maxManual: 10\n"
	write := func(body string) string {
		path := filepath.Join(t.TempDir(), "azure-devops-bench.yaml")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	if _, _, code := run(t, "scan", "--snapshot-in", blind, "-c", write(gate)); code != ExitFindings {
		t.Fatalf("exit code = %d without exceptions, want %d", code, ExitFindings)
	}
	if _, stderr, code := run(t, "scan", "--snapshot-in", blind, "-c", write(gate+"exceptions:\n"+accept.String())); code != ExitOK {
		t.Errorf("exit code = %d; every manual finding was reviewed\n%s", code, stderr)
	}
}

func TestJUnitOutputFromTheCLI(t *testing.T) {
	stdout, _, code := run(t, "scan", "--snapshot-in", writeSnapshotFixture(t), "-o", "junit", "-c", configWithFailOn(t, "none"))
	if code != ExitOK {
		t.Fatalf("exit code = %d", code)
	}
	var doc struct {
		XMLName  xml.Name `xml:"testsuites"`
		Name     string   `xml:"name,attr"`
		Failures int      `xml:"failures,attr"`
	}
	if err := xml.Unmarshal([]byte(stdout), &doc); err != nil {
		t.Fatalf("not XML: %v\n%s", err, stdout)
	}
	if doc.Name != "azure-devops-bench" || doc.Failures == 0 {
		t.Errorf("junit = %+v", doc)
	}
	if _, _, err := runRoot(t, "scan", "--snapshot-in", writeSnapshotFixture(t), "-o", "junit", "--details"); err == nil {
		t.Error("--details shapes the table only")
	}
}

// fakeCollection is the smallest Azure DevOps Server collection a scan can
// complete against: one project, one repository with a required policy, and
// nothing else — every other endpoint answers 404, as a server missing a
// feature does. It exists to test the CLI end to end, not the fetcher.
type fakeCollection struct {
	mu      sync.Mutex
	methods map[string]int
}

func (f *fakeCollection) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.methods[r.Method]++
	f.mu.Unlock()
	reply := func(body any) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		json.NewEncoder(w).Encode(body)
	}
	const pid, rid = "6ce954b1-ce1f-45d1-b94d-e6bf2464ba2c", "278d5cd2-584d-4b63-824a-2ba458937249"
	switch r.URL.Path {
	case "/DefaultCollection/_apis/projects":
		reply(map[string]any{"count": 1, "value": []any{map[string]any{"id": pid, "name": "Fabrikam", "visibility": "private"}}})
	case "/DefaultCollection/" + pid + "/_apis/git/repositories":
		reply(map[string]any{"count": 1, "value": []any{map[string]any{"id": rid, "name": "app", "defaultBranch": "refs/heads/main"}}})
	case "/DefaultCollection/" + pid + "/_apis/git/repositories/" + rid + "/refs":
		reply(map[string]any{"count": 1, "value": []any{map[string]any{"name": "refs/heads/main", "objectId": "abc"}}})
	case "/DefaultCollection/" + pid + "/_apis/git/repositories/" + rid + "/stats/branches":
		reply(map[string]any{"count": 1, "value": []any{map[string]any{"name": "main", "commit": map[string]any{"committer": map[string]any{"date": "2026-09-30T00:00:00Z"}}}}})
	case "/DefaultCollection/" + pid + "/_apis/git/policy/configurations", "/DefaultCollection/" + pid + "/_apis/policy/configurations":
		reply(map[string]any{"count": 1, "value": []any{map[string]any{
			"id": 1, "isEnabled": true, "isBlocking": true,
			"type":     map[string]any{"id": "fa4e907d-c16b-4a4c-9dfa-4906e5d171dd", "displayName": "Minimum number of reviewers"},
			"settings": map[string]any{"minimumApproverCount": 2, "scope": []any{map[string]any{"repositoryId": nil, "refName": nil, "matchKind": "DefaultBranch"}}},
		}}})
	default:
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `{"message":"TF400898: not found"}`)
	}
}

// A network scan, end to end: the snapshot it writes is 0600, its stderr ends
// with the accounting line, and every request it made was a GET.
func TestANetworkScanAccountsForEveryRequest(t *testing.T) {
	t.Setenv("AZURE_DEVOPS_BENCH_CONFIG_DIR", t.TempDir())
	fake := &fakeCollection{methods: map[string]int{}}
	srv := httptest.NewServer(fake)
	defer srv.Close()

	snapshot := filepath.Join(t.TempDir(), "out", "snapshot.json")
	stdout, stderr, err := runRoot(t, "scan", "--url", srv.URL+"/DefaultCollection", "--token", "pat-value",
		"-o", "json", "--snapshot-out", snapshot, "-c", configWithScan(t, "failOn: none"))
	if code := ExitCode(err); code != ExitOK {
		t.Fatalf("exit code = %d (%v)\n%s", code, err, stderr)
	}
	lines := strings.Split(strings.TrimSpace(stderr), "\n")
	last := lines[len(lines)-1]
	if !strings.Contains(last, "GET · 0 writes · read-only") || !strings.HasPrefix(strings.TrimSpace(strings.TrimPrefix(last, "[INFO]")), "✓") {
		t.Errorf("stderr does not end with the accounting line:\n%s", stderr)
	}
	if len(fake.methods) != 1 || fake.methods[http.MethodGet] == 0 {
		t.Errorf("methods = %v", fake.methods)
	}
	if strings.Contains(stdout+stderr, "pat-value") {
		t.Error("the token reached the output")
	}
	var rep struct {
		Metadata scm.Metadata `json:"metadata"`
	}
	if err := json.Unmarshal([]byte(stdout), &rep); err != nil {
		t.Fatalf("decode report: %v", err)
	}
	if rep.Metadata.Deployment != scm.DeploymentServer {
		t.Errorf("deployment = %q", rep.Metadata.Deployment)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(snapshot)
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Errorf("snapshot = %v, %v", info, err)
		}
	}
	// The cache was written too, under the configured directory.
	if path := filepath.Join(os.Getenv("AZURE_DEVOPS_BENCH_CONFIG_DIR"), "cache"); !dirHasJSON(path) {
		t.Errorf("no cached snapshot in %s", path)
	}
}

func dirHasJSON(dir string) bool {
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".json") {
			return true
		}
	}
	return false
}

// A rejected credential is exit 2 with directions, and the accounting line
// still says what was sent.
func TestARejectedCredentialExitsTwo(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusNonAuthoritativeInfo)
		fmt.Fprint(w, "<html>sign in</html>")
	}))
	defer srv.Close()
	_, stderr, err := runRoot(t, "scan", "--url", srv.URL+"/DefaultCollection", "--token", "bad")
	if ExitCode(err) != ExitError || err == nil || !strings.Contains(err.Error(), "credential rejected") {
		t.Fatalf("err = %v", err)
	}
	if !strings.Contains(stderr, "1 requests · 1 GET · 0 writes · read-only") {
		t.Errorf("stderr = %s", stderr)
	}
}

// The exit code and the machine-read report agree about a scan that audited
// nothing: a CI view that draws the SARIF or the JUnit without reading the
// exit code must not show a clean run either.
func TestAScanOfNoRepositoryFailsInTheReportToo(t *testing.T) {
	disabled := writeSnapshotWith(t, func(s *scm.Snapshot) {
		s.Projects[0].Repositories[0].Archived = true
		s.Projects[0].Repositories[0].Disabled = true
	})
	sarif, _, err := runRoot(t, "scan", "--snapshot-in", disabled, "-o", "sarif", "-c", configWithFailOn(t, "none"))
	if ExitCode(err) != ExitError {
		t.Errorf("exit code = %d", ExitCode(err))
	}
	if !strings.Contains(sarif, `"executionSuccessful": false`) || !strings.Contains(sarif, "evaluated no repository") {
		t.Errorf("SARIF does not fail the run:\n%s", sarif)
	}
	junit, _, _ := runRoot(t, "scan", "--snapshot-in", disabled, "-o", "junit", "-c", configWithFailOn(t, "none"))
	if !strings.Contains(junit, `<testcase name="repositories" classname="scan.coverage">`) {
		t.Errorf("JUnit does not fail the run:\n%s", junit)
	}
}

// An exception naming no control — CIS-1.1.31 for CIS-1.1.13 — is refused
// before the organization is contacted, as an include or exclude typo is.
// It would fail safe, accepting nothing, but only after a full scan and a red
// pipeline sent someone hunting for why the exception in the file did not
// apply.
func TestAnExceptionForAnUnknownControlIsRefusedBeforeScanning(t *testing.T) {
	fake := &fakeCollection{methods: map[string]int{}}
	srv := httptest.NewServer(fake)
	defer srv.Close()
	cfg := configWithExceptions(t, "  - control: CIS-1.1.31\n    resources: [PRJ/*]\n    reason: typo\n    expires: 2999-12-31\n")
	_, _, err := runRoot(t, "scan", "--url", srv.URL+"/DefaultCollection", "--token", "pat-value", "-c", cfg)
	if ExitCode(err) != ExitError || err == nil || !strings.Contains(err.Error(), "CIS-1.1.31") {
		t.Fatalf("err = %v", err)
	}
	if len(fake.methods) != 0 {
		t.Errorf("the organization was contacted before the config was refused: %v", fake.methods)
	}
}
