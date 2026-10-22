package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/scm-bench/azure-devops-bench/internal/checks"
	"github.com/scm-bench/azure-devops-bench/internal/config"
	"github.com/scm-bench/azure-devops-bench/internal/console"
	"github.com/scm-bench/azure-devops-bench/internal/engine"
	"github.com/scm-bench/azure-devops-bench/internal/scm"
	"github.com/scm-bench/azure-devops-bench/internal/scm/azuredevops"
)

// brokenWriter refuses every write, like stdout closed under the process.
type brokenWriter struct{}

var errBroken = errors.New("broken pipe")

func (brokenWriter) Write([]byte) (int, error) { return 0, errBroken }

// aFile returns the path of a regular file, for tests that need a "directory"
// that is not one.
func aFile(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "plain")
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// runWithOut runs the CLI with stdout going to out, for the tests about a
// stdout that refuses the report.
func runWithOut(t *testing.T, out io.Writer, args ...string) error {
	t.Helper()
	root := NewRootCommand()
	root.SetOut(out)
	root.SetErr(io.Discard)
	root.SetIn(strings.NewReader(""))
	root.SetArgs(args)
	return root.Execute()
}

// unknownExceptionConfig is a config that loads, but that no engine accepts:
// its exception names a control the bundle does not have.
func unknownExceptionConfig(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "azure-devops-bench.yaml")
	body := "exceptions:\n  - control: CIS-9.9.9\n    resources: [\"*\"]\n    reason: r\n    owner: o\n    expires: 2099-01-01\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRunSaysWhyItExitedAndWithWhatCode(t *testing.T) {
	cases := []struct {
		name     string
		err      error
		wantCode int
		wantTag  string
	}{
		{"success", nil, ExitOK, ""},
		{"interrupted", context.Canceled, ExitError, "WARN"},
		{"failure", errors.New("the organization could not be reached"), ExitError, "FAIL"},
		{"findings", &exitCodeError{code: ExitFindings, msg: "2 controls failed"}, ExitFindings, "INFO"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := &cobra.Command{Use: "x", SilenceErrors: true, SilenceUsage: true,
				RunE: func(*cobra.Command, []string) error { return tc.err }}
			root.SetArgs(nil)
			var buf bytes.Buffer
			code := Run(context.Background(), root, console.Writer{W: &buf})
			if code != tc.wantCode {
				t.Errorf("Run() = %d, want %d", code, tc.wantCode)
			}
			if tc.wantTag == "" {
				if buf.Len() != 0 {
					t.Errorf("a successful run printed %q", buf.String())
				}
				return
			}
			if !strings.Contains(buf.String(), tc.wantTag) {
				t.Errorf("last line = %q, want the %s tag", buf.String(), tc.wantTag)
			}
		})
	}
}

func TestShortRevisionKeepsAShortOneWhole(t *testing.T) {
	if got := shortRevision("abc123"); got != "abc123" {
		t.Errorf("shortRevision = %q", got)
	}
}

func TestHumanAge(t *testing.T) {
	for d, want := range map[time.Duration]string{
		30 * time.Second: "under a minute",
		5 * time.Minute:  "5m",
		3 * time.Hour:    "3h",
		72 * time.Hour:   "3d",
	} {
		if got := humanAge(d); got != want {
			t.Errorf("humanAge(%v) = %q, want %q", d, got, want)
		}
	}
}

// Everything that is not a plain successful read stands out in the request
// log: a write in red, a failure in red, a refusal in yellow, a retry named.
func TestTraceMarksWhatIsNotARoutineRead(t *testing.T) {
	tr := newTracer(&bytes.Buffer{}, false, true)
	post := get("/_apis/projects", "", 200)
	post.Method = http.MethodPost
	failed := get("/_apis/projects", "", 0)
	failed.Err = errors.New("connection reset")
	retried := get("/_apis/projects", "", 200)
	retried.Attempt = 2
	for _, tc := range []struct {
		e    azuredevops.RequestEvent
		want string
	}{
		{post, "POST"},
		{failed, "err"},
		{get("/_apis/projects", "", 503), "503"},
		{get("/_apis/projects", "", 404), "404"},
		{retried, "retry 2"},
	} {
		if got := tr.formatRequest(tc.e, ""); !strings.Contains(got, tc.want) {
			t.Errorf("formatRequest = %q, want %q in it", got, tc.want)
		}
	}
}

// A second start is a no-op: one line, one rotor.
func TestProgressStartsOnce(t *testing.T) {
	var buf syncBuffer
	p := &progressWriter{out: &buf}
	p.start()
	stop := p.stop
	p.start()
	if p.stop != stop {
		t.Error("a second start replaced the running rotor")
	}
	p.clear()
}

// The rotor turns on its own, so a slow request does not look like a hang.
func TestProgressSpinsWithoutRequests(t *testing.T) {
	var buf syncBuffer
	p := &progressWriter{out: &buf}
	p.start()
	defer p.clear()
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(buf.String(), "/ scanning") {
		if time.Now().After(deadline) {
			t.Fatalf("the spinner never advanced:\n%q", buf.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestProgressCallbackFeedsTheLine(t *testing.T) {
	var buf syncBuffer
	p := &progressWriter{out: &buf}
	p.callback()("reading Fabrikam/app")
	if !strings.Contains(buf.String(), "reading Fabrikam/app") {
		t.Errorf("the callback did not reach the line: %q", buf.String())
	}
}

func TestIsTerminalOnAClosedFile(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "closed")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	if isTerminal(f) {
		t.Error("a file that cannot be stat'ed is not a terminal")
	}
}

func TestDecodeMenuKeyOfNothing(t *testing.T) {
	if k := decodeMenuKey(nil); k.kind != keyNone {
		t.Errorf("decodeMenuKey(nil) = %+v, want keyNone", k)
	}
}

func TestSelectByNumberTakesTheDemo(t *testing.T) {
	if got := selectByNumber(strings.NewReader("2\n"), io.Discard, console.Painter{}, []string{"a", "b", "c"}); got != optDemo {
		t.Errorf("selectByNumber = %d, want the demo", got)
	}
}

func TestReadLineKeepsAnUnterminatedLastLine(t *testing.T) {
	if got, err := readLine(strings.NewReader("https://x")); err != nil || got != "https://x" {
		t.Errorf("readLine = %q, %v", got, err)
	}
}

// Every way out of the credential questions before there is a usable
// credential is the guided error, not a half-configured scan.
func TestPromptCredentialsGivesUpWithoutACredential(t *testing.T) {
	for name, input := range map[string]string{
		"no url at all":  "",
		"url, then eof":  "https://dev.azure.com/fabrikam\n",
		"an empty token": "https://dev.azure.com/fabrikam\n\n",
	} {
		t.Run(name, func(t *testing.T) {
			var out bytes.Buffer
			if _, err := promptCredentials(strings.NewReader(input), &out); err == nil || !strings.Contains(err.Error(), "no organization") {
				t.Errorf("err = %v, want the guided error", err)
			}
		})
	}
	var out bytes.Buffer
	promptCredentials(strings.NewReader("https://dev.azure.com/fabrikam\n\n"), &out)
	if !strings.Contains(out.String(), "A token is required") {
		t.Errorf("an empty token is not explained:\n%s", out.String())
	}
}

// A file that stats like a terminal but refuses terminal modes — /dev/null
// under a name the /dev/null check does not catch — still gets asked, by
// number, and its EOF is the guided error rather than a hang.
func TestFirstRunFallsBackWhenRawModeIsRefused(t *testing.T) {
	devnull, err := os.OpenFile("/dev//null", os.O_RDWR, 0)
	if err != nil {
		t.Skipf("no /dev/null: %v", err)
	}
	defer devnull.Close()
	if !isTerminal(devnull) {
		t.Skip("/dev//null does not stat as a character device here")
	}
	var out bytes.Buffer
	if _, err := promptFirstRun(devnull, &out, false); err == nil || !strings.Contains(err.Error(), "no organization") {
		t.Errorf("err = %v, want the guided error", err)
	}
	if !strings.Contains(out.String(), "choose [1/2/3]") {
		t.Errorf("the numbered prompt was never shown:\n%s", out.String())
	}
	if _, err := readSecret(devnull, io.Discard); err == nil {
		t.Error("reading a hidden secret from a non-terminal succeeded")
	}

	// The same file as the scan's stdin and stderr: the menu is offered, and
	// quitting it is the scan's error.
	root := NewRootCommand()
	root.SetIn(devnull)
	root.SetErr(devnull)
	root.SetOut(io.Discard)
	root.SetArgs([]string{"scan"})
	if err := root.Execute(); err == nil || !strings.Contains(err.Error(), "no organization") {
		t.Errorf("scan: err = %v, want the guided error", err)
	}
}

func TestInitReportsAFileThatRefusesTheTemplate(t *testing.T) {
	under := filepath.Join(aFile(t), "azure-devops-bench.yaml")
	if err := executeErr(t, "init", "--path", under); err == nil || !strings.Contains(err.Error(), "create "+under) {
		t.Errorf("under a file: err = %v, want a create error", err)
	}

	orig := openFile
	t.Cleanup(func() { openFile = orig })
	path := filepath.Join(t.TempDir(), "azure-devops-bench.yaml")
	openFile = func(name string, flag int, perm os.FileMode) (*os.File, error) {
		f, err := orig(name, flag, perm)
		if err != nil {
			return nil, err
		}
		f.Close()
		return os.Open(name) // read-only
	}
	if err := executeErr(t, "init", "--path", path); err == nil || !strings.Contains(err.Error(), "write "+path) {
		t.Errorf("err = %v, want a write error", err)
	}
}

// A bundle that fails to load is an error, not an empty list of controls.
func TestListChecksReportsABundleThatFailsToLoad(t *testing.T) {
	orig := loadChecks
	loadChecks = func() (*checks.Bundle, error) { return nil, errors.New("metadata.json: title is required") }
	t.Cleanup(func() { loadChecks = orig })
	if err := executeErr(t, "list-checks"); err == nil || !strings.Contains(err.Error(), "title is required") {
		t.Errorf("err = %v, want the load error", err)
	}
}

func TestListChecksReportsAnOutputItCannotWriteTo(t *testing.T) {
	if err := runWithOut(t, brokenWriter{}, "list-checks"); !errors.Is(err, errBroken) {
		t.Errorf("err = %v, want the writer's error", err)
	}
}

func TestDiffReportsWhatStopsIt(t *testing.T) {
	before, after := writeDiffPair(t)
	missing := filepath.Join(t.TempDir(), "absent.json")

	if err := executeErr(t, "diff", before, missing); err == nil || !strings.Contains(err.Error(), "read snapshot") {
		t.Errorf("unreadable after: err = %v", err)
	}
	if err := executeErr(t, "diff", "-c", missing, before, after); err == nil {
		t.Error("a missing --config was accepted")
	}
	if err := executeErr(t, "diff", "-c", unknownExceptionConfig(t), before, after); err == nil || !strings.Contains(err.Error(), "evaluate "+before) {
		t.Errorf("an engine that refuses the config: err = %v, want the before side named", err)
	}
	blocked := filepath.Join(aFile(t), "diff.json")
	if err := executeErr(t, "diff", "--output-file", blocked, before, after); err == nil {
		t.Error("writing under a file succeeded")
	}
	if err := runWithOut(t, brokenWriter{}, "diff", before, after); !errors.Is(err, errBroken) {
		t.Errorf("broken stdout: err = %v, want the writer's error", err)
	}
}

// The config a diff is judged under is named, as scan names it.
func TestDiffNamesItsConfig(t *testing.T) {
	before, after := writeDiffPair(t)
	cfg := configWithFailOn(t, "none")
	_, stderr, _ := run(t, "diff", "-c", cfg, before, after)
	if !strings.Contains(stderr, "using config "+cfg) {
		t.Errorf("stderr does not name the config:\n%s", stderr)
	}
}

// Either side failing to evaluate stops the diff and names that side, and a
// report with policy errors is never compared.
func TestDiffRefusesAnIncompleteEvaluation(t *testing.T) {
	before, after := writeDiffPair(t)
	orig := evaluateSnapshot
	t.Cleanup(func() { evaluateSnapshot = orig })

	calls := 0
	evaluateSnapshot = func(ctx context.Context, cfg config.Config, s *scm.Snapshot) (*engine.Report, error) {
		calls++
		if calls == 2 {
			return nil, errors.New("bundle exploded")
		}
		return orig(ctx, cfg, s)
	}
	if err := executeErr(t, "diff", before, after); err == nil || !strings.Contains(err.Error(), "evaluate "+after) {
		t.Errorf("after side failing: err = %v, want the after side named", err)
	}

	evaluateSnapshot = func(ctx context.Context, cfg config.Config, s *scm.Snapshot) (*engine.Report, error) {
		rep, err := orig(ctx, cfg, s)
		if err == nil {
			rep.Errors = append(rep.Errors, "CIS-1.1.1 on Fabrikam/app: policy produced no result")
		}
		return rep, err
	}
	err := executeErr(t, "diff", before, after)
	if ExitCode(err) != ExitError || !strings.Contains(err.Error(), "2 controls could not be evaluated") {
		t.Errorf("policy errors: err = %v (code %d)", err, ExitCode(err))
	}
}

func TestScanReportsAnUnusableSnapshot(t *testing.T) {
	garbled := filepath.Join(t.TempDir(), "garbled.json")
	if err := os.WriteFile(garbled, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := executeErr(t, "scan", "--snapshot-in", garbled); err == nil || !strings.Contains(err.Error(), "parse snapshot") {
		t.Errorf("garbled: err = %v, want a parse error", err)
	}
	unlabelled := writeSnapshotWith(t, func(s *scm.Snapshot) { s.Metadata.Platform = "" })
	if err := executeErr(t, "scan", "--snapshot-in", unlabelled); err == nil || !strings.Contains(err.Error(), "does not record which platform") {
		t.Errorf("no platform: err = %v", err)
	}
}

func TestScanReportsFilesItCannotWrite(t *testing.T) {
	snap := writeSnapshotFixture(t)
	blocked := filepath.Join(aFile(t), "out.json") // its parent is a file
	for _, flag := range []string{"--snapshot-out", "--output-file"} {
		if err := executeErr(t, "scan", "--snapshot-in", snap, flag, blocked); err == nil {
			t.Errorf("%s into a file's subdirectory succeeded", flag)
		}
	}
	if err := runWithOut(t, brokenWriter{}, "scan", "--snapshot-in", snap); !errors.Is(err, errBroken) {
		t.Errorf("broken stdout: err = %v, want the writer's error", err)
	}
}

// A deadline that has already passed stops the evaluation too, not only the
// fetch.
func TestScanDeadlineStopsTheEvaluation(t *testing.T) {
	err := executeErr(t, "scan", "--snapshot-in", writeSnapshotFixture(t), "--set", "scan.maxDuration=1ns")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err = %v, want the deadline", err)
	}
}

// --verbose is the full request log, and a full log asked for in the config
// is dropped when stderr is not a terminal.
func TestScanProgressModes(t *testing.T) {
	snap := writeSnapshotFixture(t)
	if _, _, code := run(t, "scan", "--snapshot-in", snap, "--verbose", "-c", configWithFailOn(t, "none")); code != ExitOK {
		t.Errorf("--verbose: exit %d", code)
	}
	if _, _, code := run(t, "scan", "--snapshot-in", snap, "--set", "scan.progress=full", "-c", configWithFailOn(t, "none")); code != ExitOK {
		t.Errorf("progress=full: exit %d", code)
	}
}

func TestScanLastReportsAnUnreadableCache(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows answers a path under a file with \"path not found\", which reads as an empty cache")
	}
	dir := t.TempDir()
	t.Setenv("AZURE_DEVOPS_BENCH_CONFIG_DIR", dir)
	if err := os.WriteFile(filepath.Join(dir, "cache"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := executeErr(t, "scan", "--last"); err == nil || !strings.Contains(err.Error(), "read snapshot cache") {
		t.Errorf("err = %v, want the cache error", err)
	}
}

// A cache that cannot be written is a warning, never a failed scan: the
// report the person asked for still arrives.
func TestScanSurvivesACacheItCannotWrite(t *testing.T) {
	fake := &fakeCollection{methods: map[string]int{}}
	srv := httptest.NewServer(fake)
	defer srv.Close()
	url := srv.URL + "/DefaultCollection"

	for name, block := range map[string]func(t *testing.T, dir string){
		// The cache directory is a file, so it cannot be created.
		"no directory": func(t *testing.T, dir string) {
			os.WriteFile(filepath.Join(dir, "cache"), []byte("x"), 0o600)
		},
		// The cache file's name is taken by a directory.
		"no file": func(t *testing.T, dir string) {
			path, err := config.SnapshotCachePath(url)
			if err != nil {
				t.Fatal(err)
			}
			os.MkdirAll(path, 0o700)
		},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			t.Setenv("AZURE_DEVOPS_BENCH_CONFIG_DIR", dir)
			block(t, dir)
			_, stderr, err := runRoot(t, "scan", "--url", url, "--token", "pat", "-o", "json", "--verbose",
				"-c", configWithScan(t, "failOn: none"))
			if ExitCode(err) != ExitOK {
				t.Fatalf("exit %d (%v)\n%s", ExitCode(err), err, stderr)
			}
			if !strings.Contains(stderr, "could not cache the snapshot") {
				t.Errorf("no warning about the cache:\n%s", stderr)
			}
		})
	}
}
