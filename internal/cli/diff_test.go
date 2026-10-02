package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// runErr returns the error itself. The root command sets SilenceErrors, so the
// message never reaches stderr — main.go prints it — and a test that wants to
// assert on the wording has to look at the error.
func runErr(t *testing.T, args ...string) error {
	t.Helper()
	var out, errOut bytes.Buffer

	root := NewRootCommand()
	root.SetOut(&out)
	root.SetErr(&errOut)
	root.SetArgs(args)
	return root.Execute()
}

// writeDiffPair saves a baseline snapshot and a second one in which the
// repository's branch protection has been removed — the shape of an actual
// regression.
func writeDiffPair(t *testing.T) (before, after string) {
	t.Helper()
	dir := t.TempDir()

	raw, err := os.ReadFile(writeSnapshotFixture(t))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	before = filepath.Join(dir, "before.json")
	if err := os.WriteFile(before, raw, 0o600); err != nil {
		t.Fatalf("write before: %v", err)
	}

	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	// Raise the approval count so CIS-1.1.3 goes the other way, giving the
	// comparison one movement in each direction.
	projects := doc["projects"].([]any)
	repo := projects[0].(map[string]any)["repositories"].([]any)[0].(map[string]any)
	repo["pullRequestSettings"].(map[string]any)["requiredApprovers"] = float64(2)

	changed, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("encode after: %v", err)
	}
	after = filepath.Join(dir, "after.json")
	if err := os.WriteFile(after, changed, 0o600); err != nil {
		t.Fatalf("write after: %v", err)
	}
	return before, after
}

func TestDiffReportsFixedControl(t *testing.T) {
	before, after := writeDiffPair(t)

	stdout, _, code := run(t, "diff", before, after)
	if code != ExitOK {
		t.Fatalf("exit code = %d, want %d for an improvement", code, ExitOK)
	}
	if !strings.Contains(stdout, "Fixed (") || !strings.Contains(stdout, "CIS-1.1.3") {
		t.Errorf("the improvement was not reported\n---\n%s", stdout)
	}
	if strings.Contains(stdout, "Regressed (") {
		t.Errorf("nothing regressed but the section was printed\n---\n%s", stdout)
	}
}

// Reversing the arguments turns the same pair into a regression, which is the
// case the exit code exists for.
func TestDiffExitsOneOnRegression(t *testing.T) {
	before, after := writeDiffPair(t)

	stdout, _, code := run(t, "diff", after, before)
	if code != ExitFindings {
		t.Fatalf("exit code = %d, want %d when a control fell from PASS to FAIL", code, ExitFindings)
	}
	if !strings.Contains(stdout, "Regressed (") {
		t.Errorf("the regression was not reported\n---\n%s", stdout)
	}
	// A regression is the one thing someone is expected to act on immediately,
	// so the fix has to be in front of them.
	if !strings.Contains(stdout, "How to fix the regressions") {
		t.Errorf("no remediation was printed for the regression\n---\n%s", stdout)
	}
}

func TestDiffFailOnRegressionCanBeDisabled(t *testing.T) {
	before, after := writeDiffPair(t)

	if _, _, code := run(t, "diff", after, before, "--fail-on-regression=false"); code != ExitOK {
		t.Errorf("exit code = %d, want %d with --fail-on-regression=false", code, ExitOK)
	}
}

func TestDiffOfIdenticalSnapshotsIsClean(t *testing.T) {
	before, _ := writeDiffPair(t)

	stdout, _, code := run(t, "diff", before, before)
	if code != ExitOK {
		t.Errorf("exit code = %d comparing a snapshot with itself", code)
	}
	if !strings.Contains(stdout, "No control changed verdict") {
		t.Errorf("an unchanged comparison should say so\n---\n%s", stdout)
	}
}

// Two different instances produce a comparison that looks meaningful and is
// not: every resource reads as both departed and arrived.
func TestDiffRefusesDifferentInstances(t *testing.T) {
	before, after := writeDiffPair(t)

	raw, err := os.ReadFile(after)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse: %v", err)
	}
	doc["metadata"].(map[string]any)["baseUrl"] = "https://elsewhere.example.com"
	changed, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	elsewhere := filepath.Join(t.TempDir(), "elsewhere.json")
	if err := os.WriteFile(elsewhere, changed, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	if _, _, code := run(t, "diff", before, elsewhere); code != ExitError {
		t.Errorf("exit code = %d, want %d for snapshots from different instances", code, ExitError)
	}
	// The message has to say what is wrong and how to proceed deliberately,
	// since comparing two instances is occasionally what someone means to do.
	err = runErr(t, "diff", before, elsewhere)
	if err == nil || !strings.Contains(err.Error(), "different organizations") {
		t.Errorf("error = %v, want it to name the mismatch", err)
	}
	if err != nil && !strings.Contains(err.Error(), "--allow-other-instance") {
		t.Errorf("error = %v, want it to name the override", err)
	}

	if _, _, code := run(t, "diff", before, elsewhere, "--allow-other-instance"); code != ExitOK {
		t.Errorf("exit code = %d with --allow-other-instance, want %d", code, ExitOK)
	}
}

func TestDiffJSONOutput(t *testing.T) {
	before, after := writeDiffPair(t)

	stdout, _, _ := run(t, "diff", after, before, "-o", "json", "--fail-on-regression=false")

	var result struct {
		Before struct {
			Score struct {
				Value int `json:"value"`
			} `json:"score"`
		} `json:"before"`
		After struct {
			Score struct {
				Value int `json:"value"`
			} `json:"score"`
		} `json:"after"`
		Regressed []struct {
			CheckID string `json:"checkId"`
			From    string `json:"from"`
			To      string `json:"to"`
		} `json:"regressed"`
	}
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatalf("diff json does not parse: %v\n%s", err, stdout)
	}
	if len(result.Regressed) == 0 {
		t.Fatal("json output carries no regression")
	}
	if result.Regressed[0].From != "PASS" || result.Regressed[0].To != "FAIL" {
		t.Errorf("regression = %+v, want PASS -> FAIL", result.Regressed[0])
	}
	if result.Before.Score.Value == result.After.Score.Value {
		t.Error("both scores are equal, but a control changed verdict")
	}
}

func TestDiffRejectsBadArguments(t *testing.T) {
	before, after := writeDiffPair(t)

	if _, _, code := run(t, "diff", before); code != ExitError {
		t.Error("diff with one argument should be rejected")
	}
	if _, _, code := run(t, "diff", before, after, "-o", "yaml"); code != ExitError {
		t.Error("an unknown --output format should be rejected")
	}
	if _, _, code := run(t, "diff", "/nonexistent.json", after); code != ExitError {
		t.Error("a missing snapshot should be an error")
	}
}
