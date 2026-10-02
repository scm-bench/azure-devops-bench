package diff

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/scm-bench/azure-devops-bench/internal/engine"
	"github.com/scm-bench/azure-devops-bench/internal/scm"
)

// The renderer wraps to console.Width, which reads COLUMNS. Pinning it keeps
// these assertions off the width of whatever terminal the suite runs under.
func TestMain(m *testing.M) {
	os.Setenv("COLUMNS", "80")
	os.Exit(m.Run())
}

func finding(check, resource string, status engine.Status, severity string) engine.Finding {
	return engine.Finding{
		CheckID:      check,
		CISID:        strings.TrimPrefix(check, "CIS-"),
		Title:        "Control " + check,
		Severity:     severity,
		Status:       status,
		Resource:     resource,
		ResourceType: engine.ResourceRepository,
		Details:      "details for " + check + " on " + resource,
		Remediation:  "fix " + check,
	}
}

func reportOf(findings ...engine.Finding) *engine.Report {
	return &engine.Report{
		Metadata: scm.Metadata{BaseURL: "https://dev.azure.com/fabrikam", Platform: scm.PlatformAzureDevOps},
		Findings: findings,
		Score:    engine.Compute(findings),
	}
}

// PASS to FAIL is the only movement that means the instance got worse in a way
// nobody chose, and the only one that should stop a pipeline.
func TestOnlyPassToFailCountsAsRegression(t *testing.T) {
	before := reportOf(
		finding("CIS-1.1.15", "PRJ/app", engine.StatusPass, "HIGH"),
		finding("CIS-1.1.3", "PRJ/app", engine.StatusFail, "HIGH"),
		finding("CIS-1.1.9", "PRJ/app", engine.StatusPass, "HIGH"),
		finding("CIS-1.1.4", "PRJ/app", engine.StatusManual, "MEDIUM"),
	)
	after := reportOf(
		finding("CIS-1.1.15", "PRJ/app", engine.StatusFail, "HIGH"),  // regression
		finding("CIS-1.1.3", "PRJ/app", engine.StatusPass, "HIGH"),   // fixed
		finding("CIS-1.1.9", "PRJ/app", engine.StatusManual, "HIGH"), // visibility lost
		finding("CIS-1.1.4", "PRJ/app", engine.StatusFail, "MEDIUM"), // was never known
	)

	r := Compare(before, after)

	if len(r.Regressed) != 1 || r.Regressed[0].CheckID != "CIS-1.1.15" {
		t.Errorf("regressed = %+v, want only CIS-1.1.15", r.Regressed)
	}
	if len(r.Fixed) != 1 || r.Fixed[0].CheckID != "CIS-1.1.3" {
		t.Errorf("fixed = %+v, want only CIS-1.1.3", r.Fixed)
	}
	// PASS -> MANUAL means the tool stopped being able to see, and MANUAL ->
	// FAIL means it started being able to. Neither is the setting getting
	// worse, so neither may fail a pipeline.
	if len(r.Changed) != 2 {
		t.Errorf("changed = %+v, want the two MANUAL transitions", r.Changed)
	}
	if !r.HasRegression() {
		t.Error("HasRegression() = false with a PASS -> FAIL present")
	}
}

// A repository added since the baseline brings its failures with it. Nothing
// got worse — there is simply more instance — so it must not fail a pipeline
// that is guarding against regression.
func TestNewResourceFailuresAreNotRegressions(t *testing.T) {
	before := reportOf(finding("CIS-1.1.15", "PRJ/app", engine.StatusPass, "HIGH"))
	after := reportOf(
		finding("CIS-1.1.15", "PRJ/app", engine.StatusPass, "HIGH"),
		finding("CIS-1.1.15", "PRJ/new", engine.StatusFail, "HIGH"),
		finding("CIS-1.1.3", "PRJ/new", engine.StatusPass, "HIGH"),
	)

	r := Compare(before, after)

	if r.HasRegression() {
		t.Errorf("a new repository's failure was counted as a regression: %+v", r.Regressed)
	}
	if len(r.NewFailures) != 1 || r.NewFailures[0].Resource != "PRJ/new" {
		t.Errorf("newFailures = %+v, want the one failure on PRJ/new", r.NewFailures)
	}
	// A new repository that passes is not news.
	for _, c := range r.NewFailures {
		if c.To == engine.StatusPass {
			t.Errorf("a passing new resource was reported: %+v", c)
		}
	}
}

func TestDepartedResourcesAreReported(t *testing.T) {
	before := reportOf(
		finding("CIS-1.1.15", "PRJ/app", engine.StatusPass, "HIGH"),
		finding("CIS-1.1.15", "PRJ/old", engine.StatusFail, "HIGH"),
	)
	after := reportOf(finding("CIS-1.1.15", "PRJ/app", engine.StatusPass, "HIGH"))

	r := Compare(before, after)

	if len(r.Departed) != 1 || r.Departed[0].Resource != "PRJ/old" {
		t.Errorf("departed = %+v, want PRJ/old", r.Departed)
	}
	if r.HasRegression() {
		t.Error("a deleted repository must not read as a regression")
	}
}

func TestIdenticalReportsShowNoChange(t *testing.T) {
	rep := reportOf(
		finding("CIS-1.1.15", "PRJ/app", engine.StatusPass, "HIGH"),
		finding("CIS-1.1.3", "PRJ/app", engine.StatusFail, "HIGH"),
	)
	r := Compare(rep, rep)

	if r.HasRegression() || len(r.Fixed) > 0 || len(r.Changed) > 0 ||
		len(r.NewFailures) > 0 || len(r.Departed) > 0 {
		t.Errorf("comparing a report with itself produced changes: %+v", r)
	}
}

// The same control on two repositories is two different questions, and the same
// repository under two controls likewise. Keying on either alone would collapse
// them.
func TestChangesAreKeyedByControlAndResource(t *testing.T) {
	before := reportOf(
		finding("CIS-1.1.15", "PRJ/a", engine.StatusPass, "HIGH"),
		finding("CIS-1.1.15", "PRJ/b", engine.StatusPass, "HIGH"),
	)
	after := reportOf(
		finding("CIS-1.1.15", "PRJ/a", engine.StatusFail, "HIGH"),
		finding("CIS-1.1.15", "PRJ/b", engine.StatusPass, "HIGH"),
	)

	r := Compare(before, after)
	if len(r.Regressed) != 1 || r.Regressed[0].Resource != "PRJ/a" {
		t.Errorf("regressed = %+v, want only PRJ/a", r.Regressed)
	}
}

func TestRegressionsAreOrderedBySeverityThenBenchmarkNumber(t *testing.T) {
	before := reportOf(
		finding("CIS-1.1.15", "PRJ/app", engine.StatusPass, "HIGH"),
		finding("CIS-1.1.3", "PRJ/app", engine.StatusPass, "HIGH"),
		finding("CIS-1.1.17", "PRJ/app", engine.StatusPass, "MEDIUM"),
	)
	after := reportOf(
		finding("CIS-1.1.15", "PRJ/app", engine.StatusFail, "HIGH"),
		finding("CIS-1.1.3", "PRJ/app", engine.StatusFail, "HIGH"),
		finding("CIS-1.1.17", "PRJ/app", engine.StatusFail, "MEDIUM"),
	)

	r := Compare(before, after)

	want := []string{"CIS-1.1.3", "CIS-1.1.15", "CIS-1.1.17"}
	for i, id := range want {
		if r.Regressed[i].CheckID != id {
			t.Fatalf("order = %v, want %v",
				[]string{r.Regressed[0].CheckID, r.Regressed[1].CheckID, r.Regressed[2].CheckID}, want)
		}
	}
}

func TestSameInstance(t *testing.T) {
	a := &scm.Snapshot{Metadata: scm.Metadata{BaseURL: "https://dev.azure.com/fabrikam"}}
	b := &scm.Snapshot{Metadata: scm.Metadata{BaseURL: "https://dev.azure.com/fabrikam"}}
	c := &scm.Snapshot{Metadata: scm.Metadata{BaseURL: "https://other.example.com"}}

	if !SameInstance(a, b) {
		t.Error("identical base URLs should compare as the same instance")
	}
	if SameInstance(a, c) {
		t.Error("different base URLs should not compare as the same instance")
	}
}

// Whatever the scan report looks like, diff has to look like it too. This
// renderer once had a layout of its own, and a diff read like a different
// program's output — right up to the closing line, which came from main and did
// not. Now both draw with console.RenderTable, so the check is that a diff is
// made of tables and that they hold their shape.
func TestTableOutputIsDrawnWithTheSameTables(t *testing.T) {
	result := &Result{
		Before:    Side{BaseURL: "https://dev.azure.com/fabrikam", Score: engine.Score{Value: 80, EarnedWeight: 8, TotalWeight: 10}},
		After:     Side{BaseURL: "https://dev.azure.com/fabrikam", Score: engine.Score{Value: 60, EarnedWeight: 6, TotalWeight: 10}},
		Regressed: []Change{{CheckID: "CIS-1.1.15", Severity: "HIGH", Resource: "PRJ/app", From: "PASS", To: "FAIL", Details: "no longer restricted", Remediation: "restrict it"}},
		Fixed:     []Change{{CheckID: "CIS-1.1.4", Severity: "MEDIUM", Resource: "PRJ/app", From: "FAIL", To: "PASS", Details: "approvals reset now"}},
		Changed:   []Change{{CheckID: "CIS-1.1.9", Severity: "HIGH", Resource: "PRJ/app", From: "PASS", To: "MANUAL", Details: "cannot be read"}},
		// A departed resource is one entry for the resource, not one per
		// control, so it carries no control ID — see
		// TestDepartedResourcesCollapseToOneEntryEach.
		Departed: []Change{{Severity: "LOW", Resource: "PRJ/old", From: "PASS", Details: "was failing 3 of 4 controls"}},
	}

	var buf bytes.Buffer
	if err := Write(&buf, result, Options{Format: "table"}); err != nil {
		t.Fatalf("Write: %v", err)
	}
	out := buf.String()

	// Each kind of change gets its own table, headed the same way scan's are.
	for _, want := range []string{
		"Regressed (1)", "Fixed (1)", "Other changes (1)", "Gone (1)",
		"┌", "│  Control  ", "Severity", "Resource", "Change", "Detail",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("diff output is missing %q\n---\n%s", want, out)
		}
	}
	// The transition is the point of the command, so it is spelled out rather
	// than left to the reader to infer from two tables.
	for _, want := range []string{"PASS → FAIL", "FAIL → PASS", "PASS → MANUAL", "gone"} {
		if !strings.Contains(out, want) {
			t.Errorf("diff output is missing the transition %q\n---\n%s", want, out)
		}
	}
	// A departed resource has no control of its own, and a table cannot drop a
	// column for one row, so it gets the dash the scan report uses for "none".
	if !strings.Contains(out, "│ -") {
		t.Errorf("a departed resource should show a dash for its control\n---\n%s", out)
	}

	// Every border line has to agree with every other on where the columns are.
	for _, block := range strings.Split(out, "\n\n") {
		layouts := map[string]bool{}
		for _, line := range strings.Split(block, "\n") {
			if !strings.ContainsAny(line, "│┌└├") {
				continue
			}
			var at []int
			for i, r := range []rune(line) {
				if strings.ContainsRune("│┌┬┐├┼┤└┴┘", r) {
					at = append(at, i)
				}
			}
			layouts[fmt.Sprint(at)] = true
		}
		if len(layouts) > 1 {
			t.Errorf("a table's columns do not line up:\n%s", block)
		}
	}
}

// Deleting one repository used to produce one GONE line per control — twenty
// for a repository, a thousand for fifty of them — while the same event on the
// other side, a repository arriving, produced only its failures. The asymmetry
// buried real regressions under a wall of GONE, which is the opposite of what
// this command is for.
func TestDepartedResourcesCollapseToOneEntryEach(t *testing.T) {
	var before []engine.Finding
	for _, id := range []string{"CIS-1.1.3", "CIS-1.1.15", "CIS-1.1.16", "CIS-1.2.1"} {
		status := engine.StatusFail
		severity := "HIGH"
		if id == "CIS-1.2.1" {
			status, severity = engine.StatusPass, "LOW"
		}
		before = append(before, engine.Finding{
			CheckID: id, CISID: strings.TrimPrefix(id, "CIS-"), Severity: severity,
			Status: status, Resource: "PRJ/gone", ResourceType: engine.ResourceRepository,
			Details: "whatever it said at the time",
		})
	}

	result := Compare(
		&engine.Report{Findings: before},
		&engine.Report{},
	)

	if len(result.Departed) != 1 {
		t.Fatalf("departed = %d entries, want 1 per resource: %+v", len(result.Departed), result.Departed)
	}
	got := result.Departed[0]
	if got.Resource != "PRJ/gone" {
		t.Errorf("resource = %q, want PRJ/gone", got.Resource)
	}
	// The worst severity it was carrying, so GONE sorts like every other list.
	if got.Severity != "HIGH" {
		t.Errorf("severity = %q, want HIGH", got.Severity)
	}
	// "the repository with three HIGH failures is gone" is the part worth
	// knowing, so the counts survive the collapse.
	if !strings.Contains(got.Details, "3 controls of 4") {
		t.Errorf("details = %q, want the failing and evaluated counts", got.Details)
	}
}

// A repository that arrives and cannot be read at all used to produce no entry
// in any category, so the fact that it existed disappeared from the comparison.
func TestNewResourcesThatCannotBeReadAreReported(t *testing.T) {
	result := Compare(
		&engine.Report{},
		&engine.Report{Findings: []engine.Finding{
			{CheckID: "CIS-1.1.15", CISID: "1.1.15", Severity: "HIGH", Status: engine.StatusManual,
				Resource: "PRJ/new", ResourceType: engine.ResourceRepository, Details: "cannot be read"},
			{CheckID: "CIS-1.2.1", CISID: "1.2.1", Severity: "LOW", Status: engine.StatusPass,
				Resource: "PRJ/new", ResourceType: engine.ResourceRepository, Details: "fine"},
		}},
	)

	if len(result.Changed) != 1 {
		t.Errorf("changed = %+v, want the new unreadable control", result.Changed)
	}
	// A new repository that passes is still not news.
	if len(result.NewFailures) != 0 {
		t.Errorf("newFailures = %+v, want none", result.NewFailures)
	}
}
