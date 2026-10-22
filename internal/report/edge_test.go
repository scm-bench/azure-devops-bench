package report

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"strings"
	"testing"

	"github.com/scm-bench/azure-devops-bench/internal/engine"
)

// failAfter accepts n bytes and then refuses, the way a full disk or a closed
// pipe does partway through a report.
type failAfter struct{ n int }

var errRefused = errors.New("write refused")

func (f *failAfter) Write(p []byte) (int, error) {
	if len(p) > f.n {
		n := f.n
		f.n = 0
		return n, errRefused
	}
	f.n -= len(p)
	return len(p), nil
}

func TestJUnitSurfacesWriteErrors(t *testing.T) {
	for _, n := range []int{0, len(xml.Header), len(xml.Header) + 50} {
		if err := Write(&failAfter{n: n}, sampleReport(), Options{Format: FormatJUnit}); !errors.Is(err, errRefused) {
			t.Errorf("after %d bytes: Write() = %v, want the writer's error", n, err)
		}
	}
}

func TestLessGroupOrdersBySeverityBenchmarkSpreadThenText(t *testing.T) {
	g := func(sev, cis string, n int, details string) findingGroup {
		return findingGroup{rep: engine.Finding{Severity: sev, CISID: cis}, details: details, resources: make([]string, n)}
	}
	cases := []struct {
		name string
		x, y findingGroup
	}{
		{"severity", g("HIGH", "2.9", 1, "z"), g("LOW", "1.1", 9, "a")},
		{"benchmark number", g("HIGH", "1.1.9", 1, "z"), g("HIGH", "1.1.11", 9, "a")},
		{"spread", g("HIGH", "1.1", 3, "z"), g("HIGH", "1.1", 2, "a")},
		{"details", g("HIGH", "1.1", 2, "a"), g("HIGH", "1.1", 2, "b")},
	}
	for _, tc := range cases {
		if !lessGroup(tc.x, tc.y) || lessGroup(tc.y, tc.x) {
			t.Errorf("%s: want x strictly before y", tc.name)
		}
	}
}

func TestLessRecordPutsTheOrganizationAheadOfItsRepositories(t *testing.T) {
	f := func(sev, cis, resource string) engine.Finding {
		return engine.Finding{Severity: sev, CISID: cis, Resource: resource}
	}
	cases := []struct {
		name string
		x, y engine.Finding
	}{
		{"severity", f("HIGH", "2.9", "z"), f("LOW", "1.1", "a")},
		{"benchmark number", f("HIGH", "1.1.9", "z"), f("HIGH", "1.1.11", "a")},
		{"organization first", f("HIGH", "1.1", engine.InstanceResourceName), f("HIGH", "1.1", "PRJ/a")},
		{"name", f("HIGH", "1.1", "PRJ/a"), f("HIGH", "1.1", "PRJ/b")},
	}
	for _, tc := range cases {
		if !lessRecord(tc.x, tc.y) || lessRecord(tc.y, tc.x) {
			t.Errorf("%s: want x strictly before y", tc.name)
		}
	}
}

func TestLessTallyPutsTheWorstResourceFirst(t *testing.T) {
	cases := []struct {
		name string
		x, y resourceTally
	}{
		{"failed", resourceTally{name: "z", failed: 2}, resourceTally{name: "a", failed: 1, unread: 9}},
		{"unread", resourceTally{name: "z", unread: 2}, resourceTally{name: "a", unread: 1, manual: 9}},
		{"manual", resourceTally{name: "z", manual: 2}, resourceTally{name: "a", manual: 1}},
		{"name", resourceTally{name: "a"}, resourceTally{name: "b"}},
	}
	for _, tc := range cases {
		if !lessTally(tc.x, tc.y) || lessTally(tc.y, tc.x) {
			t.Errorf("%s: want x strictly before y", tc.name)
		}
	}
}

func TestPluralNamesTheResourceKind(t *testing.T) {
	cases := []struct {
		n    int
		kind string
		want string
	}{
		{1, engine.ResourceRepository, "repository"},
		{2, engine.ResourceRepository, "repositories"},
		{1, engine.ResourceOrganization, "organization"},
		{2, engine.ResourceOrganization, "organizations"},
		{1, "other", "resource"},
		{3, "other", "resources"},
	}
	for _, tc := range cases {
		if got := plural(tc.n, tc.kind); got != tc.want {
			t.Errorf("plural(%d, %q) = %q, want %q", tc.n, tc.kind, got, tc.want)
		}
	}
}

func TestSARIFCarriesPolicyErrorsAsNotifications(t *testing.T) {
	rep := sampleReport()
	rep.Errors = []string{"CIS-1.1.15 on PRJ/app: policy produced no result"}
	out := renderReport(t, rep, Options{Format: FormatSARIF})
	var doc struct {
		Runs []struct {
			Invocations []struct {
				Notifications []struct {
					Level   string                `json:"level"`
					Message struct{ Text string } `json:"message"`
				} `json:"toolExecutionNotifications"`
			} `json:"invocations"`
		} `json:"runs"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatal(err)
	}
	for _, n := range doc.Runs[0].Invocations[0].Notifications {
		if n.Level == "error" && n.Message.Text == rep.Errors[0] {
			return
		}
	}
	t.Errorf("the policy error is not among the notifications:\n%s", out)
}

// With ShowPassed, N/A controls are listed too, grouped like MANUAL ones, and
// in colour their status is dimmed rather than shouted.
func TestShowPassedListsNotApplicableControls(t *testing.T) {
	rep := sampleReport()
	rep.Findings = append(rep.Findings, engine.Finding{
		CheckID: "CIS-1.1.9", CISID: "1.1.9", Severity: "LOW", Status: engine.StatusNA,
		Title: "Ensure stale branches are reviewed", Resource: "PRJ/app", ResourceType: engine.ResourceRepository,
		Details: "The repository is disabled.", Remediation: "n/a", Automated: true,
	})
	rep.Score = engine.Compute(rep.Findings)
	if out := flattened(renderReport(t, rep, Options{Format: FormatTable, ShowPassed: true})); !strings.Contains(out, "CIS-1.1.9") {
		t.Errorf("the N/A control is missing with ShowPassed:\n%s", out)
	}
	out := renderReport(t, rep, Options{Format: FormatTable, ShowPassed: true, Details: true, Color: true})
	if !strings.Contains(out, ansiDim+statusNA) {
		t.Errorf("the N/A status is not dimmed:\n%q", out)
	}
}

// A long resource name leaves the reason no room beside it, so the reason
// starts on its own line rather than in a sliver.
func TestFindingLineWithALongHead(t *testing.T) {
	rep := sampleReport()
	rep.Findings[0].Resource = "PRJ/a-repository-name-long-enough-to-crowd-out-the-reason"
	out := renderReport(t, rep, Options{Format: FormatTable, Width: 70})
	if !strings.Contains(out, rep.Findings[0].Resource+"  CIS-1.1.15 HIGH:\n"+contIndent+"Anyone with") {
		t.Errorf("the reason should start on its own line under a long head:\n%s", out)
	}
}

func TestSummaryCountsMoveToTheirOwnLineWhenNarrow(t *testing.T) {
	var buf bytes.Buffer
	writeSummary(&buf, sampleReport(), painter{}, 30)
	lines := strings.Split(buf.String(), "\n")
	if len(lines) < 3 || !strings.HasPrefix(lines[1], "SCORE") || !strings.Contains(lines[2], "passed") {
		t.Errorf("a narrow summary should put the counts on their own line:\n%s", buf.String())
	}
}

// In the per-resource layout, a resource with nothing to show gets no
// section, and a report with nothing to fix gets no remediation section.
func TestDetailsSkipsResourcesAndSectionsWithNothingInThem(t *testing.T) {
	rep := sampleReport()
	var kept []engine.Finding
	for _, f := range rep.Findings {
		if f.Status == engine.StatusPass {
			kept = append(kept, f)
		}
	}
	rep.Findings = kept
	rep.Score = engine.Compute(kept)
	out := renderReport(t, rep, Options{Format: FormatTable, Details: true})
	if strings.Contains(out, "PRJ/app") || strings.Contains(out, "Remediations") {
		t.Errorf("a passing resource got a section, or an empty remediation list was drawn:\n%s", out)
	}
}

// The folder-level hint rides under the control's reference link when it has
// one.
func TestFullSweepHintSitsUnderTheReference(t *testing.T) {
	rep := reportWithRepeatedFinding(t, 3)
	for i := range rep.Findings {
		rep.Findings[i].Remediation = "Set it at Project settings -> Repositories -> All Repositories."
		rep.Findings[i].References = []string{"https://learn.microsoft.com/azure/devops/repos/git/branch-policies"}
	}
	out := renderReport(t, rep, Options{Format: FormatTable, Width: 100})
	ref := strings.Index(out, "https://learn.microsoft.com/azure/devops/repos/git/branch-policies")
	hint := strings.Index(out, "failing on all 3 repositories")
	if ref < 0 || hint < ref {
		t.Errorf("the hint should follow the reference line:\n%s", out)
	}
}
