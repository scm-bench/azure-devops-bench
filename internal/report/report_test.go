package report

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/scm-bench/azure-devops-bench/internal/engine"
	"github.com/scm-bench/azure-devops-bench/internal/scm"
)

// The table renderer wraps to console.Width, which reads COLUMNS. Pinning it
// keeps these assertions from depending on the width of whatever terminal the
// suite happens to run under; a test that cares about a different width sets it
// with t.Setenv.
func TestMain(m *testing.M) {
	os.Setenv("COLUMNS", "80")
	os.Exit(m.Run())
}

func sampleReport() *engine.Report {
	findings := []engine.Finding{
		{
			CheckID: "CIS-1.1.15", CISID: "1.1.15", Severity: "HIGH", Status: engine.StatusFail,
			Title:    "Ensure pushing is restricted",
			Resource: "PRJ/app", ResourceType: engine.ResourceRepository,
			Description: "Direct pushes bypass review entirely.",
			Details:     "Anyone with write access can push directly to main.",
			Evidence:    []string{"no restriction covers main"},
			Remediation: "Repository settings -> Branch permissions -> Add restriction",
			FixSummary:  "Enable Prevent changes without a pull request.",
			References:  []string{"https://example.invalid/cis"},
			Automated:   true,
		},
		{
			CheckID: "CIS-1.3.5", CISID: "1.3.5", Severity: "HIGH", Status: engine.StatusManual,
			Title: "Ensure MFA is enforced", Resource: engine.InstanceResourceName,
			ResourceType: engine.ResourceOrganization,
			Details:      "MFA is enforced by the identity provider.",
			Remediation:  "Enforce MFA at the IdP",
		},
		{
			CheckID: "CIS-1.1.3", CISID: "1.1.3", Severity: "HIGH", Status: engine.StatusPass,
			Title: "Ensure two approvals", Resource: "PRJ/app", ResourceType: engine.ResourceRepository,
			Details: "Pull requests require 2 approvals.", Remediation: "n/a",
			// Carried even on a pass, because metadata belongs to the control
			// rather than the verdict. The renderer is what decides not to show
			// it, which is what TestTableShowPassedIncludesPassingControls
			// checks.
			FixSummary: "Set Minimum approvals to 2 at Repository settings.",
			Automated:  true,
		},
	}

	return &engine.Report{
		Metadata: scm.Metadata{
			Tool: "azure-devops-bench", ToolVersion: "1.2.3", Platform: scm.PlatformAzureDevOps,
			BaseURL: "https://dev.azure.com/fabrikam", GeneratedAt: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC),
			Warnings: []string{"the user directory is not readable"},
		},
		Findings: findings,
		Score:    engine.Compute(findings),
	}
}

func render(t *testing.T, opts Options) string {
	t.Helper()
	return renderReport(t, sampleReport(), opts)
}

// reportWithUnreadableResource models the case UNREAD exists for: one
// repository the token could not read, costing n controls a verdict. They are
// MANUAL and Automated, which is what separates "this run came up short" from
// "no API can answer this".
func reportWithUnreadableResource(t *testing.T, ids ...string) *engine.Report {
	t.Helper()

	findings := []engine.Finding{{
		CheckID: "CIS-1.3.5", CISID: "1.3.5", Severity: "HIGH", Status: engine.StatusManual,
		Title: "Ensure MFA is enforced", Resource: engine.InstanceResourceName,
		ResourceType: engine.ResourceOrganization,
		Details:      "MFA is enforced by the identity provider.",
		Remediation:  "Enforce MFA at the IdP -> Authentication",
		Automated:    false,
	}}
	for _, id := range ids {
		findings = append(findings, engine.Finding{
			CheckID: "CIS-" + id, CISID: id, Severity: "HIGH", Status: engine.StatusManual,
			Title: "Ensure " + id, Resource: "PRJ/locked", ResourceType: engine.ResourceRepository,
			Details:     "Branch permissions could not be read.",
			Remediation: "Repository settings -> Branch permissions -> " + id,
			Automated:   true,
		})
	}

	return &engine.Report{
		Metadata: scm.Metadata{Tool: "azure-devops-bench", Platform: scm.PlatformAzureDevOps},
		Findings: findings,
		Score:    engine.Compute(findings),
	}
}

func renderReport(t *testing.T, rep *engine.Report, opts Options) string {
	t.Helper()
	var buf bytes.Buffer
	if err := Write(&buf, rep, opts); err != nil {
		t.Fatalf("Write: %v", err)
	}
	return buf.String()
}

// reportWithRepeatedFinding models the case the grouping exists for: one
// control failing identically across n repositories.
func reportWithRepeatedFinding(t *testing.T, n int) *engine.Report {
	t.Helper()

	findings := make([]engine.Finding, 0, n)
	for i := range n {
		findings = append(findings, engine.Finding{
			CheckID: "CIS-1.1.15", CISID: "1.1.15", Severity: "HIGH", Status: engine.StatusFail,
			Title:        "Ensure pushing is restricted",
			Resource:     fmt.Sprintf("PRJ/repo-%02d", i),
			ResourceType: engine.ResourceRepository,
			Details:      "Anyone with write access can push directly to main.",
			Evidence:     []string{"no restriction covers main"},
			Remediation:  "Repository settings -> Branch permissions",
			Automated:    true,
		})
	}

	return &engine.Report{
		Metadata: scm.Metadata{Tool: "azure-devops-bench", Platform: scm.PlatformAzureDevOps},
		Findings: findings,
		Score:    engine.Compute(findings),
	}
}

func TestTableIncludesFindingsRemediationAndWarnings(t *testing.T) {
	out := render(t, Options{Format: FormatTable})

	for _, want := range []string{
		"CIS-1.1.15",
		"PRJ/app",
		"Anyone with write access can push directly to main.",
		"fix: Enable Prevent changes without a pull request.",
		"https://example.invalid/cis",
		"Rules",
		"Scan warnings",
		"the user directory is not readable",
	} {
		if !containsText(out, want) {
			t.Errorf("table output is missing %q\n---\n%s", want, out)
		}
	}

	// The default is line-oriented: no per-resource sections, and the one-line
	// fix in place of the full remediation paragraph.
	if strings.Contains(out, "Total: ") {
		t.Errorf("the default output should not draw per-resource sections\n---\n%s", out)
	}
	if containsText(out, "Repository settings -> Branch permissions -> Add restriction") {
		t.Errorf("the full remediation paragraph belongs to --details\n---\n%s", out)
	}

	// Passing controls are summarised but not listed unless asked for.
	if strings.Contains(out, "Ensure two approvals") {
		t.Error("passing controls should be hidden without --show-passed")
	}
	if !strings.Contains(out, "1 passed") {
		t.Errorf("the summary should still count the passing control\n---\n%s", out)
	}
}

func TestDetailsIncludesPerResourceSections(t *testing.T) {
	out := render(t, Options{Format: FormatTable, Details: true})

	for _, want := range []string{
		"CIS-1.1.15",
		"PRJ/app",
		"Total: ",
		"Anyone with write access can push directly to main.",
		"Repository settings -> Branch permissions -> Add restriction",
		"Remediations",
		"Scan warnings",
		"the user directory is not readable",
	} {
		if !containsText(out, want) {
			t.Errorf("details output is missing %q\n---\n%s", want, out)
		}
	}
}

// In the detail layout the scan warnings still come before the findings —
// they say how much of the report to believe — and the score is the trailer in
// both layouts: one family rule, the verdict last.
func TestWarningsComeBeforeTheDetailSections(t *testing.T) {
	out := render(t, Options{Format: FormatTable, Details: true})

	warnings := strings.Index(out, "Scan warnings")
	findings := strings.Index(out, "Total: ")
	remediations := strings.Index(out, "Remediations (")
	score := strings.Index(out, "SCORE")

	for _, step := range []struct {
		name       string
		before, at int
	}{
		{"scan warnings before the findings", warnings, findings},
		{"findings before the remediations", findings, remediations},
		{"remediations before the score trailer", remediations, score},
	} {
		if step.before < 0 || step.at < 0 {
			t.Fatalf("%s: a section is missing entirely\n---\n%s", step.name, out)
		}
		if step.before > step.at {
			t.Errorf("%s: order is wrong\n---\n%s", step.name, out)
		}
	}
}

// Findings first, their explanation next, references after, and the verdict
// last — a linter's order, where the score is the closing line a reader (or a
// CI log tail) meets first from the bottom.
func TestOverviewSectionOrder(t *testing.T) {
	out := render(t, Options{Format: FormatTable})

	findings := strings.Index(out, "CIS-1.1.15")
	warnings := strings.Index(out, "Scan warnings")
	rules := strings.Index(out, "Rules")
	hint := strings.Index(out, "Details: rerun with --details")
	score := strings.Index(out, "SCORE")

	for _, step := range []struct {
		name       string
		before, at int
	}{
		{"findings before the scan warnings", findings, warnings},
		{"scan warnings before the rules index", warnings, rules},
		{"rules index before the hint", rules, hint},
		{"hint before the score trailer", hint, score},
	} {
		if step.before < 0 || step.at < 0 {
			t.Fatalf("%s: a section is missing entirely\n---\n%s", step.name, out)
		}
		if step.before > step.at {
			t.Errorf("%s: order is wrong\n---\n%s", step.name, out)
		}
	}
}

// Both are MANUAL, and reading them as one state is what made the sample
// instance report nineteen controls needing a person when six of them did. The
// other thirteen were one unreadable repository. The Status column is where
// that difference survives now that the sections are gone.
func TestUnreadIsDistinctFromManualInTheStatusColumn(t *testing.T) {
	ids := []string{"1.1.3", "1.1.4", "1.1.9", "1.1.15", "1.1.16", "1.1.17", "1.2.1"}
	out := renderReport(t, reportWithUnreadableResource(t, ids...), Options{Format: FormatTable, Details: true})

	if n := strings.Count(out, statusUnread); n < len(ids) {
		t.Errorf("only %d of %d unreadable controls are marked %s\n---\n%s", n, len(ids), statusUnread, out)
	}
	// The control no API can answer is a different question and must not be
	// swept into the same word.
	unreadAt := strings.Index(out, "CIS-1.3.5")
	if unreadAt < 0 {
		t.Fatalf("the non-automated control is missing entirely\n---\n%s", out)
	}
	row := out[unreadAt:]
	if end := strings.Index(row, "\n"); end > 0 {
		row = row[:end]
	}
	if strings.Contains(row, statusUnread) {
		t.Errorf("a control no API can answer was reported as %s: %q", statusUnread, row)
	}

	// Every control is still named. A truncated list would leave the reader
	// unable to tell whether the ones they care about are among them.
	for _, id := range ids {
		if !strings.Contains(out, "CIS-"+id) {
			t.Errorf("control CIS-%s went unlisted\n---\n%s", id, out)
		}
	}
}

// A control the scan never saw is not known to be misconfigured. Printing how
// to change its settings would say the opposite; what it needs is access.
func TestUnreadControlsGetNoFixLine(t *testing.T) {
	out := renderReport(t, reportWithUnreadableResource(t, "1.1.15", "1.1.16"), Options{Format: FormatTable})

	for _, unwanted := range []string{"Branch permissions -> 1.1.15", "Branch permissions -> 1.1.16"} {
		if strings.Contains(out, unwanted) {
			t.Errorf("an unread control was given a remediation: %q\n---\n%s", unwanted, out)
		}
	}
	// The control that genuinely needs a person keeps its aggregated line and
	// its fix.
	if !containsText(out, "CIS-1.3.5 MANUAL") {
		t.Errorf("the true-manual control lost its record\n---\n%s", out)
	}
	if !strings.Contains(out, "Enforce MFA at the IdP") {
		t.Errorf("the control that does need a person lost its fix\n---\n%s", out)
	}
}

// The one-line fix rides in the finding's cell so the reader can act without
// scrolling; the paragraph stays in its own section so the table stays a table.
func TestFixSummaryRidesWithTheVerdictAndTheParagraphDoesNot(t *testing.T) {
	out := render(t, Options{Format: FormatTable, Details: true})

	remediations := strings.Index(out, "Remediations (")
	if remediations < 0 {
		t.Fatalf("no remediations section\n---\n%s", out)
	}
	tables, fixes := out[:remediations], out[remediations:]

	if !containsText(tables, "fix: Enable Prevent changes without a pull request.") {
		t.Errorf("the one-line fix is not in the finding's cell\n---\n%s", tables)
	}
	if containsText(tables, "Add restriction") {
		t.Errorf("the full remediation leaked into a table\n---\n%s", tables)
	}
	if !containsText(fixes, "Add restriction") {
		t.Errorf("the full remediation is missing from its section\n---\n%s", fixes)
	}
}

// Nothing may run past the width, at any width, whatever the escape sequences
// would have measured.
func TestEveryLineFitsTheTerminalWidth(t *testing.T) {
	for _, columns := range []string{"60", "80", "100", "140", "300"} {
		t.Setenv("COLUMNS", columns)
		limit := min(max(atoi(t, columns), 60), 160)

		for _, colour := range []bool{false, true} {
			for _, details := range []bool{false, true} {
				out := renderReport(t, reportWithUnreadableResource(t, "1.1.3", "1.1.15", "1.1.16"),
					Options{Format: FormatTable, Color: colour, Details: details})
				for _, line := range strings.Split(out, "\n") {
					if n := utf8.RuneCountInString(stripANSI(line)); n > limit {
						t.Errorf("COLUMNS=%s colour=%v details=%v: %d columns: %q", columns, colour, details, n, line)
					}
				}
			}
		}
	}
}

func atoi(t *testing.T, s string) int {
	t.Helper()
	n := 0
	for _, r := range s {
		n = n*10 + int(r-'0')
	}
	return n
}

// tableCells rebuilds every cell of every table in out, joining the lines a
// cell was wrapped across back into one string.
//
// Assertions need it because the renderer wraps to the terminal: a sentence in
// a cell is several lines with a border between them, so strings.Contains over
// the raw output cannot find it. Rebuilding by column boundary rather than by
// splitting on the border keeps a cell's own lines together instead of
// interleaving them with its neighbours'.
func tableCells(out string) []string {
	var cells []string
	var bounds []int
	var pending []string

	endRow := func() {
		for i, c := range pending {
			if s := strings.Join(strings.Fields(c), " "); s != "" {
				cells = append(cells, s)
			}
			pending[i] = ""
		}
	}
	endTable := func() {
		endRow()
		pending, bounds = nil, nil
	}

	for _, raw := range strings.Split(stripANSI(out), "\n") {
		line := []rune(raw)
		if len(line) == 0 {
			endTable()
			continue
		}
		switch line[0] {
		case '┌':
			endTable()
			for i, r := range line {
				if r == '┌' || r == '┬' || r == '┐' {
					bounds = append(bounds, i)
				}
			}
			pending = make([]string, max(len(bounds)-1, 0))
		case '│':
			for i := 0; i+1 < len(bounds) && i < len(pending); i++ {
				lo, hi := bounds[i]+1, bounds[i+1]
				if hi > len(line) {
					hi = len(line)
				}
				if lo < hi {
					pending[i] += " " + string(line[lo:hi])
				}
			}
		case '├':
			endRow()
		case '└':
			endTable()
		default:
			endTable()
		}
	}
	endTable()
	return cells
}

// containsText looks for want anywhere in out, treating a wrapped table cell as
// the single string it reads as.
func containsText(out, want string) bool {
	if strings.Contains(stripANSI(out), want) {
		return true
	}
	for _, cell := range tableCells(out) {
		if strings.Contains(cell, want) {
			return true
		}
	}
	return false
}

func stripANSI(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		if s[i] == 0x1b {
			for i < len(s) && s[i] != 'm' {
				i++
			}
			i++
			continue
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

func TestTableShowPassedIncludesPassingControls(t *testing.T) {
	out := render(t, Options{Format: FormatTable, ShowPassed: true, Details: true})
	if !containsText(out, "Ensure two approvals") {
		t.Error("--show-passed should list passing controls")
	}
	if !strings.Contains(out, statusPass) {
		t.Errorf("no %s appears in the Status column\n---\n%s", statusPass, out)
	}

	// Not with a fix beside them. Telling someone how to change a setting that
	// is already right reads as an instruction to go and break it.
	for _, cell := range tableCells(out) {
		if strings.Contains(cell, "Pull requests require 2 approvals.") && strings.Contains(cell, "fix:") {
			t.Errorf("a passing control was given a fix: %q", cell)
		}
	}
}

func TestTableIsPlainWithoutColor(t *testing.T) {
	out := render(t, Options{Format: FormatTable, Color: false})
	if strings.Contains(out, "\033[") {
		t.Error("colour was disabled but ANSI escapes were emitted")
	}
}

func TestJSONRoundTrips(t *testing.T) {
	out := render(t, Options{Format: FormatJSON})

	var decoded engine.Report
	if err := json.Unmarshal([]byte(out), &decoded); err != nil {
		t.Fatalf("JSON output does not parse: %v\n%s", err, out)
	}
	if len(decoded.Findings) != 3 {
		t.Errorf("decoded %d findings, want 3", len(decoded.Findings))
	}
	if decoded.Score.Value != 50 {
		t.Errorf("decoded score = %d, want 50 (one HIGH pass, one HIGH fail)", decoded.Score.Value)
	}
	// Remediation arrows must survive intact rather than becoming >.
	if !strings.Contains(out, "Branch permissions -> Add restriction") {
		t.Error("remediation text should not be HTML-escaped")
	}
}

// sarifDoc is the part of a SARIF log these tests read.
type sarifDoc struct {
	Schema  string `json:"$schema"`
	Version string `json:"version"`
	Runs    []struct {
		AutomationDetails struct {
			ID string `json:"id"`
		} `json:"automationDetails"`
		Tool struct {
			Driver struct {
				Name    string `json:"name"`
				Version string `json:"version"`
				Rules   []struct {
					ID               string `json:"id"`
					ShortDescription struct {
						Text string `json:"text"`
					} `json:"shortDescription"`
					FullDescription struct {
						Text string `json:"text"`
					} `json:"fullDescription"`
					DefaultConfiguration struct {
						Level string `json:"level"`
					} `json:"defaultConfiguration"`
					Properties struct {
						SecuritySeverity string `json:"security-severity"`
					} `json:"properties"`
				} `json:"rules"`
			} `json:"driver"`
		} `json:"tool"`
		Results []struct {
			RuleID  string `json:"ruleId"`
			Level   string `json:"level"`
			Message struct {
				Text string `json:"text"`
			} `json:"message"`
			Locations []struct {
				PhysicalLocation struct {
					ArtifactLocation struct {
						URI string `json:"uri"`
					} `json:"artifactLocation"`
					Region struct {
						StartLine, StartColumn, EndLine, EndColumn int
					} `json:"region"`
				} `json:"physicalLocation"`
				LogicalLocations []struct {
					Name               string `json:"name"`
					FullyQualifiedName string `json:"fullyQualifiedName"`
					Kind               string `json:"kind"`
				} `json:"logicalLocations"`
			} `json:"locations"`
			PartialFingerprints map[string]string `json:"partialFingerprints"`
		} `json:"results"`
		Invocations []struct {
			ExecutionSuccessful        bool `json:"executionSuccessful"`
			ToolExecutionNotifications []struct {
				Level   string `json:"level"`
				Message struct {
					Text string `json:"text"`
				} `json:"message"`
			} `json:"toolExecutionNotifications"`
		} `json:"invocations"`
	} `json:"runs"`
}

func parseSARIF(t *testing.T, out string) sarifDoc {
	t.Helper()
	var log sarifDoc
	if err := json.Unmarshal([]byte(out), &log); err != nil {
		t.Fatalf("SARIF output does not parse: %v\n%s", err, out)
	}
	if len(log.Runs) != 1 {
		t.Fatalf("expected one run, got %d", len(log.Runs))
	}
	return log
}

func TestSARIFStructure(t *testing.T) {
	log := parseSARIF(t, render(t, Options{Format: FormatSARIF, ToolVersion: "1.2.3"}))
	if log.Version != "2.1.0" || log.Schema == "" {
		t.Errorf("SARIF version = %q schema = %q", log.Version, log.Schema)
	}
	run := log.Runs[0]
	if run.Tool.Driver.Name != "azure-devops-bench" || run.Tool.Driver.Version != "1.2.3" {
		t.Errorf("driver = %+v", run.Tool.Driver)
	}
	// Per organization, so two organizations uploading to one GitHub
	// repository do not close each other's alerts — and the organization
	// path is in it, because every Services organization shares a host.
	if run.AutomationDetails.ID != "azure-devops-bench/dev.azure.com/fabrikam/" {
		t.Errorf("automationDetails.id = %q", run.AutomationDetails.ID)
	}
	// Passing controls are omitted; the failure and the manual review remain.
	if len(run.Results) != 2 {
		t.Fatalf("expected 2 results (1 fail + 1 manual), got %d", len(run.Results))
	}

	byRule := map[string]string{}
	for _, r := range run.Results {
		byRule[r.RuleID] = r.Level
		// GitHub drops a result without a physical location from the
		// Security tab while accepting the upload.
		if len(r.Locations) != 1 || r.Locations[0].PhysicalLocation.ArtifactLocation.URI == "" {
			t.Errorf("result %s has no physical location", r.RuleID)
			continue
		}
		reg := r.Locations[0].PhysicalLocation.Region
		if reg.StartLine != 1 || reg.StartColumn != 1 || reg.EndLine != 1 || reg.EndColumn != 1 {
			t.Errorf("result %s region = %+v", r.RuleID, reg)
		}
		if len(r.Locations[0].LogicalLocations) != 1 {
			t.Errorf("result %s has no logical location", r.RuleID)
		}
		if r.PartialFingerprints["scmBenchFindingV1"] == "" || !strings.HasSuffix(r.PartialFingerprints["primaryLocationLineHash"], ":1") {
			t.Errorf("result %s fingerprints = %v", r.RuleID, r.PartialFingerprints)
		}
		if !strings.Contains(r.Message.Text, "Remediation:") {
			t.Errorf("result %s message carries no remediation", r.RuleID)
		}
	}
	if byRule["CIS-1.1.15"] != "error" {
		t.Errorf("a HIGH failure should be level error, got %q", byRule["CIS-1.1.15"])
	}
	if byRule["CIS-1.3.5/manual"] != "note" {
		t.Errorf("a MANUAL finding goes under its own rule as a note, got %v", byRule)
	}
	for _, r := range run.Results {
		uri := r.Locations[0].PhysicalLocation.ArtifactLocation.URI
		switch r.RuleID {
		case "CIS-1.1.15":
			if uri != "azure-devops/dev.azure.com/fabrikam/PRJ/app" || r.Locations[0].LogicalLocations[0].Kind != "repository" {
				t.Errorf("repository location = %q %+v", uri, r.Locations[0].LogicalLocations)
			}
		case "CIS-1.3.5/manual":
			if uri != "azure-devops/dev.azure.com/fabrikam/instance" || r.Locations[0].LogicalLocations[0].Kind != "organization" {
				t.Errorf("organization location = %q %+v", uri, r.Locations[0].LogicalLocations)
			}
		}
	}

	for _, r := range run.Tool.Driver.Rules {
		switch r.ID {
		case "CIS-1.1.15":
			if r.FullDescription.Text != "Direct pushes bypass review entirely." || r.FullDescription.Text == r.ShortDescription.Text {
				t.Errorf("fullDescription = %q", r.FullDescription.Text)
			}
			if r.Properties.SecuritySeverity != "8.0" || r.DefaultConfiguration.Level != "error" {
				t.Errorf("fail rule = %+v", r)
			}
		case "CIS-1.3.5/manual":
			// "Needs a person" must never display as a High alert.
			if r.Properties.SecuritySeverity != "" || r.DefaultConfiguration.Level != "note" {
				t.Errorf("manual rule = %+v", r)
			}
			if !strings.Contains(r.ShortDescription.Text, "needs manual review") {
				t.Errorf("manual rule name = %q", r.ShortDescription.Text)
			}
		default:
			t.Errorf("unexpected rule %s", r.ID)
		}
	}

	if len(run.Invocations) != 1 || len(run.Invocations[0].ToolExecutionNotifications) != 1 || !run.Invocations[0].ExecutionSuccessful {
		t.Errorf("invocations = %+v", run.Invocations)
	}
}

// One finding's fingerprint is the same in every run, and different between
// two organizations on one host.
func TestSARIFFingerprintsAreStableAndPerOrganization(t *testing.T) {
	a := parseSARIF(t, render(t, Options{Format: FormatSARIF}))
	b := parseSARIF(t, render(t, Options{Format: FormatSARIF}))
	if a.Runs[0].Results[0].PartialFingerprints["primaryLocationLineHash"] != b.Runs[0].Results[0].PartialFingerprints["primaryLocationLineHash"] {
		t.Error("the same finding fingerprinted differently across runs")
	}
	rep := sampleReport()
	rep.Metadata.BaseURL = "https://dev.azure.com/contoso"
	c := parseSARIF(t, renderReport(t, rep, Options{Format: FormatSARIF}))
	if a.Runs[0].Results[0].PartialFingerprints["primaryLocationLineHash"] == c.Runs[0].Results[0].PartialFingerprints["primaryLocationLineHash"] {
		t.Error("two organizations share a fingerprint")
	}
	if c.Runs[0].AutomationDetails.ID == a.Runs[0].AutomationDetails.ID {
		t.Error("two organizations share an automation ID")
	}
}

// Path segments are percent-encoded: project and repository names may hold
// spaces.
func TestSARIFEncodesPathSegments(t *testing.T) {
	rep := sampleReport()
	rep.Findings[0].Resource = "Fabrikam Fiber/web app"
	rep.Metadata.BaseURL = "https://ado.example.com/tfs/Default Collection"
	log := parseSARIF(t, renderReport(t, rep, Options{Format: FormatSARIF}))
	for _, r := range log.Runs[0].Results {
		if r.RuleID == "CIS-1.1.15" {
			if got := r.Locations[0].PhysicalLocation.ArtifactLocation.URI; got != "azure-devops/ado.example.com/tfs/Default%20Collection/Fabrikam%20Fiber/web%20app" {
				t.Errorf("uri = %q", got)
			}
		}
	}
}

// A control no API can answer is one question, not one per repository.
func TestSARIFManualByDesignIsOneResultPerControl(t *testing.T) {
	var findings []engine.Finding
	for i := 0; i < 5; i++ {
		findings = append(findings, engine.Finding{
			CheckID: "CIS-1.1.6", CISID: "1.1.6", Severity: "MEDIUM", Status: engine.StatusManual,
			Title: "Code owners", Resource: fmt.Sprintf("P/r%d", i), ResourceType: engine.ResourceRepository,
			Details: "Confirm by hand.", Automated: false,
		})
	}
	// An automated control that came up short is per resource.
	findings = append(findings, engine.Finding{
		CheckID: "CIS-1.1.15", CISID: "1.1.15", Severity: "HIGH", Status: engine.StatusManual,
		Title: "Pushes", Resource: "P/r0", ResourceType: engine.ResourceRepository, Details: "unreadable", Automated: true,
	}, engine.Finding{
		CheckID: "CIS-1.1.15", CISID: "1.1.15", Severity: "HIGH", Status: engine.StatusManual,
		Title: "Pushes", Resource: "P/r1", ResourceType: engine.ResourceRepository, Details: "unreadable", Automated: true,
	})
	rep := &engine.Report{Metadata: scm.Metadata{BaseURL: "https://dev.azure.com/fabrikam", Platform: scm.PlatformAzureDevOps}, Findings: findings}
	log := parseSARIF(t, renderReport(t, rep, Options{Format: FormatSARIF}))
	count := map[string]int{}
	for _, r := range log.Runs[0].Results {
		count[r.RuleID]++
		if r.RuleID == "CIS-1.1.6/manual" && !strings.Contains(r.Message.Text, "applies to 5 repositories") {
			t.Errorf("message = %q", r.Message.Text)
		}
	}
	if count["CIS-1.1.6/manual"] != 1 || count["CIS-1.1.15/manual"] != 2 {
		t.Errorf("results per rule = %v", count)
	}
}

// GitHub rejects a run of more than 5000 results; the worst are kept and the
// cut is announced.
func TestSARIFCapsResultsHighestSeverityFirst(t *testing.T) {
	var findings []engine.Finding
	for i := 0; i < 5003; i++ {
		findings = append(findings, engine.Finding{
			CheckID: "CIS-1.1.8", CISID: "1.1.8", Severity: "LOW", Status: engine.StatusFail,
			Title: "Stale", Resource: fmt.Sprintf("P/r%05d", i), ResourceType: engine.ResourceRepository, Details: "stale", Automated: true,
		})
	}
	findings = append(findings, engine.Finding{
		CheckID: "CIS-1.1.15", CISID: "1.1.15", Severity: "HIGH", Status: engine.StatusFail,
		Title: "Pushes", Resource: "P/zzz", ResourceType: engine.ResourceRepository, Details: "push", Automated: true,
	})
	rep := &engine.Report{Metadata: scm.Metadata{BaseURL: "https://dev.azure.com/fabrikam", Platform: scm.PlatformAzureDevOps}, Findings: findings}
	log := parseSARIF(t, renderReport(t, rep, Options{Format: FormatSARIF}))
	run := log.Runs[0]
	if len(run.Results) != 5000 {
		t.Fatalf("results = %d, want 5000", len(run.Results))
	}
	if run.Results[0].RuleID != "CIS-1.1.15" {
		t.Errorf("first result = %s; the HIGH failure must survive the cap", run.Results[0].RuleID)
	}
	var notice string
	for _, n := range run.Invocations[0].ToolExecutionNotifications {
		if strings.Contains(n.Message.Text, "withheld") {
			notice = n.Message.Text
		}
	}
	if !strings.Contains(notice, "4 of 5004") || !strings.Contains(notice, "-o json") {
		t.Errorf("notice = %q", notice)
	}
}

// A scan that could not enumerate everything is not a successful execution,
// and says what it missed.
func TestSARIFReportsIncompleteEnumeration(t *testing.T) {
	rep := sampleReport()
	rep.Metadata.Unlisted = []string{"Fabrikam-Fiber"}
	log := parseSARIF(t, renderReport(t, rep, Options{Format: FormatSARIF}))
	inv := log.Runs[0].Invocations[0]
	if inv.ExecutionSuccessful {
		t.Error("executionSuccessful must be false for an incomplete scan")
	}
	found := false
	for _, n := range inv.ToolExecutionNotifications {
		if n.Level == "error" && strings.Contains(n.Message.Text, "project Fabrikam-Fiber") {
			found = true
		}
	}
	if !found {
		t.Errorf("notifications = %+v", inv.ToolExecutionNotifications)
	}
}

func TestUnknownFormatIsRejected(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, sampleReport(), Options{Format: "yaml"}); err == nil {
		t.Error("an unknown format should be rejected")
	}
}

// Remediation is a paragraph naming a settings path, and a paragraph in a table
// cell is a column of three-word lines. It keeps its own section, as prose.
func TestRemediationLivesInItsOwnSection(t *testing.T) {
	out := render(t, Options{Format: FormatTable, Details: true})

	remedy := "Repository settings -> Branch permissions -> Add restriction"
	tables, remediations, ok := strings.Cut(out, "Remediations (")
	if !ok {
		t.Fatalf("no remediation section\n---\n%s", out)
	}
	if containsText(tables, remedy) {
		t.Errorf("remediation is still inside a finding's table\n---\n%s", tables)
	}
	if !containsText(remediations, remedy) {
		t.Errorf("remediation missing from its own section\n---\n%s", remediations)
	}
	// Prose, not a table: no borders after the section heading.
	if strings.Contains(remediations, "┌") {
		t.Errorf("the remediation section was drawn as a table\n---\n%s", remediations)
	}
}

// The fix rides with every finding — a record is self-contained — but the
// Rules index names each control exactly once.
func TestRulesIndexNamesEachControlOnce(t *testing.T) {
	rep := reportWithRepeatedFinding(t, 4)
	rep.Findings[2].Status = engine.StatusManual
	for i := range rep.Findings {
		rep.Findings[i].References = []string{"https://example.invalid/branch-permissions"}
	}
	rep.Score = engine.Compute(rep.Findings)

	out := renderReport(t, rep, Options{Format: FormatTable})
	at := strings.Index(out, "Rules")
	if at < 0 {
		t.Fatalf("no rules index\n---\n%s", out)
	}
	if n := strings.Count(out[at:], "CIS-1.1.15"); n != 1 {
		t.Errorf("the index names the control %d times, want once\n---\n%s", n, out[at:])
	}
}

func TestNoRemediationsDropsTheSection(t *testing.T) {
	out := render(t, Options{Format: FormatTable, NoRemediations: true})

	if strings.Contains(out, "Remediations (") {
		t.Errorf("--no-remediations left the section in\n---\n%s", out)
	}
	// The findings themselves are still there; only the fixes are gone.
	if !strings.Contains(out, "CIS-1.1.15") {
		t.Errorf("--no-remediations dropped the findings too\n---\n%s", out)
	}
}

// All four states are counted, on one line, in the state names the rest of the
// tool uses.
//
// PASS/FAIL/MANUAL/NA — the names in the JSON and in `list-checks`. The Status
// column inside a table says UNREAD where a MANUAL was this run's shortfall
// rather than the control's; the arithmetic up here does not, because the score
// counts what the control returned.
func TestSummaryReportsAllFourStates(t *testing.T) {
	out := render(t, Options{Format: FormatTable})

	for _, want := range []string{"1 passed", "1 failed", "1 manual", "0 n/a"} {
		if !strings.Contains(out, want) {
			t.Errorf("summary is missing %q\n---\n%s", want, out)
		}
	}
	// One line, not kube-bench's four.
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "SCORE") {
			if !strings.Contains(line, "1 passed") || !strings.Contains(line, "0 n/a") {
				t.Errorf("the counts should sit beside the score, got %q", line)
			}
			return
		}
	}
	t.Errorf("no SCORE line\n---\n%s", out)
}

// SARIF types run.results as an array, and a nil Go slice marshals to null.
// The case that reaches it is the good one — an instance where nothing failed
// and nothing needed a human — so the failure mode was that a clean scan
// produced a file GitHub's SARIF upload rejects, while every dirty scan worked.
func TestSARIFResultsIsAnArrayWhenThereIsNothingToReport(t *testing.T) {
	rep := &engine.Report{
		Metadata: scm.Metadata{Tool: "azure-devops-bench", Platform: scm.PlatformAzureDevOps},
		Findings: []engine.Finding{{
			CheckID: "CIS-1.3.9", CISID: "1.3.9", Title: "Ensure the organization is verified",
			Severity: "LOW", Status: engine.StatusNA,
			Resource: engine.InstanceResourceName, ResourceType: engine.ResourceOrganization,
			Details: "Not applicable.",
		}},
	}
	out := renderReport(t, rep, Options{Format: FormatSARIF, ToolVersion: "1.2.3"})

	if strings.Contains(out, `"results": null`) {
		t.Fatalf("run.results serialised as null, which is not a SARIF array:\n%s", out)
	}

	// Asserted through the raw JSON rather than a typed struct, because
	// unmarshalling turns both null and [] into the same nil slice and would
	// pass either way.
	var log struct {
		Runs []struct {
			Results *[]json.RawMessage `json:"results"`
			Tool    struct {
				Driver struct {
					Rules *[]json.RawMessage `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
		} `json:"runs"`
	}
	if err := json.Unmarshal([]byte(out), &log); err != nil {
		t.Fatalf("unmarshal SARIF: %v", err)
	}
	if len(log.Runs) != 1 {
		t.Fatalf("got %d runs, want 1", len(log.Runs))
	}
	if log.Runs[0].Results == nil {
		t.Error("run.results is null, want []")
	} else if len(*log.Runs[0].Results) != 0 {
		t.Errorf("run.results has %d entries, want 0", len(*log.Runs[0].Results))
	}
	if log.Runs[0].Tool.Driver.Rules == nil {
		t.Error("tool.driver.rules is null, want []")
	}
}

// The score excludes MANUAL from both sides, so a scan that could see very
// little scores high off a tiny denominator — 100/100 is reachable from three
// decided controls. The arithmetic is right; what was missing was any line
// saying how small the sample was.
func TestSummaryStatesHowMuchWasActuallyScored(t *testing.T) {
	out := render(t, Options{Format: FormatTable, ToolVersion: "1.2.3"})
	if !strings.Contains(out, "could not be evaluated") {
		t.Errorf("summary does not report evaluation coverage:\n%s", out)
	}

	// With nothing unevaluated there is nothing to caveat, so the line is
	// absent rather than reading "0 could not be evaluated".
	rep := &engine.Report{
		Metadata: scm.Metadata{Tool: "azure-devops-bench", Platform: scm.PlatformAzureDevOps},
		Findings: []engine.Finding{{
			CheckID: "CIS-1.1.15", CISID: "1.1.15", Title: "t", Severity: "HIGH",
			Status: engine.StatusPass, Resource: "PRJ/app", ResourceType: engine.ResourceRepository,
			Details: "fine",
		}},
	}
	rep.Score = engine.Compute(rep.Findings)
	if got := renderReport(t, rep, Options{Format: FormatTable}); strings.Contains(got, "could not be evaluated") {
		t.Errorf("coverage line shown when everything was evaluated:\n%s", got)
	}
}

// GitHub takes an alert's displayed severity from the rule's security-severity,
// not from the result's level. A control that can only ever report MANUAL —
// CIS-1.3.5, where multi-factor authentication is enforced somewhere Azure DevOps
// cannot be asked about it — therefore arrived in the Security panel as an 8.0
// High alert asserting a setting was broken, while `--fail-on high` locally did
// not fail on it at all. Two severities for one finding, and the louder one was
// the wrong one.
func TestSARIFManualFindingsUseTheirOwnRule(t *testing.T) {
	failing := engine.Finding{
		CheckID: "CIS-1.1.15", CISID: "1.1.15", Title: "Restrict pushes", Severity: "HIGH",
		Status: engine.StatusFail, Resource: "PRJ/app", Automated: true,
		ResourceType: engine.ResourceRepository, Details: "anyone can push",
	}
	unread := engine.Finding{
		CheckID: "CIS-1.1.15", CISID: "1.1.15", Title: "Restrict pushes", Severity: "HIGH",
		Status: engine.StatusManual, Resource: "PRJ/other", Automated: true,
		ResourceType: engine.ResourceRepository, Details: "cannot read",
	}
	rep := &engine.Report{
		Metadata: scm.Metadata{Tool: "azure-devops-bench", Platform: scm.PlatformAzureDevOps, BaseURL: "https://dev.azure.com/fabrikam"},
		Findings: []engine.Finding{unread, failing},
	}
	log := parseSARIF(t, renderReport(t, rep, Options{Format: FormatSARIF, ToolVersion: "1.2.3"}))
	rules := map[string]string{}
	for _, r := range log.Runs[0].Tool.Driver.Rules {
		rules[r.ID] = r.Properties.SecuritySeverity
	}
	if rules["CIS-1.1.15"] != "8.0" {
		t.Errorf("fail rule severity = %q", rules["CIS-1.1.15"])
	}
	if sev, ok := rules["CIS-1.1.15/manual"]; !ok || sev != "" {
		t.Errorf("manual rule = %q present=%v; no security-severity", sev, ok)
	}
}

func TestSARIFSeverityScores(t *testing.T) {
	for sev, want := range map[string]string{"HIGH": "8.0", "MEDIUM": "5.0", "LOW": "2.0"} {
		if got := securitySeverity(sev); got != want {
			t.Errorf("%s = %s, want %s", sev, got, want)
		}
	}
	for sev, want := range map[string]string{"HIGH": "error", "MEDIUM": "warning", "LOW": "note"} {
		if got := sarifLevel(sev); got != want {
			t.Errorf("%s = %s, want %s", sev, got, want)
		}
	}
	if instanceID("::bad") == "" {
		t.Error("an unparseable base URL still names something")
	}
}

// countText counts occurrences of want, treating a wrapped table cell as the
// single string it reads as.
func countText(out, want string) int {
	n := strings.Count(stripANSI(out), want)
	for _, cell := range tableCells(out) {
		n += strings.Count(cell, want)
	}
	return n
}

// The cap exists for an instance with more repositories than anyone will read
// through, and when it bites it has to say so — a report that silently omits
// repositories with findings is worse than a long one.
func TestMaxResourcesCapsTheTablesAndSaysSo(t *testing.T) {
	out := renderReport(t, reportWithRepeatedFinding(t, 6), Options{Format: FormatTable, Details: true, MaxResources: 2})

	if n := strings.Count(out, "Total: "); n != 2 {
		t.Errorf("drew %d resource tables, want 2\n---\n%s", n, out)
	}
	if !containsText(out, "4 more resources with findings not shown") {
		t.Errorf("the cap was applied silently\n---\n%s", out)
	}
}

// Zero is the default and means "draw them all", because each table is a
// resource's whole verdict rather than a list that could be trimmed.
func TestMaxResourcesZeroDrawsEveryTable(t *testing.T) {
	out := renderReport(t, reportWithRepeatedFinding(t, 6), Options{Format: FormatTable, Details: true, MaxResources: 0})
	if n := strings.Count(out, "Total: "); n != 6 {
		t.Errorf("drew %d resource tables, want 6\n---\n%s", n, out)
	}
	if strings.Contains(out, "not shown") {
		t.Errorf("nothing should have been withheld\n---\n%s", out)
	}
}

// A report with no warnings and no policy errors should not print the headings
// for them.
func TestQuietScanOmitsTheWarningSections(t *testing.T) {
	rep := reportWithRepeatedFinding(t, 1)
	out := renderReport(t, rep, Options{Format: FormatTable})
	for _, unwanted := range []string{"Scan warnings", "Policy errors"} {
		if strings.Contains(out, unwanted) {
			t.Errorf("%q was printed for a scan that had none\n---\n%s", unwanted, out)
		}
	}
}

// A policy that would not evaluate is a failure of the tool, and it has to be
// as visible as one.
func TestPolicyErrorsAreReported(t *testing.T) {
	rep := sampleReport()
	rep.Errors = []string{"CIS-1.1.3 on PRJ/app: policy evaluation failed: undefined function"}
	out := renderReport(t, rep, Options{Format: FormatTable})

	if !strings.Contains(out, "Policy errors") {
		t.Errorf("no policy error section\n---\n%s", out)
	}
	if !containsText(out, "policy evaluation failed") {
		t.Errorf("the policy error text is missing\n---\n%s", out)
	}
}

// A long base URL pushes the header past the width. It sheds a part at a time
// rather than wrapping, because the padded "·" separators do not survive being
// broken across a line.
func TestHeaderShedsPartsRatherThanOverflowing(t *testing.T) {
	for _, tc := range []struct {
		name    string
		baseURL string
		want    []string
	}{
		{"fits on one line", "https://bb.example.com",
			[]string{"azure-devops-bench 1.2.3  ·  https://bb.example.com  ·  2026-01-01 12:00:00 UTC"}},
		{"timestamp moves down", "https://ado.a-fairly-long-hostname.example.com/c",
			[]string{"azure-devops-bench 1.2.3  ·  https://ado.a-fairly-long-hostname.example.com/c", "scanned 2026-01-01 12:00:00 UTC"}},
		{"url gets its own line", "https://ado.a-very-long-hostname-for-one-company-intranet.example.com/c",
			[]string{"azure-devops-bench 1.2.3", "https://ado.a-very-long-hostname-for-one-company-intranet.example.com/c", "scanned 2026-01-01 12:00:00 UTC"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rep := sampleReport()
			rep.Metadata.BaseURL = tc.baseURL
			out := renderReport(t, rep, Options{Format: FormatTable})

			header := strings.SplitN(out, "\n\n", 2)[0]
			if got := strings.Split(header, "\n"); !slices.Equal(got, tc.want) {
				t.Errorf("header =\n%#v\nwant\n%#v", got, tc.want)
			}
			// The URL is one unbreakable token, so its own line may still be
			// long; nothing else may be.
			for _, l := range strings.Split(header, "\n") {
				if strings.Contains(l, tc.baseURL) {
					continue
				}
				if n := utf8.RuneCountInString(l); n > 80 {
					t.Errorf("header line is %d columns: %q", n, l)
				}
			}
		})
	}
}

// FAIL rows lead, ordered by severity and then benchmark number, so the top of
// the table is the top of the to-do list.
func TestOverviewOrdersRowsBySeverityThenID(t *testing.T) {
	rep := reportWithRepeatedFinding(t, 1)
	rep.Findings = append(rep.Findings,
		engine.Finding{
			CheckID: "CIS-1.1.8", CISID: "1.1.8", Severity: "LOW", Status: engine.StatusFail,
			Title: "Ensure stale branches are removed", Resource: "PRJ/repo-00",
			ResourceType: engine.ResourceRepository, Details: "d", Automated: true,
		},
		engine.Finding{
			CheckID: "CIS-1.1.4", CISID: "1.1.4", Severity: "MEDIUM", Status: engine.StatusFail,
			Title: "Ensure approvals are dismissed", Resource: "PRJ/repo-00",
			ResourceType: engine.ResourceRepository, Details: "d", Automated: true,
		},
		engine.Finding{
			CheckID: "CIS-1.3.5", CISID: "1.3.5", Severity: "HIGH", Status: engine.StatusManual,
			Title: "Ensure MFA is enforced", Resource: engine.InstanceResourceName,
			ResourceType: engine.ResourceOrganization, Details: "ask the IdP",
		},
	)
	rep.Score = engine.Compute(rep.Findings)
	out := renderReport(t, rep, Options{Format: FormatTable})

	high := strings.Index(out, "CIS-1.1.15")  // HIGH FAIL
	medium := strings.Index(out, "CIS-1.1.4") // MEDIUM FAIL
	low := strings.Index(out, "CIS-1.1.8")    // LOW FAIL
	manual := strings.Index(out, "CIS-1.3.5") // HIGH MANUAL
	if high < 0 || medium < 0 || low < 0 || manual < 0 {
		t.Fatalf("a control is missing from the overview\n---\n%s", out)
	}
	if !(high < medium && medium < low) {
		t.Errorf("FAIL rows are not ordered by severity\n---\n%s", out)
	}
	if manual < low {
		t.Errorf("a MANUAL row appears before the FAIL rows\n---\n%s", out)
	}
}

// Thirteen controls the token could not read are one problem with one cause,
// so the overview says so once instead of thirteen times.
func TestOverviewCollapsesUnreadToOneSentence(t *testing.T) {
	ids := []string{"1.1.3", "1.1.15", "1.1.16"}
	rep := reportWithUnreadableResource(t, ids...)
	rep.Metadata.Warnings = []string{"branch permissions are not readable (401)"}
	out := renderReport(t, rep, Options{Format: FormatTable})

	if strings.Contains(out, statusUnread) {
		t.Errorf("unread findings should not appear as rows in the overview\n---\n%s", out)
	}
	if !containsText(out, "3 controls could not be read (Unread) on PRJ/locked; see Scan warnings below.") {
		t.Errorf("no unread summary sentence\n---\n%s", out)
	}
	// The control no API can answer is a different thing and keeps its row.
	if !containsText(out, "CIS-1.3.5") {
		t.Errorf("the manual control lost its row\n---\n%s", out)
	}
}

func TestOverviewShowPassedAddsPassRecords(t *testing.T) {
	out := render(t, Options{Format: FormatTable, ShowPassed: true})
	// A record carries the finding's details — what was verified — not the
	// control's title.
	if !containsText(out, "CIS-1.1.3 PASS: Pull requests require 2 approvals.") {
		t.Errorf("--show-passed should add PASS records\n---\n%s", out)
	}

	// Without it, passes stay out.
	out = render(t, Options{Format: FormatTable})
	if containsText(out, "Pull requests require 2 approvals.") {
		t.Errorf("a PASS record appeared without --show-passed\n---\n%s", out)
	}
}

func TestOverviewSaysSoWhenNothingNeedsAttention(t *testing.T) {
	rep := &engine.Report{
		Metadata: scm.Metadata{Tool: "azure-devops-bench", Platform: scm.PlatformAzureDevOps},
		Findings: []engine.Finding{{
			CheckID: "CIS-1.1.15", CISID: "1.1.15", Title: "t", Severity: "HIGH",
			Status: engine.StatusPass, Resource: "PRJ/app", ResourceType: engine.ResourceRepository,
			Details: "fine", Automated: true,
		}},
	}
	rep.Score = engine.Compute(rep.Findings)
	out := renderReport(t, rep, Options{Format: FormatTable})

	if !strings.Contains(out, "No failed or manual-review controls.") {
		t.Errorf("a clean overview should say it is clean\n---\n%s", out)
	}
}

func TestHintAppearsOnlyInOverview(t *testing.T) {
	if out := render(t, Options{Format: FormatTable}); !strings.Contains(out, "Details: rerun with --details") {
		t.Errorf("the overview should say how to get the details\n---\n%s", out)
	}
	if out := render(t, Options{Format: FormatTable, Details: true}); strings.Contains(out, "Details: rerun with --details") {
		t.Errorf("the details layout should not advertise itself\n---\n%s", out)
	}
}

func TestDetailsFilterByResource(t *testing.T) {
	rep := reportWithRepeatedFinding(t, 3) // PRJ/repo-00 .. PRJ/repo-02
	out := renderReport(t, rep, Options{Format: FormatTable, Details: true, DetailFilters: []string{"REPO-01"}})

	sections := out[strings.Index(out, "Total: "):]
	if strings.Contains(sections, "PRJ/repo-00") || strings.Contains(sections, "PRJ/repo-02") {
		t.Errorf("resources outside the filter got sections\n---\n%s", out)
	}
	if n := strings.Count(out, "Total: "); n != 1 {
		t.Errorf("drew %d sections, want 1\n---\n%s", n, out)
	}
}

func TestDetailsFilterByControl(t *testing.T) {
	rep := sampleReport()
	for _, value := range []string{"CIS-1.1.15", "cis-1.1.15", "1.1.15"} {
		out := renderReport(t, rep, Options{Format: FormatTable, Details: true, DetailFilters: []string{value}})
		if !containsText(out, "Anyone with write access can push directly to main.") {
			t.Errorf("--details=%s lost the control it names\n---\n%s", value, out)
		}
		if strings.Contains(out[strings.Index(out, "Total: "):], "CIS-1.3.5") {
			t.Errorf("--details=%s kept a control it does not name\n---\n%s", value, out)
		}
		// Remediations narrow with the filter.
		if strings.Contains(out, "Enforce MFA at the IdP") {
			t.Errorf("--details=%s kept a filtered control's remediation\n---\n%s", value, out)
		}
	}
}

func TestDetailsFilterKindsIntersect(t *testing.T) {
	rep := reportWithRepeatedFinding(t, 3)
	rep.Findings = append(rep.Findings, engine.Finding{
		CheckID: "CIS-1.1.8", CISID: "1.1.8", Severity: "LOW", Status: engine.StatusFail,
		Title: "Ensure stale branches are removed", Resource: "PRJ/repo-01",
		ResourceType: engine.ResourceRepository, Details: "stale branches exist",
		Remediation: "Delete the stale branches", Automated: true,
	})
	rep.Score = engine.Compute(rep.Findings)

	out := renderReport(t, rep, Options{Format: FormatTable, Details: true,
		DetailFilters: []string{"repo-01", "1.1.8"}})
	sections := out[strings.Index(out, "Total: "):]
	if !strings.Contains(sections, "CIS-1.1.8") {
		t.Errorf("the named control on the named resource is missing\n---\n%s", out)
	}
	if strings.Contains(sections, "CIS-1.1.15") {
		t.Errorf("a control outside the filter survived it\n---\n%s", out)
	}
	if n := strings.Count(out, "Total: "); n != 1 {
		t.Errorf("drew %d sections, want 1\n---\n%s", n, out)
	}
}

// A filter that matches nothing would render a report indistinguishable from a
// clean one, so it is an error — and an early one, before any output.
func TestDetailsFilterMatchingNothingErrors(t *testing.T) {
	var buf bytes.Buffer
	err := Write(&buf, sampleReport(), Options{Format: FormatTable, Details: true, DetailFilters: []string{"bogus"}})
	if err == nil {
		t.Fatal("a filter matching nothing should be an error")
	}
	if !strings.Contains(err.Error(), `"bogus"`) {
		t.Errorf("the error does not name the value: %v", err)
	}
	if buf.Len() != 0 {
		t.Errorf("output was written before the filter was rejected:\n%s", buf.String())
	}
}

// The Rules index closes the default layout: each failed or manual control
// once, with the vendor's doc page dim beside it. The fix already rode with
// each finding, so this is only where to read more.
func TestRulesIndexCarriesTheReferenceLink(t *testing.T) {
	out := render(t, Options{Format: FormatTable})

	at := strings.Index(out, "Rules")
	if at < 0 {
		t.Fatalf("no rules index\n---\n%s", out)
	}
	rules := out[at:strings.Index(out, "Details: rerun")]
	if !strings.Contains(rules, "https://example.invalid/cis") {
		t.Errorf("the reference link is missing\n---\n%s", rules)
	}
	if containsText(rules, "Add restriction") {
		t.Errorf("the full remediation paragraph leaked into the index\n---\n%s", rules)
	}
}

// Every control carries the generic CIS benchmark landing page; it identifies
// none of them, so it never earns a line.
func TestRemediationLinkSkipsTheGenericBenchmarkPage(t *testing.T) {
	for _, tc := range []struct {
		name string
		refs []string
		want string
	}{
		{"vendor page wins", []string{"https://www.cisecurity.org/benchmark/software-supply-chain-security", "https://confluence.atlassian.com/x"}, "https://confluence.atlassian.com/x"},
		{"only the landing page", []string{"https://www.cisecurity.org/benchmark/software-supply-chain-security"}, ""},
		{"no references", nil, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := referenceLine(tc.refs); got != tc.want {
				t.Errorf("referenceLine = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestRemediationFallsBackToFirstSentenceWithoutFixSummary(t *testing.T) {
	f := engine.Finding{Remediation: "Do the first thing. Then a second thing that is much longer."}
	if got, want := fixLine(f), "Do the first thing."; got != want {
		t.Errorf("fixLine = %q, want %q", got, want)
	}
	f = engine.Finding{Remediation: "One sentence without a follow-up"}
	if got := fixLine(f); got != f.Remediation {
		t.Errorf("fixLine = %q, want the whole remediation", got)
	}
	f = engine.Finding{FixSummary: "The summary.", Remediation: "The paragraph. More paragraph."}
	if got := fixLine(f); got != "The summary." {
		t.Errorf("fixLine = %q, want the FixSummary", got)
	}
}

// Warnings are bullets with a hanging indent, so where one ends and the next
// begins survives the wrapping.
func TestWarningsAreBulleted(t *testing.T) {
	t.Setenv("COLUMNS", "60")
	rep := sampleReport()
	rep.Metadata.Warnings = []string{
		"global user permissions are not readable (GET /api/1.0/admin/permissions/users: 401 nope); rules will report MANUAL",
	}
	out := renderReport(t, rep, Options{Format: FormatTable})

	warnings := out[strings.Index(out, "Scan warnings"):]
	if !strings.Contains(warnings, "  - global user permissions") {
		t.Errorf("no bulleted warning\n---\n%s", warnings)
	}
	continuation := false
	for _, l := range strings.Split(warnings, "\n") {
		if strings.HasPrefix(l, "    ") && strings.TrimSpace(l) != "" {
			continuation = true
		}
	}
	if !continuation {
		t.Errorf("a wrapped warning should continue at the bullet's text column\n---\n%s", warnings)
	}
	if strings.Contains(out, "\033[") {
		t.Error("colour was off but escapes were emitted")
	}
}

// The parenthesised cause is forensics; dimming it lets the conclusion read
// first without hiding anything.
func TestWarningCauseIsDimmed(t *testing.T) {
	rep := sampleReport()
	rep.Metadata.Warnings = []string{"permissions are not readable (GET /x: 403 nope); rules report MANUAL"}
	out := renderReport(t, rep, Options{Format: FormatTable, Color: true})

	if !strings.Contains(out, "\033[2m(GET /x: 403 nope)\033[0m") {
		t.Errorf("the parenthesised cause is not dimmed\n---\n%q", out)
	}
	if !strings.Contains(out, "permissions are not readable ") {
		t.Errorf("the conclusion should stay undimmed\n---\n%q", out)
	}
}

// A cause long enough to wrap keeps its dimming on every line it crosses.
func TestWarningDimSpanCarriesAcrossWrappedLines(t *testing.T) {
	t.Setenv("COLUMNS", "60")
	rep := sampleReport()
	rep.Metadata.Warnings = []string{
		"project permissions are not readable (GET /api/1.0/projects/VERYLONGKEY/permissions/users: 401 You are not permitted to access this resource) so nothing follows",
	}
	out := renderReport(t, rep, Options{Format: FormatTable, Color: true})

	inSpan := false
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, "(GET") {
			inSpan = true
		}
		if !inSpan {
			continue
		}
		if !strings.Contains(l, "\033[2m") {
			t.Errorf("a line inside the open paren span is not dimmed: %q", l)
		}
		if strings.Contains(l, ")") {
			break
		}
	}
	if !inSpan {
		t.Fatalf("the warning did not render\n---\n%s", out)
	}
}

// Options.Width is the caller's statement of how wide the destination is; it
// wins over the environment the tests pin.
func TestOptionsWidthOverridesEnvironment(t *testing.T) {
	out := render(t, Options{Format: FormatTable, Width: 60})
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, "https://") {
			continue // links are unbreakable tokens, printed whole by policy
		}
		if n := utf8.RuneCountInString(stripANSI(l)); n > 60 {
			t.Errorf("line is %d columns despite Width 60: %q", n, l)
		}
	}
}

// The SCORE line counts findings; the Findings table has one row per control;
// the process exits saying "N controls failed". This is the line that lets a
// reader reconcile them, worded exactly as the exit line words it.
func TestSummaryBridgesControlsAndFindings(t *testing.T) {
	out := renderReport(t, reportWithRepeatedFinding(t, 4), Options{Format: FormatTable})
	if !strings.Contains(out, "1 control failed across 4 findings") {
		t.Errorf("no control/finding bridge line\n---\n%s", out)
	}

	// One control failing once: "across 1 finding" would be noise.
	single := render(t, Options{Format: FormatTable})
	if !strings.Contains(single, "1 control failed") || strings.Contains(single, "across 1 finding") {
		t.Errorf("the bridge line should skip the redundant across-clause\n---\n%s", single)
	}

	// Nothing failed: no line.
	clean := reportWithRepeatedFinding(t, 1)
	clean.Findings[0].Status = engine.StatusPass
	clean.Score = engine.Compute(clean.Findings)
	if out := renderReport(t, clean, Options{Format: FormatTable}); strings.Contains(out, "control") && strings.Contains(out, "failed across") {
		t.Errorf("a clean report printed a failure bridge\n---\n%s", out)
	}
}

func TestCoverageLineCountsFindings(t *testing.T) {
	out := render(t, Options{Format: FormatTable})
	if !strings.Contains(out, "scored 2 of 3 findings") {
		t.Errorf("the coverage line should count findings, not controls\n---\n%s", out)
	}
}

// The scan's own blind spot is a finding about the token, and it gets a fix
// like any other: without it the report's biggest caveat is the one problem
// it never says how to solve.
func TestUnreadableWarningsCarryAFix(t *testing.T) {
	rep := sampleReport()
	rep.Metadata.Warnings = []string{
		"global user permissions are not readable (GET /x: 401 nope); rules will report MANUAL",
	}
	out := renderReport(t, rep, Options{Format: FormatTable})
	if !containsText(out, "fix: rerun with a token holding the scopes the warnings name") {
		t.Errorf("unreadable warnings got no fix line\n---\n%s", out)
	}

	// A warning that is not about access gets no access advice.
	rep.Metadata.Warnings = []string{"the scan covered 0 repositories"}
	out = renderReport(t, rep, Options{Format: FormatTable})
	if containsText(out, "scopes the warnings name") {
		t.Errorf("a non-access warning was answered with token advice\n---\n%s", out)
	}
}

// Fixes and judgements are different asks. The details layout keeps its two
// sections; the default keeps FAIL records ahead of the aggregated MANUAL
// lines for the same reason.
func TestRemediationsSplitFixesFromManualReview(t *testing.T) {
	out := render(t, Options{Format: FormatTable, Details: true})
	fixes := strings.Index(out, "Remediations (1)")
	review := strings.Index(out, "Manual review (1)")
	if fixes < 0 || review < 0 {
		t.Fatalf("expected both sections\n---\n%s", out)
	}
	if fixes > review {
		t.Errorf("fixes should come before manual review\n---\n%s", out)
	}
	between := out[fixes:review]
	if !strings.Contains(between, "CIS-1.1.15") || strings.Contains(between, "CIS-1.3.5") {
		t.Errorf("controls landed in the wrong sections\n---\n%s", out)
	}

	deflt := render(t, Options{Format: FormatTable})
	fail := strings.Index(deflt, "CIS-1.1.15 HIGH:")
	manual := strings.Index(deflt, "CIS-1.3.5 MANUAL")
	if fail < 0 || manual < 0 {
		t.Fatalf("expected a FAIL record and a MANUAL group\n---\n%s", deflt)
	}
	if fail > manual {
		t.Errorf("FAIL records should come before the MANUAL groups\n---\n%s", deflt)
	}
}

// A control failing on every repository, whose remediation names a
// project-level variant, says so in one line: it is the single move that
// fixes the whole row, and slimming the paragraphs had cost exactly this.
func TestFullSweepPointsAtTheProjectLevelSetting(t *testing.T) {
	rep := reportWithRepeatedFinding(t, 4)
	for i := range rep.Findings {
		rep.Findings[i].Remediation = "Enable the check at Project settings -> Repositories -> <repository>. Set the same at Project settings -> Repositories -> All Repositories to cover the project."
	}
	rep.Score = engine.Compute(rep.Findings)
	out := flattened(renderReport(t, rep, Options{Format: FormatTable}))
	if !strings.Contains(out, "failing on all 4 repositories — setting it once at Project settings -> Repositories -> All Repositories covers them together.") {
		t.Errorf("a full sweep with a project-level variant got no pointer\n---\n%s", out)
	}

	// A partial failure keeps the plain line: the project-wide move would
	// also touch repositories that pass.
	rep.Findings[3].Status = engine.StatusPass
	rep.Score = engine.Compute(rep.Findings)
	if out := flattened(renderReport(t, rep, Options{Format: FormatTable})); strings.Contains(out, "setting it once at") {
		t.Errorf("a partial failure was given the full-sweep advice\n---\n%s", out)
	}

	// A remediation with no project-level variant gets no invented one.
	rep = reportWithRepeatedFinding(t, 4) // "Repository settings -> Branch permissions"
	if out := flattened(renderReport(t, rep, Options{Format: FormatTable})); strings.Contains(out, "setting it once at") {
		t.Errorf("advice was invented for a control with no project-level variant\n---\n%s", out)
	}
}

// flattened collapses all whitespace to single spaces, so a phrase can be
// found no matter where the renderer wrapped it.
func flattened(s string) string { return strings.Join(strings.Fields(stripANSI(s)), " ") }

func acceptedReport() *engine.Report {
	rep := sampleReport()
	rep.Findings[0].Waiver = &engine.Waiver{Reason: "release tooling", Owner: "platform", Expires: "2027-03-31"}
	rep.ExceptionWarnings = []string{"the exception for CIS-1.1.13 on Fabrikam/old accepts nothing this run — remove it"}
	return rep
}

// An accepted finding carries SARIF's own suppression, which code scanning
// shows as dismissed with the justification, rather than as an open alert.
func TestSARIFCarriesAcceptedFindingsAsSuppressed(t *testing.T) {
	out := renderReport(t, acceptedReport(), Options{Format: FormatSARIF})
	var log struct {
		Runs []struct {
			Results []struct {
				RuleID       string `json:"ruleId"`
				Suppressions []struct {
					Kind          string `json:"kind"`
					Status        string `json:"status"`
					Justification string `json:"justification"`
				} `json:"suppressions"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal([]byte(out), &log); err != nil {
		t.Fatal(err)
	}
	for _, r := range log.Runs[0].Results {
		if r.RuleID != "CIS-1.1.15" {
			if len(r.Suppressions) != 0 {
				t.Errorf("%s is suppressed without an exception", r.RuleID)
			}
			continue
		}
		s := r.Suppressions
		if len(s) != 1 || s[0].Kind != "external" || s[0].Status != "accepted" || !strings.Contains(s[0].Justification, "accepted until 2027-03-31: release tooling (platform)") {
			t.Errorf("suppressions = %+v", s)
		}
	}
}

// Accepted findings move out of the failure list into their own section, and
// the summary reconciles the FAIL count with a run that does not fail on them.
func TestTableListsAcceptedFindingsSeparately(t *testing.T) {
	out := flattened(renderReport(t, acceptedReport(), Options{Format: FormatTable}))
	for _, want := range []string{
		"Accepted by exceptions (1)",
		"PRJ/app CIS-1.1.15 FAIL: accepted until 2027-03-31: release tooling (platform)",
		"1 failed finding accepted by exceptions, counted here and in the score, not failing the run",
		"Exceptions - the exception for CIS-1.1.13",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("report does not say %q\n%s", want, out)
		}
	}
	if strings.Contains(out, "CIS-1.1.15 HIGH:") {
		t.Error("an accepted finding is still listed as a failure")
	}
	details := renderReport(t, acceptedReport(), Options{Format: FormatTable, Details: true})
	if !containsText(details, "accepted until 2027-03-31: release tooling (platform)") || !strings.Contains(details, "Exceptions") {
		t.Errorf("details view lacks the accepted note\n%s", details)
	}
}

type junitDoc struct {
	XMLName  xml.Name `xml:"testsuites"`
	Name     string   `xml:"name,attr"`
	Tests    int      `xml:"tests,attr"`
	Failures int      `xml:"failures,attr"`
	Skipped  int      `xml:"skipped,attr"`
	Props    []struct {
		Name  string `xml:"name,attr"`
		Value string `xml:"value,attr"`
	} `xml:"properties>property"`
	Suites []struct {
		Name     string `xml:"name,attr"`
		Tests    int    `xml:"tests,attr"`
		Failures int    `xml:"failures,attr"`
		Skipped  int    `xml:"skipped,attr"`
		Cases    []struct {
			Name      string `xml:"name,attr"`
			ClassName string `xml:"classname,attr"`
			Failure   *struct {
				Message string `xml:"message,attr"`
				Type    string `xml:"type,attr"`
				Text    string `xml:",chardata"`
			} `xml:"failure"`
			Skipped *struct {
				Message string `xml:"message,attr"`
			} `xml:"skipped"`
		} `xml:"testcase"`
	} `xml:"testsuite"`
}

func parseJUnit(t *testing.T, out string) junitDoc {
	t.Helper()
	var doc junitDoc
	if err := xml.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("JUnit output does not parse: %v\n%s", err, out)
	}
	return doc
}

// One suite per control, one case per resource; FAIL is a failure, the rest
// are skipped with the reason, and the totals add up to every finding.
func TestJUnitShape(t *testing.T) {
	out := render(t, Options{Format: FormatJUnit, ToolVersion: "1.2.3"})
	if !strings.HasPrefix(out, xml.Header) {
		t.Error("no XML header")
	}
	doc := parseJUnit(t, out)
	if doc.Name != "azure-devops-bench" || doc.Tests != 3 || doc.Failures != 1 || doc.Skipped != 1 {
		t.Errorf("totals = %+v", doc)
	}
	props := map[string]string{}
	for _, p := range doc.Props {
		props[p.Name] = p.Value
	}
	if props["score"] == "" || props["baseUrl"] != "https://dev.azure.com/fabrikam" || props["toolVersion"] != "1.2.3" {
		t.Errorf("properties = %v", props)
	}
	// Benchmark order: 1.1.3 before 1.1.15 before 1.3.5.
	var names []string
	for _, s := range doc.Suites {
		names = append(names, s.Name)
	}
	if len(names) != 3 || !strings.HasPrefix(names[0], "CIS-1.1.3: ") || !strings.HasPrefix(names[1], "CIS-1.1.15: ") {
		t.Errorf("suites = %v", names)
	}
	for _, s := range doc.Suites {
		for _, c := range s.Cases {
			switch c.ClassName {
			case "CIS-1.1.15":
				if c.Failure == nil || c.Failure.Type != "HIGH" || !strings.Contains(c.Failure.Text, "Fix: ") || !strings.Contains(c.Failure.Text, "· no restriction covers main") {
					t.Errorf("failure = %+v", c.Failure)
				}
			case "CIS-1.3.5":
				if c.Skipped == nil || !strings.HasPrefix(c.Skipped.Message, "MANUAL: ") {
					t.Errorf("manual = %+v", c.Skipped)
				}
			case "CIS-1.1.3":
				if c.Failure != nil || c.Skipped != nil {
					t.Error("a PASS is a bare test case")
				}
			}
		}
	}
}

func TestJUnitAcceptedAndNotApplicable(t *testing.T) {
	rep := acceptedReport()
	rep.Findings = append(rep.Findings, engine.Finding{
		CheckID: "CIS-1.3.9", CISID: "1.3.9", Title: "Verified", Severity: "LOW", Status: engine.StatusNA,
		Resource: engine.InstanceResourceName, ResourceType: engine.ResourceOrganization, Details: "No badge exists.",
	})
	doc := parseJUnit(t, renderReport(t, rep, Options{Format: FormatJUnit}))
	if doc.Failures != 0 || doc.Skipped != 3 {
		t.Errorf("failures=%d skipped=%d", doc.Failures, doc.Skipped)
	}
	for _, s := range doc.Suites {
		for _, c := range s.Cases {
			if c.ClassName == "CIS-1.1.15" && (c.Skipped == nil || !strings.Contains(c.Skipped.Message, "FAIL, accepted until 2027-03-31")) {
				t.Errorf("accepted = %+v", c.Skipped)
			}
			if c.ClassName == "CIS-1.3.9" && (c.Skipped == nil || !strings.HasPrefix(c.Skipped.Message, "not applicable: ")) {
				t.Errorf("na = %+v", c.Skipped)
			}
		}
	}
}

// A scan that missed a project, or a policy that failed, cannot render as a
// clean test run: the repositories it missed have no case to fail.
func TestJUnitIncompleteScanFails(t *testing.T) {
	rep := sampleReport()
	rep.Metadata.Unlisted = []string{"Fabrikam-Fiber"}
	rep.Errors = []string{"CIS-1.1.3 on PRJ/app: policy evaluation failed"}
	doc := parseJUnit(t, renderReport(t, rep, Options{Format: FormatJUnit}))
	last := doc.Suites[len(doc.Suites)-1]
	if last.Name != "scan" || last.Failures != 2 || doc.Failures != 3 {
		t.Errorf("scan suite = %+v, total failures %d", last, doc.Failures)
	}
}
