package engine

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/scm-bench/azure-devops-bench/internal/config"
	"github.com/scm-bench/azure-devops-bench/internal/scm"
)

var exceptionNow = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

func failing(check, resource, severity string) Finding {
	return Finding{CheckID: check, Resource: resource, Severity: severity, Status: StatusFail}
}

func TestExceptionsAcceptMatchingFindingsOnly(t *testing.T) {
	findings := []Finding{
		failing("CIS-1.1.13", "Fabrikam/legacy-billing", "LOW"),
		failing("CIS-1.1.13", "Fabrikam/payments", "LOW"),
		failing("CIS-1.1.15", "Fabrikam/legacy-billing", "HIGH"),
		{CheckID: "CIS-1.1.13", Resource: "Fabrikam/legacy-ui", Severity: "LOW", Status: StatusPass},
		{CheckID: "CIS-1.1.13", Resource: "Fabrikam/legacy-docs", Severity: "LOW", Status: StatusManual},
	}
	warnings := applyExceptions(findings, []config.Exception{{
		Control: "cis-1.1.13", Resources: []string{"fabrikam/LEGACY-*"},
		Reason: "release tooling", Owner: "platform", Expires: "2027-03-31",
	}}, exceptionNow)

	if len(warnings) != 0 {
		t.Errorf("warnings = %v, want none", warnings)
	}
	if w := findings[0].Waiver; w == nil || w.Reason != "release tooling" || w.Owner != "platform" || w.Expires != "2027-03-31" {
		t.Errorf("legacy-billing CIS-1.1.13 waiver = %+v, want the exception", w)
	}
	if findings[1].Waiver != nil {
		t.Error("Fabrikam/payments does not match the pattern and must not be accepted")
	}
	if findings[2].Waiver != nil {
		t.Error("another control on the same repository must not be accepted")
	}
	if findings[3].Waiver != nil {
		t.Error("a PASS has nothing to accept")
	}
	if findings[4].Waiver == nil {
		t.Error("a MANUAL finding a person reviewed can be accepted")
	}
}

// A lapsed exception does nothing, and says so: its findings fail the run
// again from the day after its expiry.
func TestLapsedExceptionsAreNotAppliedAndAreReported(t *testing.T) {
	findings := []Finding{failing("CIS-1.1.13", "Fabrikam/legacy", "LOW")}
	warnings := applyExceptions(findings, []config.Exception{{
		Control: "CIS-1.1.13", Resources: []string{"Fabrikam/legacy"}, Reason: "r", Expires: "2026-09-30",
	}}, exceptionNow)
	if findings[0].Waiver != nil {
		t.Error("a lapsed exception was applied")
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "lapsed on 2026-09-30") {
		t.Errorf("warnings = %v, want the lapse reported", warnings)
	}

	// The expiry day itself still counts.
	findings = []Finding{failing("CIS-1.1.13", "Fabrikam/legacy", "LOW")}
	applyExceptions(findings, []config.Exception{{
		Control: "CIS-1.1.13", Resources: []string{"Fabrikam/legacy"}, Reason: "r", Expires: "2026-10-01",
	}}, exceptionNow)
	if findings[0].Waiver == nil {
		t.Error("an exception expiring today must still apply today")
	}
}

// An exception that accepts nothing is a finding fixed, renamed or out of
// scope — or a typo. Either way the list is rotting, and it is said.
func TestExceptionsMatchingNothingAreReported(t *testing.T) {
	warnings := applyExceptions([]Finding{failing("CIS-1.1.13", "Fabrikam/a", "LOW")}, []config.Exception{{
		Control: "CIS-1.1.15", Resources: []string{"Fabrikam/a"}, Reason: "r", Expires: "2027-01-01",
	}}, exceptionNow)
	if len(warnings) != 1 || !strings.Contains(warnings[0], "accepts nothing") {
		t.Errorf("warnings = %v, want the stale exception reported", warnings)
	}
}

// "instance" names the organization-level resource.
func TestExceptionsReachOrganizationFindings(t *testing.T) {
	findings := []Finding{failing("CIS-1.3.3", InstanceResourceName, "HIGH")}
	applyExceptions(findings, []config.Exception{{
		Control: "CIS-1.3.3", Resources: []string{"instance"}, Reason: "merger", Expires: "2027-01-01",
	}}, exceptionNow)
	if findings[0].Waiver == nil {
		t.Error("the organization's finding was not accepted")
	}
}

// The score describes the organization, and accepting a finding does not
// change the organization; what changes is whether the run fails on it.
func TestAcceptedFailuresStayInTheScoreButDoNotFailTheRun(t *testing.T) {
	findings := []Finding{failing("CIS-1.1.15", "Fabrikam/a", "HIGH"), {CheckID: "CIS-1.1.3", Resource: "Fabrikam/a", Severity: "HIGH", Status: StatusPass}}
	before := Compute(findings)
	applyExceptions(findings, []config.Exception{{
		Control: "CIS-1.1.15", Resources: []string{"Fabrikam/*"}, Reason: "r", Expires: "2027-01-01",
	}}, exceptionNow)
	rep := &Report{Findings: findings, Score: Compute(findings)}

	if rep.Score.Value != before.Value || rep.Score.Failed != before.Failed || rep.Score.EarnedWeight != before.EarnedWeight {
		t.Errorf("score changed from %+v to %+v", before, rep.Score)
	}
	if rep.HasFailureAtOrAbove("high") {
		t.Error("an accepted HIGH failure still fails the run")
	}
	findings[0].Waiver = nil
	if !(&Report{Findings: findings}).HasFailureAtOrAbove("high") {
		t.Error("an unaccepted HIGH failure must fail the run")
	}
}

// The exceptions run inside Evaluate, after the score.
func TestEvaluateAppliesExceptions(t *testing.T) {
	cfg := config.Default()
	cfg.Exceptions = []config.Exception{{Control: "CIS-1.1.3", Resources: []string{"Fabrikam/*"}, Reason: "r", Expires: "2027-01-01"}}
	eng, err := New(context.Background(), cfg, scm.PlatformAzureDevOps)
	if err != nil {
		t.Fatal(err)
	}
	eng.now = func() time.Time { return exceptionNow }
	rep, err := eng.Evaluate(context.Background(), &scm.Snapshot{
		SchemaVersion: scm.SchemaVersion,
		Metadata:      scm.Metadata{Platform: scm.PlatformAzureDevOps},
		Projects: []scm.Project{{Key: "Fabrikam", Repositories: []scm.Repository{{
			FullName: "Fabrikam/app", DefaultBranch: "refs/heads/main",
			Available: map[string]bool{"pullRequestSettings": true},
		}}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range rep.Findings {
		if f.CheckID == "CIS-1.1.3" && (f.Status != StatusFail || f.Waiver == nil) {
			t.Errorf("CIS-1.1.3 = %s waiver=%v", f.Status, f.Waiver)
		}
	}
}
