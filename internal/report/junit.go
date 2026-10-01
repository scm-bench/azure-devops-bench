package report

import (
	"encoding/xml"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/scm-bench/azure-devops-bench/internal/checks"
	"github.com/scm-bench/azure-devops-bench/internal/engine"
)

// JUnit XML, for the CI systems that draw test results natively — Azure
// Pipelines' PublishTestResults, Jenkins' JUnit publisher, GitLab's test
// report. None of them reads SARIF without an extension, and all of them read
// this; for an organization audited from Azure Pipelines it is the format that
// puts the result in front of people without a marketplace task.
//
// One test suite per control and one test case per resource it was evaluated
// against, so a CI's test view groups the way the report does: by control,
// with the repositories underneath. An unaccepted FAIL is a failure; MANUAL,
// NA and an accepted failure are skipped, each with the reason in the message,
// so the totals add up to every finding and nothing is silently dropped.

type junitTestSuites struct {
	XMLName    xml.Name         `xml:"testsuites"`
	Name       string           `xml:"name,attr"`
	Tests      int              `xml:"tests,attr"`
	Failures   int              `xml:"failures,attr"`
	Errors     int              `xml:"errors,attr"`
	Skipped    int              `xml:"skipped,attr"`
	Properties *junitProperties `xml:"properties,omitempty"`
	Suites     []junitTestSuite `xml:"testsuite"`
}

type junitProperties struct {
	Property []junitProperty `xml:"property"`
}

type junitProperty struct {
	Name  string `xml:"name,attr"`
	Value string `xml:"value,attr"`
}

type junitTestSuite struct {
	Name     string          `xml:"name,attr"`
	Tests    int             `xml:"tests,attr"`
	Failures int             `xml:"failures,attr"`
	Errors   int             `xml:"errors,attr"`
	Skipped  int             `xml:"skipped,attr"`
	Cases    []junitTestCase `xml:"testcase"`
}

type junitTestCase struct {
	Name      string        `xml:"name,attr"`
	ClassName string        `xml:"classname,attr"`
	Failure   *junitFailure `xml:"failure,omitempty"`
	Skipped   *junitSkipped `xml:"skipped,omitempty"`
}

type junitFailure struct {
	Message string `xml:"message,attr"`
	Type    string `xml:"type,attr"`
	Text    string `xml:",chardata"`
}

type junitSkipped struct {
	Message string `xml:"message,attr"`
}

func writeJUnit(w io.Writer, rep *engine.Report, opts Options) error {
	byControl := map[string]*junitTestSuite{}
	var order []string
	cisIDs := map[string]string{}
	root := junitTestSuites{Name: benchName}

	for _, f := range rep.Findings {
		suite, ok := byControl[f.CheckID]
		if !ok {
			suite = &junitTestSuite{Name: f.CheckID + ": " + f.Title}
			byControl[f.CheckID] = suite
			order = append(order, f.CheckID)
			cisIDs[f.CheckID] = f.CISID
		}
		tc := junitTestCase{Name: f.Resource, ClassName: f.CheckID}
		switch {
		case f.Status == engine.StatusFail && f.Waiver == nil:
			tc.Failure = &junitFailure{
				Message: f.Details,
				Type:    strings.ToUpper(f.Severity),
				Text:    failureText(f),
			}
			suite.Failures++
		case f.Waiver != nil:
			tc.Skipped = &junitSkipped{Message: fmt.Sprintf("%s, %s", f.Status, acceptedNote(f.Waiver))}
			suite.Skipped++
		case f.Status == engine.StatusManual:
			tc.Skipped = &junitSkipped{Message: "MANUAL: " + f.Details}
			suite.Skipped++
		case f.Status == engine.StatusNA:
			tc.Skipped = &junitSkipped{Message: "not applicable: " + f.Details}
			suite.Skipped++
		}
		suite.Tests++
		suite.Cases = append(suite.Cases, tc)
	}

	// Benchmark order, so 1.1.9 is listed before 1.1.11 in the CI's view.
	sort.Slice(order, func(i, j int) bool { return checks.LessCISID(cisIDs[order[i]], cisIDs[order[j]]) })
	for _, id := range order {
		suite := byControl[id]
		root.Suites = append(root.Suites, *suite)
		root.Tests += suite.Tests
		root.Failures += suite.Failures
		root.Skipped += suite.Skipped
	}
	root.Properties = &junitProperties{Property: []junitProperty{
		{Name: "score", Value: fmt.Sprintf("%d", rep.Score.Value)},
		{Name: "baseUrl", Value: rep.Metadata.BaseURL},
		{Name: "platform", Value: rep.Metadata.Platform},
		{Name: "toolVersion", Value: opts.ToolVersion},
	}}
	// A scan that missed projects must not render as a clean test run: the
	// missing repositories have no test case to fail, so the run carries a
	// failure of its own.
	if len(rep.Metadata.Unlisted) > 0 || len(rep.Errors) > 0 {
		suite := junitTestSuite{Name: "scan"}
		for _, project := range rep.Metadata.Unlisted {
			suite.Cases = append(suite.Cases, junitTestCase{
				Name: project, ClassName: "scan.coverage",
				Failure: &junitFailure{Message: "the repositories of this project could not be listed", Type: "ERROR"},
			})
		}
		for _, e := range rep.Errors {
			suite.Cases = append(suite.Cases, junitTestCase{
				Name: "policy evaluation", ClassName: "scan.policy",
				Failure: &junitFailure{Message: e, Type: "ERROR"},
			})
		}
		suite.Tests = len(suite.Cases)
		suite.Failures = len(suite.Cases)
		root.Suites = append(root.Suites, suite)
		root.Tests += suite.Tests
		root.Failures += suite.Failures
	}

	if _, err := io.WriteString(w, xml.Header); err != nil {
		return err
	}
	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	if err := enc.Encode(root); err != nil {
		return err
	}
	_, err := io.WriteString(w, "\n")
	return err
}

// failureText is what a CI shows when the failure is opened: the finding, the
// values behind it, and how to fix it.
func failureText(f engine.Finding) string {
	var b strings.Builder
	b.WriteString(f.Details)
	for _, e := range f.Evidence {
		b.WriteString("\n  · " + e)
	}
	if f.Remediation != "" {
		b.WriteString("\n\nFix: " + f.Remediation)
	}
	return b.String()
}
