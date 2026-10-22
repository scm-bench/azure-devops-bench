package diff

import (
	"bytes"
	"strings"
	"testing"

	"github.com/scm-bench/azure-devops-bench/internal/engine"
)

func TestLessDepartedPutsTheWorstFirstThenByName(t *testing.T) {
	high := Change{Resource: "z", Severity: "HIGH"}
	low := Change{Resource: "a", Severity: "LOW"}
	if !lessDeparted(high, low) || lessDeparted(low, high) {
		t.Error("a resource that carried a HIGH failure sorts before one that carried a LOW one")
	}
	a, b := Change{Resource: "a", Severity: "HIGH"}, Change{Resource: "b", Severity: "HIGH"}
	if !lessDeparted(a, b) || lessDeparted(b, a) {
		t.Error("equal severity sorts by name")
	}
}

func TestLessChangeOrdersBySeverityBenchmarkThenResource(t *testing.T) {
	cases := []struct {
		name string
		a, b Change
	}{
		{"severity", Change{Severity: "HIGH", CISID: "1.9"}, Change{Severity: "LOW", CISID: "1.1"}},
		{"benchmark", Change{Severity: "HIGH", CISID: "1.1.9"}, Change{Severity: "HIGH", CISID: "1.1.11"}},
		{"resource", Change{Severity: "HIGH", CISID: "1.1", Resource: "a"}, Change{Severity: "HIGH", CISID: "1.1", Resource: "b"}},
	}
	for _, tc := range cases {
		if !lessChange(tc.a, tc.b) || lessChange(tc.b, tc.a) {
			t.Errorf("%s: want a strictly before b", tc.name)
		}
	}
}

// A deleted repository that was passing everything is still worth a line,
// and the line says it was clean.
func TestADepartedResourceThatWasPassing(t *testing.T) {
	result := Compare(reportOf(
		finding("CIS-1.1.3", "PRJ/clean", engine.StatusPass, "HIGH"),
		finding("CIS-1.1.4", "PRJ/clean", engine.StatusPass, "LOW"),
	), reportOf())
	if len(result.Departed) != 1 || !strings.Contains(result.Departed[0].Details, "none of its 2 controls were failing") {
		t.Errorf("departed = %+v", result.Departed)
	}
}

// The fix for a control that regressed on several repositories is printed
// once, not once per repository.
func TestEachRegressedControlsFixIsPrintedOnce(t *testing.T) {
	before := reportOf(
		finding("CIS-1.1.3", "PRJ/a", engine.StatusPass, "HIGH"),
		finding("CIS-1.1.3", "PRJ/b", engine.StatusPass, "HIGH"),
		finding("CIS-1.1.4", "PRJ/a", engine.StatusPass, "LOW"),
	)
	after := reportOf(
		finding("CIS-1.1.3", "PRJ/a", engine.StatusFail, "HIGH"),
		finding("CIS-1.1.3", "PRJ/b", engine.StatusFail, "HIGH"),
		finding("CIS-1.1.4", "PRJ/a", engine.StatusFail, "LOW"),
	)
	var buf bytes.Buffer
	if err := Write(&buf, Compare(before, after), Options{Width: 100}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	fixes := out[strings.Index(out, "How to fix the regressions"):]
	if n := strings.Count(fixes, "fix CIS-1.1.3"); n != 1 {
		t.Errorf("CIS-1.1.3's fix printed %d times, want once:\n%s", n, fixes)
	}
	if !strings.Contains(fixes, "fix CIS-1.1.4") {
		t.Errorf("CIS-1.1.4's fix is missing:\n%s", fixes)
	}
}

func TestDepartedResourcesAreListedWorstFirst(t *testing.T) {
	result := Compare(reportOf(
		finding("CIS-1.1.4", "PRJ/a-low", engine.StatusFail, "LOW"),
		finding("CIS-1.1.3", "PRJ/z-high", engine.StatusFail, "HIGH"),
	), reportOf())
	if len(result.Departed) != 2 || result.Departed[0].Resource != "PRJ/z-high" {
		t.Errorf("departed = %+v, want PRJ/z-high first", result.Departed)
	}
}
