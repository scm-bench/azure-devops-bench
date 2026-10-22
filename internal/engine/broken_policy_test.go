package engine

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/open-policy-agent/opa/v1/ast"

	"github.com/scm-bench/azure-devops-bench/internal/checks"
	"github.com/scm-bench/azure-devops-bench/internal/config"
	"github.com/scm-bench/azure-devops-bench/internal/scm"
)

func fakeCheck(id, pkg, scope string) checks.Check {
	return checks.Check{Metadata: checks.Metadata{
		ID: id, CISID: "9." + strings.TrimPrefix(id, "T-"), Package: pkg, Scope: scope,
		Severity: checks.SeverityHigh, Platforms: []string{scm.PlatformAzureDevOps}, Automated: true,
		Title: id, Remediation: "fix " + id, FixSummary: "fix " + id,
	}}
}

func withBundle(t *testing.T, b *checks.Bundle, err error) {
	t.Helper()
	orig := loadBundle
	loadBundle = func() (*checks.Bundle, error) { return b, err }
	t.Cleanup(func() { loadBundle = orig })
}

// twoRepos is an organization with one project holding two repositories.
func twoRepos() *scm.Snapshot {
	return &scm.Snapshot{
		SchemaVersion: scm.SchemaVersion,
		Metadata:      scm.Metadata{Tool: "azure-devops-bench", Platform: scm.PlatformAzureDevOps, BaseURL: "https://dev.azure.com/fabrikam"},
		Projects: []scm.Project{{Key: "P", Name: "P", Repositories: []scm.Repository{
			{FullName: "P/a", Name: "a"},
			{FullName: "P/b", Name: "b"},
		}}},
	}
}

func TestNewReportsABundleThatFailsToLoad(t *testing.T) {
	withBundle(t, nil, errors.New("metadata.json: title is required"))
	_, err := New(context.Background(), config.Default(), scm.PlatformAzureDevOps)
	if err == nil || !strings.Contains(err.Error(), "load policy bundle") {
		t.Errorf("New() error = %v, want the load failure", err)
	}
}

func TestNewReportsAPolicyThatDoesNotCompile(t *testing.T) {
	withBundle(t, &checks.Bundle{
		Checks:  []checks.Check{fakeCheck("T-1", "scmbench.test.broken", checks.ScopeRepository)},
		Modules: []checks.Module{{Path: "broken.rego", Source: "package scmbench.test.broken\n\nresult := {"}},
	}, nil)
	_, err := New(context.Background(), config.Default(), scm.PlatformAzureDevOps)
	if err == nil || !strings.Contains(err.Error(), "compile policies") {
		t.Errorf("New() error = %v, want a compile error", err)
	}
}

func TestNewReportsAPackageThatCannotBeQueried(t *testing.T) {
	// A hyphen is not legal in a package path: the query parses as a
	// subtraction with an unbound variable, and preparing it fails.
	withBundle(t, &checks.Bundle{
		Checks: []checks.Check{fakeCheck("T-1", "scmbench.bad-pkg", checks.ScopeRepository)},
	}, nil)
	_, err := New(context.Background(), config.Default(), scm.PlatformAzureDevOps)
	if err == nil || !strings.Contains(err.Error(), "prepare T-1") {
		t.Errorf("New() error = %v, want a prepare error naming the control", err)
	}
}

// A policy that decides nothing, decides something that is not a verdict, or
// fails at runtime becomes a MANUAL finding with the reason, and the reason
// is listed in the report's errors so the run cannot pass as complete.
func TestBrokenPoliciesBecomeManualFindingsWithAReason(t *testing.T) {
	withBundle(t, &checks.Bundle{
		Checks: []checks.Check{
			fakeCheck("T-1", "scmbench.test.silent", checks.ScopeOrganization),
			fakeCheck("T-2", "scmbench.test.weird", checks.ScopeRepository),
			fakeCheck("T-3", "scmbench.test.crash", checks.ScopeRepository),
			fakeCheck("T-4", "scmbench.test.ok", checks.ScopeRepository),
		},
		Modules: []checks.Module{
			{Path: "silent.rego", Source: "package scmbench.test.silent\n\nresult := r if {\n\tr := {\"status\": \"PASS\", \"details\": \"x\"}\n\tinput.resource.nothing\n}\n"},
			{Path: "weird.rego", Source: "package scmbench.test.weird\n\nresult := {\"status\": \"MAYBE\", \"details\": \"hmm\"}\n"},
			// Two values for one complete rule is a runtime conflict error.
			{Path: "crash.rego", Source: "package scmbench.test.crash\n\nresult := {\"status\": \"PASS\", \"details\": \"a\"} if input.resource.name\nresult := {\"status\": \"FAIL\", \"details\": \"b\"} if input.resource.fullName\n"},
			{Path: "ok.rego", Source: "package scmbench.test.ok\n\nresult := {\"status\": \"PASS\", \"details\": \"fine\", \"evidence\": [\"a\", 1]}\n"},
		},
	}, nil)
	eng, err := New(context.Background(), config.Default(), scm.PlatformAzureDevOps)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := eng.Evaluate(context.Background(), twoRepos())
	if err != nil {
		t.Fatal(err)
	}
	byKey := map[string]Finding{}
	for _, f := range rep.Findings {
		byKey[f.CheckID+"@"+f.Resource] = f
	}
	for key, want := range map[string]string{
		"T-1@" + InstanceResourceName: "produced no result",
		"T-2@P/a":                     "malformed result",
		"T-3@P/b":                     "failed to run",
	} {
		f := byKey[key]
		if f.Status != StatusManual || !strings.Contains(f.Details, want) {
			t.Errorf("%s = %s %q, want MANUAL mentioning %q", key, f.Status, f.Details, want)
		}
	}
	if ok := byKey["T-4@P/a"]; ok.Status != StatusPass || strings.Join(ok.Evidence, ",") != "a,1" {
		t.Errorf("the working policy = %+v, want PASS with evidence a,1", ok)
	}
	// One for the organization, two per repository.
	if len(rep.Errors) != 5 {
		t.Errorf("report errors = %d, want 5: %q", len(rep.Errors), rep.Errors)
	}
}

func TestEvaluateStopsWhenCancelled(t *testing.T) {
	eng, err := New(context.Background(), config.Default(), scm.PlatformAzureDevOps)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := eng.Evaluate(ctx, twoRepos()); !errors.Is(err, context.Canceled) {
		t.Errorf("Evaluate() = %v, want context.Canceled", err)
	}
}

func TestEvaluateStopsWhenAnInputCannotBeEncoded(t *testing.T) {
	failOn := func(target string) func(any) (ast.Value, error) {
		return func(v any) (ast.Value, error) {
			name := ""
			switch v.(type) {
			case config.Config:
				name = "config"
			case scm.Metadata:
				name = "metadata"
			case scm.Organization:
				name = "organization"
			case scm.Project:
				name = "project"
			case scm.Repository:
				name = "repository"
			}
			if name == target {
				return nil, errors.New("cannot encode " + name)
			}
			return toAST(v)
		}
	}
	for _, target := range []string{"config", "metadata", "organization", "project", "repository"} {
		t.Run(target, func(t *testing.T) {
			eng, err := New(context.Background(), config.Default(), scm.PlatformAzureDevOps)
			if err != nil {
				t.Fatal(err)
			}
			eng.encode = failOn(target)
			rep, err := eng.Evaluate(context.Background(), twoRepos())
			if err == nil || !strings.Contains(err.Error(), "encode "+target) && !strings.Contains(err.Error(), "encode snapshot "+target) {
				t.Errorf("Evaluate() = %v, %v; want an encode error for the %s", rep, err, target)
			}
		})
	}
}

func TestDecodeResultRejectsWhatIsNotAVerdict(t *testing.T) {
	cases := []struct {
		name  string
		value any
		want  string
	}{
		{"not an object", []any{"PASS"}, "want an object"},
		{"unknown status", map[string]any{"status": "OK", "details": "d"}, "is not PASS"},
		{"blank details", map[string]any{"status": "PASS", "details": "  "}, "missing details"},
		{"evidence not a list", map[string]any{"status": "FAIL", "details": "d", "evidence": "one"}, "want an array"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := decodeResult(tc.value); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("decodeResult(%v) error = %v, want %q", tc.value, err, tc.want)
			}
		})
	}
}
