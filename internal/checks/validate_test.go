package checks

import (
	"encoding/json"
	"errors"
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"
)

// valid returns metadata that passes, so each case below changes exactly one
// thing and the failure names the field that broke.
func valid() Metadata {
	return Metadata{
		ID:          "CIS-1.1.11",
		CISID:       "1.1.11",
		Package:     "scmbench.rules.cis_1_1_11",
		Scope:       ScopeRepository,
		Severity:    SeverityLow,
		Platforms:   []string{"azure-devops"},
		Automated:   true,
		Title:       "Ensure all open comments are resolved before merging",
		Remediation: "Project settings -> Repositories -> <repository> -> Policies: set \"Check for comment resolution\" to Required.",
		FixSummary:  "Require comment resolution at Project settings -> Repositories -> <repo> -> Policies.",
	}
}

// The engine dispatches on scope, and an unrecognised one matches no branch:
// validate is what stands between a typo and a control silently evaluated
// against nothing.
func TestValidateRejectsAScopeFromAnotherDomain(t *testing.T) {
	for _, scope := range []string{"controller", "job", "Repository", "repo", ""} {
		m := valid()
		m.Scope = scope
		err := Check{Metadata: m}.validate()
		if err == nil || !strings.Contains(err.Error(), "scope") {
			t.Errorf("scope %q: err = %v, want a scope error", scope, err)
		}
	}
}

func TestValidateAcceptsThisDomainsScopes(t *testing.T) {
	for _, scope := range []string{ScopeRepository, ScopeOrganization} {
		m := valid()
		m.Scope = scope
		if err := (Check{Metadata: m}).validate(); err != nil {
			t.Errorf("scope %q was rejected: %v", scope, err)
		}
	}
}

func TestValidateRequiresEveryFieldAReportPrints(t *testing.T) {
	tests := []struct {
		field  string
		mutate func(*Metadata)
	}{
		{"id", func(m *Metadata) { m.ID = "" }},
		{"package", func(m *Metadata) { m.Package = "" }},
		{"title", func(m *Metadata) { m.Title = "" }},
		{"remediation", func(m *Metadata) { m.Remediation = "" }},
		{"fixSummary", func(m *Metadata) { m.FixSummary = "" }},
		{"severity", func(m *Metadata) { m.Severity = "CRITICAL" }},
		{"platform", func(m *Metadata) { m.Platforms = nil }},
	}
	for _, tt := range tests {
		t.Run(tt.field, func(t *testing.T) {
			m := valid()
			tt.mutate(&m)
			err := Check{Metadata: m}.validate()
			if err == nil || !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(tt.field)) {
				t.Errorf("metadata missing %s: err = %v, want it named", tt.field, err)
			}
		})
	}
}

// Severity decides a control's weight, and Weight falls back to LOW for
// anything it does not recognise, so a misspelling must fail here instead.
func TestValidateAcceptsSeverityInAnyCase(t *testing.T) {
	for _, s := range []string{"HIGH", "high", "Medium", "low"} {
		m := valid()
		m.Severity = s
		if err := (Check{Metadata: m}).validate(); err != nil {
			t.Errorf("severity %q was rejected: %v", s, err)
		}
	}
}

func TestLessCISIDHandlesNonNumericComponents(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"1.x.9", "1.x.11", true}, // equal words, then numbers compared as numbers
		{"1.x.11", "1.x.9", false},
		{"1.a", "1.b", true}, // differing words compare as text
		{"1.b", "1.a", false},
		{"", "1", true}, // an empty component sorts as text
		{"2.1.6", "2.1.6a", true},
	}
	for _, tc := range cases {
		if got := LessCISID(tc.a, tc.b); got != tc.want {
			t.Errorf("LessCISID(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}

func metaJSON(t *testing.T, m Metadata) *fstest.MapFile {
	t.Helper()
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return &fstest.MapFile{Data: raw}
}

// failingFS lists every file of the wrapped FS but refuses to read the named
// ones, the way an unreadable file shows up in a directory listing.
type failingFS struct {
	fstest.MapFS
	fail map[string]bool
}

func (f failingFS) Open(name string) (fs.File, error) {
	if f.fail[name] {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrPermission}
	}
	return f.MapFS.Open(name)
}

func (f failingFS) ReadFile(name string) ([]byte, error) {
	if f.fail[name] {
		return nil, &fs.PathError{Op: "read", Path: name, Err: fs.ErrPermission}
	}
	return f.MapFS.ReadFile(name)
}

func TestLoadFromKeepsOnlyTheBundlesOwnFiles(t *testing.T) {
	fsys := fstest.MapFS{
		"policies/azuredevops/a/metadata.json":   metaJSON(t, valid()),
		"policies/azuredevops/a/check.rego":      {Data: []byte("package a")},
		"policies/azuredevops/a/check_test.rego": {Data: []byte("package a_test")},
		"policies/azuredevops/a/fixture.json":    {Data: []byte("{}")},
		"policies/azuredevops/a/notes.txt":       {Data: []byte("ignored")},
	}
	b, err := loadFrom(fsys)
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Checks) != 1 || len(b.Modules) != 1 || b.Modules[0].Path != "policies/azuredevops/a/check.rego" {
		t.Errorf("checks = %d, modules = %+v; want one control and its non-test module", len(b.Checks), b.Modules)
	}
}

func TestLoadFromRejectsABrokenBundle(t *testing.T) {
	invalid := valid()
	invalid.Title = ""
	cases := []struct {
		name string
		fsys fs.FS
		want string
	}{
		{"no policies directory", fstest.MapFS{}, "policies"},
		{"unknown field", fstest.MapFS{
			"policies/azuredevops/a/metadata.json": {Data: []byte(`{"id":"X","surprise":1}`)},
		}, "parse policies/azuredevops/a/metadata.json"},
		{"invalid control", fstest.MapFS{
			"policies/azuredevops/a/metadata.json": metaJSON(t, invalid),
		}, "title is required"},
		{"duplicate id", fstest.MapFS{
			"policies/azuredevops/a/metadata.json": metaJSON(t, valid()),
			"policies/azuredevops/b/metadata.json": metaJSON(t, valid()),
		}, "duplicate check ID CIS-1.1.11"},
		{"unreadable module", failingFS{
			MapFS: fstest.MapFS{"policies/azuredevops/a/check.rego": {Data: []byte("package a")}},
			fail:  map[string]bool{"policies/azuredevops/a/check.rego": true},
		}, "read policies/azuredevops/a/check.rego"},
		{"unreadable metadata", failingFS{
			MapFS: fstest.MapFS{"policies/azuredevops/a/metadata.json": metaJSON(t, valid())},
			fail:  map[string]bool{"policies/azuredevops/a/metadata.json": true},
		}, "read policies/azuredevops/a/metadata.json"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := loadFrom(tc.fsys)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want it to mention %q", err, tc.want)
			}
		})
	}
	_, err := loadFrom(failingFS{
		MapFS: fstest.MapFS{"policies/azuredevops/a/check.rego": {Data: []byte("package a")}},
		fail:  map[string]bool{"policies/azuredevops/a/check.rego": true},
	})
	if !errors.Is(err, fs.ErrPermission) {
		t.Errorf("err = %v, want it to wrap fs.ErrPermission", err)
	}
}
