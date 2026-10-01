// Package engine compiles the embedded Rego policies once and evaluates them
// against a snapshot. It owns no policy logic of its own: every verdict comes
// from a rule, and the engine only decides which resources a rule sees.
package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"

	"github.com/scm-bench/azure-devops-bench/internal/checks"
	"github.com/scm-bench/azure-devops-bench/internal/config"
	"github.com/scm-bench/azure-devops-bench/internal/scm"
)

// Status is the outcome of one control against one resource.
type Status string

const (
	// StatusPass means the control is satisfied.
	StatusPass Status = "PASS"
	// StatusFail means the control is not satisfied.
	StatusFail Status = "FAIL"
	// StatusManual means the instance did not expose enough data to decide.
	// It never counts towards the score, because guessing would be worse than
	// admitting the gap.
	StatusManual Status = "MANUAL"
	// StatusNA means the control does not apply to this resource.
	StatusNA Status = "NA"
)

// Resource kinds a finding can be attached to.
const (
	ResourceRepository   = "repository"
	ResourceOrganization = "organization"
)

// InstanceResourceName labels findings that apply to the instance as a whole.
const InstanceResourceName = "instance"

// Finding is one control evaluated against one resource.
type Finding struct {
	CheckID      string `json:"checkId"`
	CISID        string `json:"cisId"`
	Title        string `json:"title"`
	Severity     string `json:"severity"`
	Status       Status `json:"status"`
	Resource     string `json:"resource"`
	ResourceType string `json:"resourceType"`
	// Description is why the control exists, carried from its metadata. It
	// explains the finding to someone who is not already convinced the control
	// matters — Details says what this resource does, Remediation says what to
	// change, and neither answers "why should I care".
	Description string   `json:"description,omitempty"`
	Details     string   `json:"details"`
	Evidence    []string `json:"evidence,omitempty"`
	Remediation string   `json:"remediation"`
	// FixSummary is Remediation's first move in one line. The table report
	// prints it beside the verdict and keeps the full paragraph for its own
	// section; consumers that want everything should read Remediation.
	FixSummary string   `json:"fixSummary,omitempty"`
	References []string `json:"references,omitempty"`
	// Automated is false for controls that are documented as unanswerable by
	// the API and always report MANUAL.
	Automated bool `json:"automated"`
	// Waiver is set when a configured exception accepts this finding. The
	// status is unchanged — an accepted FAIL is still a FAIL, and still counts
	// in the score — but it no longer fails the run.
	Waiver *Waiver `json:"waiver,omitempty"`
}

// Waiver is the exception that accepted a finding, as the report shows it.
type Waiver struct {
	Reason  string `json:"reason"`
	Owner   string `json:"owner,omitempty"`
	Expires string `json:"expires"`
}

// Report is the full result of an evaluation.
type Report struct {
	Metadata scm.Metadata `json:"metadata"`
	Findings []Finding    `json:"findings"`
	Score    Score        `json:"score"`
	// Repositories is how many repositories the repository-scope controls
	// were evaluated against, counted after skipArchivedRepositories rather
	// than read off the snapshot. Zero means they audited nothing — a
	// --project nobody can read, a token that sees nothing, an organization
	// whose every repository is disabled — and the machine-read formats say
	// so themselves: a report holding only organization-level findings, which
	// can all pass, otherwise renders as a clean run to a CI view that never
	// sees the exit code.
	Repositories int `json:"repositories"`
	// Errors records policies that failed to evaluate. They surface as MANUAL
	// findings too, so a broken rule is loud but not fatal.
	Errors []string `json:"errors,omitempty"`
	// ExceptionWarnings names configured exceptions that did nothing this
	// run: lapsed ones, and ones no finding matched any more. Both are how an
	// exceptions list rots, so both are said out loud.
	ExceptionWarnings []string `json:"exceptionWarnings,omitempty"`
}

// Engine holds the compiled policy bundle.
type Engine struct {
	cfg      config.Config
	bundle   *checks.Bundle
	prepared map[string]rego.PreparedEvalQuery
	selected []checks.Check
	// now decides which exceptions have lapsed; a field so tests can fix it.
	now func() time.Time
}

// New compiles the embedded policies for the given platform and configuration.
func New(ctx context.Context, cfg config.Config, platform string) (*Engine, error) {
	bundle, err := checks.Load()
	if err != nil {
		return nil, fmt.Errorf("load policy bundle: %w", err)
	}

	// A check ID that names nothing is almost always a typo, and the silent
	// reading of it is the dangerous one: an `exclude` that matches no control
	// leaves that control running, and an `include` that matches none would
	// narrow the scan to nothing. Both look like a successful scan. An
	// exception naming no control fails safe — it accepts nothing — but only
	// after a red pipeline sends someone hunting for why the exception they
	// can see in the file did not apply.
	if err := validateSelection(cfg, bundle); err != nil {
		return nil, err
	}

	modules := make(map[string]string, len(bundle.Modules))
	for _, m := range bundle.Modules {
		modules[m.Path] = m.Source
	}
	compiler, err := ast.CompileModules(modules)
	if err != nil {
		return nil, fmt.Errorf("compile policies: %w", err)
	}

	e := &Engine{
		cfg:      cfg,
		bundle:   bundle,
		prepared: make(map[string]rego.PreparedEvalQuery),
	}

	for _, check := range bundle.Checks {
		if !check.AppliesTo(platform) || !cfg.Selects(check.ID) {
			continue
		}
		query := fmt.Sprintf("data.%s.result", check.Package)
		pq, prepErr := rego.New(
			rego.Query(query),
			rego.Compiler(compiler),
		).PrepareForEval(ctx)
		if prepErr != nil {
			return nil, fmt.Errorf("prepare %s (%s): %w", check.ID, query, prepErr)
		}
		e.prepared[check.ID] = pq
		e.selected = append(e.selected, check)
	}

	if len(e.selected) == 0 {
		return nil, fmt.Errorf("no checks selected for platform %q", platform)
	}
	return e, nil
}

// Checks returns the controls this engine will evaluate, in benchmark order.
func (e *Engine) Checks() []checks.Check { return e.selected }

// validateSelection rejects include/exclude entries that name no control in the
// bundle. IDs are compared case-insensitively and trimmed, matching how
// config.Selects reads them, so the two cannot disagree about what is known.
func validateSelection(cfg config.Config, bundle *checks.Bundle) error {
	known := make(map[string]bool, len(bundle.Checks))
	for _, c := range bundle.Checks {
		known[strings.ToUpper(c.ID)] = true
	}

	excepted := make([]string, 0, len(cfg.Exceptions))
	for _, ex := range cfg.Exceptions {
		excepted = append(excepted, ex.Control)
	}

	var unknown []string
	for _, list := range [][]string{cfg.Include, cfg.Exclude, excepted} {
		for _, id := range list {
			id = strings.TrimSpace(id)
			if id == "" || known[strings.ToUpper(id)] {
				continue
			}
			unknown = append(unknown, id)
		}
	}
	if len(unknown) == 0 {
		return nil
	}
	sort.Strings(unknown)
	return fmt.Errorf("unknown check ID(s) in include/exclude/exceptions: %s; run `azure-devops-bench list-checks` for the %d valid IDs",
		strings.Join(unknown, ", "), len(bundle.Checks))
}

// Evaluate runs every selected control against every resource in the snapshot.
//
// Each resource's input is built and converted to an OPA value once, and every
// control evaluates that one value. Converting per control per resource —
// rego.EvalInput does the conversion on every call — made a large organization
// pay for the same JSON-to-AST walk twenty-four times per repository, and the
// conversion, not the rules, dominated the evaluation.
//
// A repository's input holds the repository, its project without sibling
// repositories, the config and the capture metadata — nothing about the rest
// of the organization. The organization's input holds the organization and
// no repository. Handing every repository the whole organization made each
// evaluation's input grow with the organization rather than with the
// repository, which is quadratic over a scan.
func (e *Engine) Evaluate(ctx context.Context, snapshot *scm.Snapshot) (*Report, error) {
	cfgValue, err := toJSONValue(e.cfg)
	if err != nil {
		return nil, fmt.Errorf("encode config: %w", err)
	}
	metaValue, err := toJSONValue(snapshot.Metadata)
	if err != nil {
		return nil, fmt.Errorf("encode snapshot metadata: %w", err)
	}

	report := &Report{Metadata: snapshot.Metadata}

	var orgChecks, repoChecks []checks.Check
	for _, check := range e.selected {
		switch check.Scope {
		case checks.ScopeOrganization:
			orgChecks = append(orgChecks, check)
		case checks.ScopeRepository:
			repoChecks = append(repoChecks, check)
		}
	}

	if len(orgChecks) > 0 {
		orgValue, err := toJSONValue(snapshot.Organization)
		if err != nil {
			return nil, fmt.Errorf("encode organization: %w", err)
		}
		input, err := ast.InterfaceToValue(map[string]any{
			"resource": orgValue,
			"config":   cfgValue,
			"metadata": metaValue,
		})
		if err != nil {
			return nil, fmt.Errorf("convert organization input: %w", err)
		}
		for _, check := range orgChecks {
			report.Findings = append(report.Findings,
				e.evaluateOne(ctx, e.prepared[check.ID], check, InstanceResourceName, ResourceOrganization, input, report))
		}
	}

	for _, project := range snapshot.Projects {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		// The project is passed without its repositories: a control asking
		// about the project should not be able to walk into sibling repos.
		bare := project
		bare.Repositories = nil
		projValue, err := toJSONValue(bare)
		if err != nil {
			return nil, fmt.Errorf("encode project %s: %w", project.Key, err)
		}
		for _, repo := range project.Repositories {
			// Applied here as well as in the fetcher, so the setting means the
			// same thing whichever way a repository arrived: a snapshot
			// evaluated with --snapshot-in or diff honours it too.
			if e.cfg.SkipArchivedRepositories && repo.Archived {
				continue
			}
			report.Repositories++
			repoValue, err := toJSONValue(repo)
			if err != nil {
				return nil, fmt.Errorf("encode repository %s: %w", repo.FullName, err)
			}
			input, err := ast.InterfaceToValue(map[string]any{
				"resource": repoValue,
				"project":  projValue,
				"config":   cfgValue,
				"metadata": metaValue,
			})
			if err != nil {
				return nil, fmt.Errorf("convert repository input %s: %w", repo.FullName, err)
			}
			for _, check := range repoChecks {
				report.Findings = append(report.Findings,
					e.evaluateOne(ctx, e.prepared[check.ID], check, repo.FullName, ResourceRepository, input, report))
			}
		}
	}

	sortFindings(report.Findings)
	report.Score = Compute(report.Findings)
	now := time.Now
	if e.now != nil {
		now = e.now
	}
	report.ExceptionWarnings = applyExceptions(report.Findings, e.cfg.Exceptions, now())
	return report, nil
}

// applyExceptions marks the findings configured exceptions accept and returns
// what is worth telling the operator about the exceptions themselves.
//
// Only FAIL and MANUAL findings can be accepted: there is nothing to accept
// about a PASS or an NA. The score is computed before this runs and does not
// change — it describes the organization, and accepting a finding does not
// change the organization.
func applyExceptions(findings []Finding, exceptions []config.Exception, now time.Time) []string {
	var warnings []string
	for _, ex := range exceptions {
		if !now.Before(ex.ExpiresAt()) {
			warnings = append(warnings, fmt.Sprintf("the exception for %s on %s lapsed on %s; its findings fail the run again (%s)",
				ex.Control, strings.Join(ex.Resources, ", "), ex.Expires, ex.Reason))
			continue
		}
		matched := 0
		for i := range findings {
			f := &findings[i]
			if !strings.EqualFold(f.CheckID, strings.TrimSpace(ex.Control)) || !resourceMatches(ex.Resources, f.Resource) {
				continue
			}
			if f.Status != StatusFail && f.Status != StatusManual {
				continue
			}
			if f.Waiver == nil {
				f.Waiver = &Waiver{Reason: ex.Reason, Owner: ex.Owner, Expires: ex.Expires}
			}
			matched++
		}
		if matched == 0 {
			warnings = append(warnings, fmt.Sprintf("the exception for %s on %s accepts nothing this run — the finding is fixed, renamed or out of scope; remove it",
				ex.Control, strings.Join(ex.Resources, ", ")))
		}
	}
	return warnings
}

// resourceMatches compares case-insensitively: Azure DevOps project and
// repository names are case-insensitive, and an exception written
// Fabrikam/legacy-* must not miss fabrikam/Legacy-Billing.
func resourceMatches(patterns []string, resource string) bool {
	for _, pattern := range patterns {
		if ok, _ := path.Match(strings.ToLower(strings.TrimSpace(pattern)), strings.ToLower(resource)); ok {
			return true
		}
	}
	return false
}

// evaluateOne runs a single control against a single resource. A policy that
// errors or returns nothing yields a MANUAL finding carrying the reason, so a
// broken rule is visible in the report instead of silently missing.
func (e *Engine) evaluateOne(ctx context.Context, pq rego.PreparedEvalQuery, check checks.Check, resource, resourceType string, input ast.Value, report *Report) Finding {
	finding := Finding{
		CheckID:      check.ID,
		CISID:        check.CISID,
		Title:        check.Title,
		Severity:     strings.ToUpper(check.Severity),
		Resource:     resource,
		ResourceType: resourceType,
		Description:  check.Description,
		Remediation:  check.Remediation,
		FixSummary:   check.FixSummary,
		References:   check.References,
		Automated:    check.Automated,
	}

	rs, err := pq.Eval(ctx, rego.EvalParsedInput(input))
	if err != nil {
		msg := fmt.Sprintf("%s on %s: policy evaluation failed: %v", check.ID, resource, err)
		report.Errors = append(report.Errors, msg)
		finding.Status = StatusManual
		finding.Details = "This control could not be evaluated because its policy failed to run: " + err.Error()
		return finding
	}
	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		msg := fmt.Sprintf("%s on %s: policy produced no result", check.ID, resource)
		report.Errors = append(report.Errors, msg)
		finding.Status = StatusManual
		finding.Details = "This control could not be evaluated because its policy produced no result."
		return finding
	}

	decoded, err := decodeResult(rs[0].Expressions[0].Value)
	if err != nil {
		msg := fmt.Sprintf("%s on %s: %v", check.ID, resource, err)
		report.Errors = append(report.Errors, msg)
		finding.Status = StatusManual
		finding.Details = "This control returned a malformed result: " + err.Error()
		return finding
	}

	finding.Status = decoded.Status
	finding.Details = decoded.Details
	finding.Evidence = decoded.Evidence
	return finding
}

type policyResult struct {
	Status   Status
	Details  string
	Evidence []string
}

func decodeResult(value any) (policyResult, error) {
	obj, ok := value.(map[string]any)
	if !ok {
		return policyResult{}, fmt.Errorf("policy result is %T, want an object", value)
	}

	statusRaw, _ := obj["status"].(string)
	status := Status(strings.ToUpper(strings.TrimSpace(statusRaw)))
	switch status {
	case StatusPass, StatusFail, StatusManual, StatusNA:
	default:
		return policyResult{}, fmt.Errorf("policy result status %q is not PASS, FAIL, MANUAL or NA", statusRaw)
	}

	details, _ := obj["details"].(string)
	if strings.TrimSpace(details) == "" {
		return policyResult{}, fmt.Errorf("policy result is missing details")
	}

	var evidence []string
	if raw, present := obj["evidence"]; present {
		items, isSlice := raw.([]any)
		if !isSlice {
			return policyResult{}, fmt.Errorf("policy result evidence is %T, want an array", raw)
		}
		for _, item := range items {
			evidence = append(evidence, fmt.Sprintf("%v", item))
		}
	}

	return policyResult{Status: status, Details: details, Evidence: evidence}, nil
}

// toJSONValue converts a Go value into the plain maps and slices OPA expects,
// honouring the json tags that define the snapshot's contract with the rules.
func toJSONValue(v any) (any, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var out any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// sortFindings orders the report the way it is read: worst first, then by
// benchmark number, then by resource.
func sortFindings(findings []Finding) {
	sort.SliceStable(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if ra, rb := statusRank(a.Status), statusRank(b.Status); ra != rb {
			return ra < rb
		}
		if wa, wb := checks.Weight(a.Severity), checks.Weight(b.Severity); wa != wb {
			return wa > wb
		}
		if a.CISID != b.CISID {
			return checks.LessCISID(a.CISID, b.CISID)
		}
		return a.Resource < b.Resource
	})
}

func statusRank(s Status) int {
	switch s {
	case StatusFail:
		return 0
	case StatusManual:
		return 1
	case StatusPass:
		return 2
	default:
		return 3
	}
}
