// Package diff compares two evaluations of the same instance, so a scan can
// answer "did this get worse" rather than only "how bad is it".
//
// Both sides are evaluated by the same engine with the same configuration
// before being compared. Comparing two already-rendered reports would be
// easier, but the difference would then include whatever changed about the
// tool or its thresholds between the two runs, which is exactly what a
// regression check must not be confused by.
package diff

import (
	"fmt"
	"sort"

	"github.com/scm-bench/azure-devops-bench/internal/checks"
	"github.com/scm-bench/azure-devops-bench/internal/console"
	"github.com/scm-bench/azure-devops-bench/internal/engine"
	"github.com/scm-bench/azure-devops-bench/internal/scm"
)

// Change is one control on one resource whose verdict moved.
type Change struct {
	CheckID      string        `json:"checkId"`
	CISID        string        `json:"cisId"`
	Title        string        `json:"title"`
	Severity     string        `json:"severity"`
	Resource     string        `json:"resource"`
	ResourceType string        `json:"resourceType"`
	From         engine.Status `json:"from,omitempty"`
	To           engine.Status `json:"to"`
	// Details is the current verdict's explanation — what is true now, which is
	// what someone acting on the change needs.
	Details     string `json:"details"`
	Remediation string `json:"remediation,omitempty"`
}

// Result is the full comparison.
type Result struct {
	Before Side `json:"before"`
	After  Side `json:"after"`

	// Regressed is PASS to FAIL: a control that was satisfied and no longer is.
	// This is the only category that means the instance got worse in a way
	// nobody chose, and the only one that drives the exit code.
	Regressed []Change `json:"regressed,omitempty"`
	// Fixed is FAIL to PASS.
	Fixed []Change `json:"fixed,omitempty"`
	// NewFailures are failures on resources that did not exist before — a
	// repository added since the baseline. Worth seeing, but not a regression:
	// nothing got worse, there is simply more of the instance.
	NewFailures []Change `json:"newFailures,omitempty"`
	// Changed is every other movement, including anything involving MANUAL.
	// A control going PASS to MANUAL means the tool stopped being able to see,
	// not that the setting changed, and calling that a regression would blame
	// the instance for a lost permission or a removed add-on.
	Changed []Change `json:"changed,omitempty"`
	// Departed are resources present before and absent now, one entry per
	// resource rather than per control: a repository being deleted is one fact
	// about the repository, not twenty facts about twenty controls.
	Departed []Change `json:"departed,omitempty"`
}

// Side summarises one of the two evaluations.
type Side struct {
	BaseURL     string       `json:"baseUrl,omitempty"`
	GeneratedAt string       `json:"generatedAt,omitempty"`
	Score       engine.Score `json:"score"`
}

// HasRegression reports whether any control fell from PASS to FAIL. It backs
// the exit code.
func (r *Result) HasRegression() bool { return len(r.Regressed) > 0 }

// Compare diffs two reports of the same instance.
func Compare(before, after *engine.Report) *Result {
	result := &Result{
		Before: side(before),
		After:  side(after),
	}

	old := index(before.Findings)
	current := index(after.Findings)

	for key, now := range current {
		then, existed := old[key]
		change := changeOf(now)

		switch {
		case !existed:
			// A resource nobody has seen before. A new repository that passes
			// is not news. One that fails is, and so is one the tool cannot see
			// into: "a repository arrived that nothing can be read from" used
			// to produce no entry at all, so the fact disappeared entirely.
			switch now.Status {
			case engine.StatusFail:
				result.NewFailures = append(result.NewFailures, change)
			case engine.StatusManual:
				result.Changed = append(result.Changed, change)
			}
		case then.Status == now.Status:
			// No movement.
		case then.Status == engine.StatusPass && now.Status == engine.StatusFail:
			change.From = then.Status
			result.Regressed = append(result.Regressed, change)
		case then.Status == engine.StatusFail && now.Status == engine.StatusPass:
			change.From = then.Status
			result.Fixed = append(result.Fixed, change)
		default:
			change.From = then.Status
			result.Changed = append(result.Changed, change)
		}
	}

	result.Departed = departedResources(old, current)

	for _, set := range [][]Change{
		result.Regressed, result.Fixed, result.NewFailures, result.Changed, result.Departed,
	} {
		sortChanges(set)
	}
	return result
}

// departedResources collapses the controls of a vanished resource into one
// entry for the resource itself.
//
// It used to emit one per control, so deleting a repository produced twenty
// lines and deleting fifty produced a thousand — while the same event on the
// other side, a repository arriving, produced only its failures. The asymmetry
// buried real regressions under a wall of GONE, which is the opposite of what
// this command is for. The count of failures the resource was carrying is kept,
// because "the repository with five HIGH failures is gone" is the part worth
// knowing.
func departedResources(old, current map[findingKey]engine.Finding) []Change {
	type gone struct {
		change   Change
		failures int
		controls int
	}
	byResource := map[string]*gone{}

	for key, then := range old {
		if _, still := current[key]; still {
			continue
		}
		entry, seen := byResource[key.resource]
		if !seen {
			entry = &gone{change: Change{
				Resource:     then.Resource,
				ResourceType: then.ResourceType,
				To:           "",
			}}
			byResource[key.resource] = entry
		}
		entry.controls++
		if then.Status == engine.StatusFail {
			entry.failures++
			// The severity shown is the worst the resource was carrying, so the
			// list still sorts the way every other category does.
			if checks.Weight(then.Severity) > checks.Weight(entry.change.Severity) {
				entry.change.Severity = then.Severity
			}
		}
	}

	out := make([]Change, 0, len(byResource))
	for _, entry := range byResource {
		entry.change.Details = departedDetails(entry.controls, entry.failures)
		out = append(out, entry.change)
	}
	sort.Slice(out, func(i, j int) bool {
		if wa, wb := checks.Weight(out[i].Severity), checks.Weight(out[j].Severity); wa != wb {
			return wa > wb
		}
		return out[i].Resource < out[j].Resource
	})
	return out
}

// departedDetails says what the resource was carrying when it was last seen,
// because "the repository with five HIGH failures is gone" is the part of a
// deletion worth knowing.
func departedDetails(controls, failures int) string {
	if failures == 0 {
		return fmt.Sprintf("no longer present; none of its %s were failing", console.Pluralize(controls, "control"))
	}
	return fmt.Sprintf("no longer present; it was failing %s of %d evaluated",
		console.Pluralize(failures, "control"), controls)
}

func side(rep *engine.Report) Side {
	s := Side{Score: rep.Score, BaseURL: rep.Metadata.BaseURL}
	if !rep.Metadata.GeneratedAt.IsZero() {
		s.GeneratedAt = rep.Metadata.GeneratedAt.UTC().Format("2006-01-02 15:04:05 MST")
	}
	return s
}

// findingKey identifies the same question asked of the same thing. Both parts
// are needed: a control alone spans every repository, and a resource alone
// spans every control.
type findingKey struct {
	checkID  string
	resource string
}

func index(findings []engine.Finding) map[findingKey]engine.Finding {
	out := make(map[findingKey]engine.Finding, len(findings))
	for _, f := range findings {
		out[findingKey{checkID: f.CheckID, resource: f.Resource}] = f
	}
	return out
}

func changeOf(f engine.Finding) Change {
	return Change{
		CheckID:      f.CheckID,
		CISID:        f.CISID,
		Title:        f.Title,
		Severity:     f.Severity,
		Resource:     f.Resource,
		ResourceType: f.ResourceType,
		To:           f.Status,
		Details:      f.Details,
		Remediation:  f.Remediation,
	}
}

// sortChanges orders a category the way it is read: worst severity first, then
// by benchmark number, then by resource.
func sortChanges(changes []Change) {
	sort.SliceStable(changes, func(i, j int) bool {
		a, b := changes[i], changes[j]
		if wa, wb := checks.Weight(a.Severity), checks.Weight(b.Severity); wa != wb {
			return wa > wb
		}
		if a.CISID != b.CISID {
			return checks.LessCISID(a.CISID, b.CISID)
		}
		return a.Resource < b.Resource
	})
}

// SameInstance reports whether two snapshots describe the same instance.
// Diffing two different instances produces a result that looks meaningful and
// is not, so the caller warns rather than letting it pass unremarked.
func SameInstance(before, after *scm.Snapshot) bool {
	return before.Metadata.BaseURL == after.Metadata.BaseURL
}
