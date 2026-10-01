package diff

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/scm-bench/azure-devops-bench/internal/checks"
	"github.com/scm-bench/azure-devops-bench/internal/console"
	"github.com/scm-bench/azure-devops-bench/internal/report"
)

// Options controls how a comparison is rendered.
type Options struct {
	Format string
	Color  bool
	// Width is how many columns the table may use; zero asks the environment
	// (console.Width), mirroring report.Options.
	Width int
}

// The codes come from internal/console, which is the one place they are
// defined. Three private copies of the same six constants is how two renderers
// end up disagreeing about what "dim" is without anything failing.
const (
	ansiBold   = console.Bold
	ansiDim    = console.Dim
	ansiRed    = console.Red
	ansiGreen  = console.Green
	ansiYellow = console.Yellow
	ansiCyan   = console.Cyan
)

// Write renders the comparison.
func Write(w io.Writer, r *Result, opts Options) error {
	switch strings.ToLower(strings.TrimSpace(opts.Format)) {
	case "", report.FormatTable:
		return writeTable(w, r, opts)
	case report.FormatJSON:
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		enc.SetEscapeHTML(false)
		return enc.Encode(r)
	default:
		return fmt.Errorf("unknown output format %q for diff; want table or json", opts.Format)
	}
}

func paint(enabled bool, code, s string) string {
	return console.Painter{Enabled: enabled}.Paint(code, s)
}

// writeTable renders the comparison in the same shape as the scan report.
//
// It draws with the same table renderer, and it does so for the same reason it
// used to carry the same tag column: this renderer once had a layout of its
// own, and a diff looked like a different program's output right up to the
// closing line, which came from main and did not. Whatever scan's report looks
// like, diff has to look like it too.
func writeTable(w io.Writer, r *Result, opts Options) error {
	c := opts.Color
	width := opts.Width
	if width == 0 {
		width = console.Width()
	}

	line(w, "%s  %s", paint(c, ansiBold, "azure-devops-bench diff"), paint(c, ansiDim, sideLabel(r)))
	writeScoreLine(w, r, c)

	sections := []struct {
		changes []Change
		header  string
		colour  string
		// arrow is false where a from-status would be noise: a new resource has
		// no previous verdict to move from.
		arrow bool
	}{
		{r.Regressed, "Regressed", ansiRed, true},
		{r.NewFailures, "New failures", ansiYellow, false},
		{r.Fixed, "Fixed", ansiGreen, true},
		{r.Changed, "Other changes", ansiYellow, true},
		{r.Departed, "Gone", ansiDim, false},
	}

	var any bool
	for _, s := range sections {
		if len(s.changes) == 0 {
			continue
		}
		any = true
		blank(w)
		line(w, "%s %s", paint(c, ansiBold+s.colour, s.header), paint(c, ansiDim, fmt.Sprintf("(%d)", len(s.changes))))
		blank(w)
		writeChanges(w, s.changes, opts, width, s.arrow)
	}

	if !any {
		blank(w)
		line(w, "%s", paint(c, ansiGreen, "No control changed verdict."))
	}

	// Remediation is printed once, for the regressions only: those are the ones
	// somebody is expected to act on right now. It stays prose for the same
	// reason scan's does — these are paragraphs, and a paragraph in a cell is a
	// column of three-word lines.
	if len(r.Regressed) > 0 {
		blank(w)
		line(w, "%s", paint(c, ansiBold, "How to fix the regressions"))
		blank(w)
		for _, id := range distinctChecks(r.Regressed) {
			for _, ch := range r.Regressed {
				if ch.CheckID != id {
					continue
				}
				prose(w, width, "  "+paint(c, ansiCyan+ansiBold, ch.CheckID)+"  ", len(ch.CheckID)+4, ch.Remediation)
				break
			}
		}
	}

	blank(w)
	return nil
}

func line(w io.Writer, format string, args ...any) {
	fmt.Fprintf(w, format+"\n", args...)
}

func blank(w io.Writer) { fmt.Fprintln(w) }

// prose writes wrapped text with a hanging indent, matching the scan report's
// remediation section.
func prose(w io.Writer, width int, prefix string, prefixWidth int, text string) {
	lines := console.Wrap(text, width-prefixWidth)
	pad := strings.Repeat(" ", prefixWidth)
	for i, l := range lines {
		if i == 0 {
			line(w, "%s%s", prefix, l)
			continue
		}
		line(w, "%s%s", pad, l)
	}
}

func writeScoreLine(w io.Writer, r *Result, c bool) {
	before, after := r.Before.Score.Value, r.After.Score.Value
	delta := after - before

	arrow := paint(c, ansiDim, "→")
	sign := ""
	colour := ansiDim
	switch {
	case delta > 0:
		sign, colour = "+", ansiGreen
	case delta < 0:
		colour = ansiRed
	}

	line(w, "%s  %d %s %d   %s",
		paint(c, ansiBold, "SCORE"),
		before, arrow, after,
		paint(c, colour, fmt.Sprintf("(%s%d)", sign, delta)),
	)
	// The weighted arithmetic moves for two different reasons — a verdict
	// changed, or the number of applicable controls did — and the score alone
	// cannot tell them apart.
	line(w, "%s", paint(c, ansiDim, fmt.Sprintf(
		"       weighted %d/%d → %d/%d",
		r.Before.Score.EarnedWeight, r.Before.Score.TotalWeight,
		r.After.Score.EarnedWeight, r.After.Score.TotalWeight,
	)))
}

func writeChanges(w io.Writer, changes []Change, opts Options, width int, arrow bool) {
	c := opts.Color

	// A departed resource has no control ID: it is one entry for the resource,
	// not one per control. The column is still drawn, with a dash, because a
	// table cannot drop a column for one row — and a dash is how the scan
	// report already writes "none here".
	cols := []console.Column{
		{Header: "Control", Align: console.AlignLeft,
			Colour: func(s string) string { return paint(c, ansiCyan, s) }},
		{Header: "Severity", Align: console.AlignLeft, Colour: func(s string) string {
			switch strings.ToUpper(s) {
			case checks.SeverityHigh:
				return paint(c, ansiRed, s)
			case checks.SeverityMedium:
				return paint(c, ansiYellow, s)
			}
			return paint(c, ansiDim, s)
		}},
		{Header: "Resource", Align: console.AlignLeft},
		{Header: "Change", Align: console.AlignLeft, Colour: func(s string) string { return paint(c, ansiDim, s) }},
		{Header: "Detail", Align: console.AlignLeft, Flex: true},
	}

	rows := make([][]string, 0, len(changes))
	for _, ch := range changes {
		transition := string(ch.To)
		if arrow && ch.From != "" {
			transition = fmt.Sprintf("%s → %s", ch.From, ch.To)
		}
		if ch.To == "" {
			transition = "gone"
		}
		id := ch.CheckID
		if id == "" {
			id = "-"
		}
		rows = append(rows, []string{id, strings.ToUpper(ch.Severity), ch.Resource, transition, ch.Details})
	}
	console.RenderTable(w, width, cols, rows)
}

func sideLabel(r *Result) string {
	if r.Before.GeneratedAt == "" || r.After.GeneratedAt == "" {
		return r.After.BaseURL
	}
	return fmt.Sprintf("%s  ·  %s → %s", r.After.BaseURL, r.Before.GeneratedAt, r.After.GeneratedAt)
}

func distinctChecks(changes []Change) []string {
	seen := map[string]bool{}
	var out []string
	for _, ch := range changes {
		if seen[ch.CheckID] {
			continue
		}
		seen[ch.CheckID] = true
		out = append(out, ch.CheckID)
	}
	return out
}
