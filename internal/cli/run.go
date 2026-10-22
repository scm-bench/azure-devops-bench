package cli

import (
	"context"
	"errors"

	"github.com/spf13/cobra"

	"github.com/scm-bench/azure-devops-bench/internal/console"
)

// Run executes the command tree and returns the process's exit code. When it
// is not ExitOK, the reason is the last line on out, carrying the same tag
// column as everything above it, so a reader scanning down column one does not
// lose the thread at the one line that says why the scan stopped.
func Run(ctx context.Context, root *cobra.Command, out console.Writer) int {
	err := root.ExecuteContext(ctx)
	if err == nil {
		return ExitOK
	}
	code := ExitCode(err)
	switch {
	case errors.Is(err, context.Canceled):
		// Ctrl-C. Saying so beats exiting 2 in silence, which is
		// indistinguishable from a crash to anyone reading a log later.
		out.Line(console.Warn, "interrupted")
	case code == ExitError:
		out.Line(console.Fail, "%v", err)
	default:
		// A findings exit is a successful scan with a negative result: the
		// report has already been printed, so only a one-line summary belongs
		// on stderr. INFO, not ERR — nothing went wrong with the scan.
		out.Line(console.Info, "%v", err)
	}
	return code
}
