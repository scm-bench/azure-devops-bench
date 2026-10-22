// Command azure-devops-bench audits an Azure DevOps organization against the
// Source Code section of the CIS Software Supply Chain Security Guide.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/scm-bench/azure-devops-bench/internal/cli"
)

// exit is os.Exit; a variable so the wiring below can be tested in-process.
var exit = os.Exit

func main() {
	// A scan can take a while on a large organization, so Ctrl-C cancels the
	// in-flight requests rather than leaving the process to be killed.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := cli.Run(ctx, cli.NewRootCommand(), cli.StderrWriter())
	stop()
	exit(code)
}
