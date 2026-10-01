package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"

	"github.com/scm-bench/azure-devops-bench/internal/config"
	"github.com/scm-bench/azure-devops-bench/internal/console"
	"github.com/scm-bench/azure-devops-bench/internal/engine"
	"github.com/scm-bench/azure-devops-bench/internal/report"
	"github.com/scm-bench/azure-devops-bench/internal/safefile"
	"github.com/scm-bench/azure-devops-bench/internal/scm"
	"github.com/scm-bench/azure-devops-bench/internal/scm/azuredevops"
)

// Progress modes. Compact is the default: one self-overwriting line while the
// scan runs, and the closing accounting line when it finishes. Full — every
// request on its own line — is what --verbose turns on.
const (
	ProgressFull    = "full"
	ProgressCompact = "compact"
	ProgressOff     = "off"
)

// The environment variables the scan flags fall back to.
const (
	envURL   = "AZURE_DEVOPS_URL"
	envToken = "AZURE_DEVOPS_TOKEN"
)

// exitCodeError carries a specific process exit code out of RunE.
type exitCodeError struct {
	code int
	msg  string
}

func (e *exitCodeError) Error() string { return e.msg }

// ExitCode extracts the process exit code from an error returned by the root
// command, defaulting to ExitError.
func ExitCode(err error) int {
	if err == nil {
		return ExitOK
	}
	var coded *exitCodeError
	if errors.As(err, &coded) {
		return coded.code
	}
	return ExitError
}

type scanOptions struct {
	baseURL string
	token   string

	projects     []string
	repositories []string

	demo bool
	// saveInstance remembers the interactively entered URL and token once the
	// scan proves they work.
	saveInstance bool

	configPath     string
	set            []string
	format         string
	outputPath     string
	showPassed     bool
	details        []string
	maxResources   int
	noColor        bool
	verbose        bool
	noRemediations bool

	// The deployment-stable settings, filled from the config file's scan
	// section rather than flags: they describe the organization, not the run.
	scan config.Scan

	snapshotIn  string
	snapshotOut string
	// last renders the previous scan's cached snapshot instead of fetching.
	last bool

	// logMu serializes progress output: the fetcher scans repositories
	// concurrently and calls the log callback from each goroutine.
	logMu sync.Mutex
}

func newScanCommand() *cobra.Command {
	opts := &scanOptions{}

	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan an Azure DevOps organization or collection",
		Long: `Scan captures a read-only snapshot of an Azure DevOps organization (Services) or
collection (Server 2022 and later) and evaluates it against the benchmark.

--url takes https://dev.azure.com/{organization}, https://{organization}.visualstudio.com,
or https://{server}/{collection} for Azure DevOps Server. --token takes a personal
access token, or a Microsoft Entra access token — anything shaped like a JWT is
sent as a bearer token:

  az account get-access-token --resource 499b84ac-1321-427f-aa17-267ca6975798

vso.project and vso.code are enough for the policy-based controls. Who can
bypass, force push, delete, administer or create repositories needs
vso.security_manage (and vso.identity, vso.graph); dormant users need
vso.memberentitlementmanagement; secret push protection needs vso.advsec.
Without them those controls report MANUAL instead of failing.

Credentials may be supplied by flag or environment:
  AZURE_DEVOPS_URL, AZURE_DEVOPS_TOKEN

No organization yet? --demo evaluates a sample bundled into the binary. Run bare
on a terminal, scan offers the same choice interactively — and can save the URL
and token you enter (0600, under your user config directory, or
AZURE_DEVOPS_BENCH_CONFIG_DIR) so later scans need nothing.

The table report is line-oriented: one record per failure, naming the resource,
the control and what is wrong, with the one-line fix and the evidence beneath
it. Controls needing a person aggregate to one line each. --details expands
the report to a table per resource; --details=<resource|control>[,...] narrows
those sections to what is named.

Each network scan also leaves its snapshot behind (0600, under the user config
directory), so ` + "`scan --last --details`" + ` re-renders the previous scan without
contacting the organization. scan.cache: false keeps it off disk.

Exit codes: 0 clean, 1 a threshold was breached, 2 the scan failed — including a
scan that evaluated no repository at all, and one whose enumeration was
incomplete unless scan.allowIncomplete is set. Findings accepted by an
exception in the config (with a reason and an expiry) are still reported and
scored, but do not trip scan.failOn.

The settings that describe the deployment rather than any one run — exit
thresholds, transport (caFile, insecure, allowPlaintext), concurrency,
progress — live in the config file's scan section. Run
` + "`azure-devops-bench init`" + ` to write a commented azure-devops-bench.yaml; scan finds it
in the working directory (or the user config directory) and names it on stderr.
For a one-off, --set overrides any config key: --set scan.failOn=none.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runScan(cmd, opts)
		},
	}

	f := cmd.Flags()
	f.StringVar(&opts.baseURL, "url", os.Getenv(envURL), "organization or collection URL, e.g. https://dev.azure.com/fabrikam ["+envURL+"]")
	f.StringVar(&opts.token, "token", os.Getenv(envToken), "personal access token, or a Microsoft Entra access token ["+envToken+"]")

	f.StringSliceVarP(&opts.projects, "project", "p", nil, "project to scan; repeatable, defaults to all")
	f.StringSliceVarP(&opts.repositories, "repository", "r", nil, "repository to scan as PROJECT/REPOSITORY; repeatable")

	f.BoolVar(&opts.demo, "demo", false, "evaluate the bundled example instead of an organization, to see what a report looks like")

	f.StringVarP(&opts.configPath, "config", "c", "", "path to a YAML config file; found automatically as ./azure-devops-bench.yaml or in the user config directory")
	f.StringArrayVar(&opts.set, "set", nil, "override one config key for this run, e.g. --set scan.failOn=none; repeatable")
	f.StringVarP(&opts.format, "output", "o", report.FormatTable, "output format: "+strings.Join(report.Formats(), ", "))
	f.StringVar(&opts.outputPath, "output-file", "", "write the report to this file (0600) instead of stdout")
	f.BoolVar(&opts.showPassed, "show-passed", false, "include passing and not-applicable controls in the table output")
	f.StringSliceVar(&opts.details, "details", nil, "per-resource findings instead of the overview; --details=<resource|control>[,...] narrows it (the '=' is required when passing values)")
	// Bare --details, no value, means every resource and every control.
	f.Lookup("details").NoOptDefVal = "all"
	f.IntVar(&opts.maxResources, "max-resources", report.DefaultMaxResources, "with --details: how many resources get a table of their own; 0 means every one")
	f.BoolVar(&opts.noColor, "no-color", false, "disable ANSI colour")
	f.BoolVarP(&opts.verbose, "verbose", "v", false, "log every request and the fetch's progress to stderr")
	f.BoolVar(&opts.noRemediations, "no-remediations", false, "omit the remediation section from the table report")

	f.StringVar(&opts.snapshotIn, "snapshot-in", "", "evaluate this snapshot file instead of contacting the organization")
	f.StringVar(&opts.snapshotOut, "snapshot-out", "", "write the captured snapshot to this file (0600)")
	f.BoolVar(&opts.last, "last", false, "render the previous scan's cached snapshot instead of contacting the organization")

	cmd.SetFlagErrorFunc(movedFlagError)
	return cmd
}

// movedFlags maps the settings that are config keys in this family, not
// flags, to where they live — someone arriving from another tool's habits gets
// told where it went instead of cobra's bare "unknown flag".
var movedFlags = map[string]string{
	"fail-on":          "scan.failOn",
	"fail-under":       "scan.failUnder",
	"max-manual":       "scan.maxManual",
	"concurrency":      "scan.concurrency",
	"timeout":          "scan.timeout",
	"max-duration":     "scan.maxDuration",
	"insecure":         "scan.insecure",
	"allow-plaintext":  "scan.allowPlaintext",
	"ca-file":          "scan.caFile",
	"allow-incomplete": "scan.allowIncomplete",
	"progress":         "scan.progress",
}

// movedFlagError upgrades "unknown flag" for one of the settings above into
// directions. Anything else passes through untouched.
func movedFlagError(cmd *cobra.Command, err error) error {
	msg := err.Error()
	for flag, key := range movedFlags {
		if strings.Contains(msg, "--"+flag) {
			return fmt.Errorf("--%s is the config key %s\n"+
				"run `azure-devops-bench init` to keep it in a file, or override once with --set %s=<value>", flag, key, key)
		}
	}
	return err
}

func runScan(cmd *cobra.Command, opts *scanOptions) error {
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	if opts.demo {
		// A typed flag the demo would silently ignore is refused: the report
		// would look exactly like the scan that was asked for and not be it.
		// Flags merely filled in from the environment do not count — an
		// exported AZURE_DEVOPS_URL must not make the demo argue.
		for _, name := range []string{"url", "token", "project", "repository", "snapshot-in", "last"} {
			if cmd.Flags().Changed(name) {
				return fmt.Errorf("--demo evaluates the bundled example, so --%s has nothing to act on; drop one of them", name)
			}
		}
		opts.baseURL, opts.token = "", ""
	}

	// --last replays the previous scan from its cached snapshot, so every
	// flag that shapes a fresh capture has nothing to act on and is refused.
	if opts.last {
		for _, name := range []string{"url", "token", "project", "repository", "snapshot-in"} {
			if cmd.Flags().Changed(name) {
				return fmt.Errorf("--last renders the previous scan's cached snapshot, so --%s has nothing to act on; drop one of them", name)
			}
		}
		path, err := config.LatestSnapshotCache()
		if err != nil {
			return err
		}
		if path == "" {
			return fmt.Errorf("no cached snapshot to render: --last replays the previous scan, and none has been cached yet\n" +
				"scan the organization first; its snapshot is kept automatically unless the config sets scan.cache: false")
		}
		opts.snapshotIn = path
		opts.baseURL, opts.token = "", ""
	}

	// The config comes first, because nearly everything after reads it. It is
	// named on stderr whether it was discovered or given: a config file a pull
	// request dropped into the working directory changes how the CI gate
	// judges the organization, and must not do it silently.
	stderr := cmd.ErrOrStderr()
	configPath := opts.configPath
	if configPath == "" {
		discovered, err := config.Discover()
		if err != nil {
			return err
		}
		configPath = discovered
	}
	if configPath != "" {
		console.Writer{W: stderr, P: console.Painter{Enabled: useProgressColor(opts, stderr)}}.
			Line(console.Info, "using config %s", configPath)
	}
	cfg, err := config.LoadWithOverrides(configPath, opts.set)
	if err != nil {
		return err
	}
	opts.scan = cfg.Scan
	if cfg.Scan.CAFile != "" {
		// Validated now, whatever the scan will do: a CA bundle that cannot
		// be read is a broken configuration, and finding out after the
		// credential has been typed — or only on the next network scan — is
		// finding out too late.
		if _, err := azuredevops.LoadCABundle(cfg.Scan.CAFile); err != nil {
			return err
		}
	}

	// An organization saved by an earlier run's menu answers the question
	// silently. It only fills what is absent, and the stderr line keeps it
	// debuggable: a scan that silently picks up a credential from disk is a
	// scan whose authentication failures make no sense.
	if !opts.demo && opts.snapshotIn == "" && strings.TrimSpace(opts.baseURL) == "" {
		inst, path, err := config.LoadInstance()
		if err != nil {
			return err
		}
		if inst.URL != "" {
			opts.baseURL = inst.URL
			if strings.TrimSpace(opts.token) == "" {
				opts.token = inst.Token
			}
			console.Writer{W: stderr, P: console.Painter{Enabled: useProgressColor(opts, stderr)}}.
				Line(console.Info, "using saved organization %s (%s)", inst.URL, path)
		}
	}

	// Nothing configured, but a person present: offer the menu instead of the
	// error. Both ends must be terminals.
	if !opts.demo && opts.snapshotIn == "" && strings.TrimSpace(opts.baseURL) == "" {
		if in, ok := cmd.InOrStdin().(*os.File); ok && isTerminal(in) && isTerminal(stderr) {
			res, err := promptFirstRun(in, stderr, useProgressColor(opts, stderr))
			if err != nil {
				return err
			}
			if res.demo {
				opts.demo = true
			} else {
				opts.baseURL = res.url
				opts.token = res.token
				opts.saveInstance = res.save
			}
		}
	}

	if len(opts.details) > 0 && !strings.EqualFold(opts.format, report.FormatTable) {
		return fmt.Errorf("--details shapes the table output; -o %s already carries every finding", opts.format)
	}
	if cmd.Flags().Changed("max-resources") && len(opts.details) == 0 {
		return fmt.Errorf("--max-resources caps the per-resource tables, which the default overview does not print; combine it with --details")
	}

	if err := validateScanOptions(opts); err != nil {
		return err
	}

	// The engine is built before anything is fetched. An include, exclude or
	// exception naming no control is a configuration error, and finding it
	// after a full network scan of a large organization wastes the scan.
	// Every snapshot this build accepts is an Azure DevOps one (parseSnapshot
	// refuses the rest), so the platform is known now.
	eng, err := engine.New(ctx, cfg, scm.PlatformAzureDevOps)
	if err != nil {
		return err
	}

	// A whole-scan deadline is opt-in: how long is too long depends entirely
	// on how big the organization is.
	if opts.scan.MaxDuration.Get() > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, opts.scan.MaxDuration.Get())
		defer cancel()
	}

	shown := strings.ToLower(opts.scan.Progress)
	if opts.verbose {
		shown = ProgressFull
	}
	if !isTerminal(stderr) && shown == ProgressFull && !opts.verbose {
		// Every request on its own line needs a terminal to be readable; in a
		// log it is thousands of lines nobody asked for. --verbose typed into
		// a pipeline is a request for exactly those lines, so it still wins.
		shown = ProgressOff
	}
	// The tracer exists even when nothing is shown: its closing line is an
	// account of what the token was used for, and that is worth having in a
	// CI log too.
	trace := newTracer(stderr, useProgressColor(opts, stderr), shown == ProgressFull)

	if opts.demo {
		console.Writer{W: stderr, P: console.Painter{Enabled: useProgressColor(opts, stderr)}}.
			Line(console.Info, "evaluating the bundled example; pass --url to scan your own organization")
	}

	progress := newProgressWriter(stderr, shown == ProgressCompact && !opts.verbose)
	snapshot, err := obtainSnapshot(ctx, cmd, opts, cfg, trace, progress)
	progress.clear()
	// The accounting line closes the scan's stderr, whatever happens next —
	// a saved organization, a written report, a failure — because it is the
	// one line that says what the token was used for, and it must not be
	// buried above them. Only the process's own exit line follows it.
	defer func() {
		if line, tag := trace.summary(); line != "" {
			console.Writer{W: stderr, P: console.Painter{Enabled: useProgressColor(opts, stderr)}}.Line(tag, "%s", line)
		}
	}()
	if err != nil {
		return describeScanFailure(ctx, opts, err)
	}

	// A replayed snapshot must say how old it is, every time: the report
	// looks exactly like a fresh scan, and its one real difference from one
	// is the capture time.
	if opts.last {
		w := console.Writer{W: stderr, P: console.Painter{Enabled: useProgressColor(opts, stderr)}}
		age := time.Since(snapshot.Metadata.GeneratedAt)
		if age > staleSnapshotAge {
			w.Line(console.Warn, "rendering the snapshot of %s captured %s ago — scan again for current state", snapshot.Metadata.BaseURL, humanAge(age))
		} else {
			w.Line(console.Info, "rendering the snapshot of %s captured %s ago", snapshot.Metadata.BaseURL, humanAge(age))
		}
	}

	// Only now, with the fetch behind it, is the interactively entered
	// organization worth remembering: a credential saved before it worked
	// would replay its typo on every following run.
	if opts.saveInstance {
		w := console.Writer{W: stderr, P: console.Painter{Enabled: useProgressColor(opts, stderr)}}
		if path, err := config.SaveInstance(config.Instance{URL: opts.baseURL, Token: opts.token}); err != nil {
			w.Line(console.Warn, "could not save the organization: %v", err)
		} else {
			w.Line(console.Info, "saved to %s; delete the file to forget it", path)
		}
	}

	if opts.snapshotOut != "" {
		if err := writeSnapshot(opts.snapshotOut, snapshot); err != nil {
			return err
		}
		logf(cmd, opts, "snapshot written to %s", opts.snapshotOut)
	}

	// A network scan's snapshot is kept for --last, 0600 like every other
	// copy of an organization's posture this tool writes. Replays and the
	// demo are excluded: one would only rewrite what it just read, the other
	// would let --last pass off the bundled example as somebody's
	// organization.
	if !opts.demo && opts.snapshotIn == "" && opts.scan.Cache {
		if path, err := config.SnapshotCachePath(snapshot.Metadata.BaseURL); err != nil {
			emit(cmd, opts, console.Warn, "could not cache the snapshot: %v", err)
		} else if err := writeSnapshot(path, snapshot); err != nil {
			emit(cmd, opts, console.Warn, "could not cache the snapshot: %v", err)
		} else {
			logf(cmd, opts, "snapshot cached for --last (%s)", path)
		}
	}

	rep, err := eng.Evaluate(ctx, snapshot)
	if err != nil {
		return err
	}
	// Printed whatever the verbosity: a lapsed exception is a finding that
	// starts failing the run today, and the exit code alone would not say why.
	if len(rep.ExceptionWarnings) > 0 {
		w := console.Writer{W: stderr, P: console.Painter{Enabled: useProgressColor(opts, stderr)}}
		for _, warning := range rep.ExceptionWarnings {
			w.Line(console.Warn, "%s", warning)
		}
	}

	// The report is rendered into memory first, so a render failure cannot
	// leave a half-written file that looks like a complete report.
	var buf bytes.Buffer
	reportOpts := report.Options{
		Format:         opts.format,
		ShowPassed:     opts.showPassed,
		Details:        len(opts.details) > 0,
		DetailFilters:  opts.details,
		MaxResources:   opts.maxResources,
		NoRemediations: opts.noRemediations,
		ToolVersion:    Version,
	}
	if opts.outputPath == "" {
		out := cmd.OutOrStdout()
		reportOpts.Color = useColor(opts, out)
		reportOpts.Width = console.WidthFor(out)
	}
	if opts.demo {
		reportOpts.Notice = demoNotice
	}
	if err := report.Write(&buf, rep, reportOpts); err != nil {
		return err
	}
	if opts.outputPath != "" {
		// 0600 and atomic: a report names every repository that can be force
		// pushed and every account that should have been removed — the same
		// map of weak points the snapshot is — and a CI step must never read
		// a half-written one as complete.
		if err := safefile.Write(opts.outputPath, buf.Bytes()); err != nil {
			return err
		}
		logf(cmd, opts, "report written to %s", opts.outputPath)
	} else if _, err := io.Copy(cmd.OutOrStdout(), &buf); err != nil {
		return err
	}

	return exitStatus(rep, opts)
}

func validateScanOptions(opts *scanOptions) error {
	// Checked here as well as in the fetcher so a typo costs nothing to find:
	// the fetcher only reaches its own check after the preflight.
	for _, r := range opts.repositories {
		project, name, ok := strings.Cut(strings.TrimSpace(r), "/")
		if !ok || strings.TrimSpace(project) == "" || strings.TrimSpace(name) == "" {
			return fmt.Errorf("--repository %q must be PROJECT/REPOSITORY, e.g. Fabrikam-Fiber/payments-api", r)
		}
	}
	if !opts.demo && opts.snapshotIn == "" && strings.TrimSpace(opts.baseURL) == "" {
		return errNoInstance()
	}
	// --project and --repository narrow what is fetched. A snapshot has
	// already been fetched, and ignoring them silently would produce a report
	// covering every repository in the file that looks like the narrowed scan.
	if opts.snapshotIn != "" && (len(opts.projects) > 0 || len(opts.repositories) > 0) {
		return fmt.Errorf("--project/--repository narrow what is fetched from an organization, so they cannot be combined with --snapshot-in\n" +
			"the snapshot already holds a fixed set of repositories; re-capture with --project/--repository to narrow it")
	}
	return nil
}

// obtainSnapshot either reads a saved snapshot or captures a fresh one.
func obtainSnapshot(ctx context.Context, cmd *cobra.Command, opts *scanOptions, cfg config.Config, trace *tracer, progress *progressWriter) (*scm.Snapshot, error) {
	if opts.demo {
		return demoSnapshot()
	}
	if opts.snapshotIn != "" {
		return readSnapshot(opts.snapshotIn)
	}

	progress.start()
	client, err := azuredevops.NewClient(azuredevops.Options{
		URL:            opts.baseURL,
		Token:          opts.token,
		Timeout:        opts.scan.Timeout.Get(),
		Concurrency:    opts.scan.Concurrency,
		Insecure:       opts.scan.Insecure,
		AllowPlaintext: opts.scan.AllowPlaintext,
		CAFile:         opts.scan.CAFile,
		ToolVersion:    Version,
		OnRequest: func(e azuredevops.RequestEvent) {
			trace.record(e)
			progress.tick()
		},
		Logf: func(format string, args ...any) {
			logf(cmd, opts, format, args...)
		},
		// Warnings are what the scan could not see. They go only to the
		// verbose channel: every one is repeated in the report's own block.
		Warnf: func(format string, args ...any) {
			emit(cmd, opts, console.Warn, format, args...)
		},
	})
	if err != nil {
		return nil, err
	}

	fetcher := azuredevops.NewFetcher(client, cfg)
	return fetcher.Fetch(ctx, azuredevops.FetchOptions{
		Projects:         opts.projects,
		Repositories:     opts.repositories,
		Concurrency:      opts.scan.Concurrency,
		ToolVersion:      Version,
		Progress:         progress.callback(),
		OnRepositoryDone: trace.repositoryDone,
	})
}

// describeScanFailure names the deadline as the cause when one was set and hit.
func describeScanFailure(ctx context.Context, opts *scanOptions, err error) error {
	if opts.scan.MaxDuration.Get() > 0 && errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return fmt.Errorf("scan abandoned after scan.maxDuration %s: %w\n"+
			"raise or drop scan.maxDuration in the config, or narrow the scan with --project/--repository", opts.scan.MaxDuration.Get(), err)
	}
	return err
}

func readSnapshot(path string) (*scm.Snapshot, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read snapshot %s: %w", path, err)
	}
	return parseSnapshot(raw, "snapshot "+path)
}

// parseSnapshot decodes and sanity-checks snapshot bytes, wherever they came
// from — a file on disk, or the sample compiled into the binary.
func parseSnapshot(raw []byte, source string) (*scm.Snapshot, error) {
	var snapshot scm.Snapshot
	if err := json.Unmarshal(raw, &snapshot); err != nil {
		return nil, fmt.Errorf("parse %s: %w", source, err)
	}
	if snapshot.SchemaVersion != scm.SchemaVersion {
		return nil, fmt.Errorf("%s has schema version %q, but this build reads version %q.\n"+
			"Capture it again with this build: the older shape is missing settings the current "+
			"controls decide on, and evaluating it anyway would report verdicts its data cannot support",
			source, snapshot.SchemaVersion, scm.SchemaVersion)
	}
	if snapshot.Metadata.Platform == "" {
		return nil, fmt.Errorf("%s does not record which platform it came from", source)
	}
	if snapshot.Metadata.Platform != scm.PlatformAzureDevOps {
		// The schema is shared with bitbucket-bench, so a Bitbucket snapshot
		// parses cleanly — and then every control here, written for Azure
		// DevOps, would find nothing to evaluate and report nothing.
		return nil, fmt.Errorf("%s was captured from %q; azure-devops-bench evaluates %q snapshots",
			source, snapshot.Metadata.Platform, scm.PlatformAzureDevOps)
	}
	return &snapshot, nil
}

// staleSnapshotAge is when a replayed snapshot's age line turns into a warning.
const staleSnapshotAge = 24 * time.Hour

func humanAge(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "under a minute"
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	}
}

// writeSnapshot writes a snapshot owner-only and atomically. A snapshot is a
// map of an organization's weak points, and a truncated one re-evaluated
// later would be read as a complete capture.
func writeSnapshot(path string, snapshot *scm.Snapshot) error {
	raw, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return fmt.Errorf("encode snapshot: %w", err)
	}
	return safefile.Write(path, append(raw, '\n'))
}

// useProgressColor decides colour for stderr, which cannot reuse the report's
// decision about stdout.
func useProgressColor(opts *scanOptions, out io.Writer) bool {
	return !opts.noColor && !hasNoColorEnv() && isTerminal(out)
}

func useColor(opts *scanOptions, out io.Writer) bool {
	if opts.noColor || hasNoColorEnv() || opts.format != report.FormatTable {
		return false
	}
	return isTerminal(out)
}

// hasNoColorEnv honours the NO_COLOR convention.
func hasNoColorEnv() bool { return os.Getenv("NO_COLOR") != "" }

// exitStatus turns a report into the process's exit code.
//
// The scan-could-not-complete conditions come first and exit 2, because a CI
// gate reading their 0 or 1 would be reading a verdict about an organization
// the scan did not fully see:
//
//   - a policy that failed to evaluate (a broken tool, not a finding);
//   - no repository evaluated at all (nothing of what this bench audits);
//   - an enumeration that missed a project (unless scan.allowIncomplete).
//
// Then the three thresholds, which answer different questions: are there
// failures this bad (failOn), is the score acceptable (failUnder), and did the
// scan see enough to have an opinion (maxManual).
func exitStatus(rep *engine.Report, opts *scanOptions) error {
	if len(rep.Errors) > 0 {
		return &exitCodeError{
			code: ExitError,
			msg: fmt.Sprintf("%s could not be evaluated; the report is incomplete and its score is not comparable\n%s",
				console.Pluralize(len(rep.Errors), "control"), strings.Join(rep.Errors, "\n")),
		}
	}
	// The engine's count, not the snapshot's: a snapshot whose every
	// repository is disabled evaluates none of them under
	// skipArchivedRepositories, and the report's SARIF and JUnit fail on the
	// same number.
	if rep.Repositories == 0 {
		return &exitCodeError{
			code: ExitError,
			msg: "no repository was evaluated, so nothing was audited: check --project/--repository, " +
				"whether the token can see the repositories you expected, and whether skipArchivedRepositories dropped them",
		}
	}
	if n := len(rep.Metadata.Unlisted); n > 0 && !opts.scan.AllowIncomplete {
		return &exitCodeError{
			code: ExitError,
			msg: fmt.Sprintf("the repositories of %s could not be listed (%s), so the scan is incomplete and they are missing from the report\n"+
				"grant the token read access to them, or set scan.allowIncomplete: true to accept a partial scan",
				console.Pluralize(n, "project"), strings.Join(rep.Metadata.Unlisted, ", ")),
		}
	}

	if opts.scan.MaxManual >= 0 {
		// Only automated controls count: the bundle also ships controls that
		// are MANUAL by design, and counting those would give every scan a
		// manual floor no token could lower.
		unread := 0
		for _, f := range rep.Findings {
			// An accepted MANUAL finding is one somebody has reviewed by hand
			// and recorded as such; it is no longer a gap in what was seen.
			if f.Status == engine.StatusManual && f.Automated && f.Waiver == nil {
				unread++
			}
		}
		decidable := rep.Score.Passed + rep.Score.Failed + unread
		// Cross-multiplied rather than divided, so the comparison is exact.
		if decidable > 0 && unread*100 > opts.scan.MaxManual*decidable {
			return &exitCodeError{
				code: ExitFindings,
				msg: fmt.Sprintf("%d of %d automatable findings needed manual review (scan.maxManual %d%%); the scan could not see enough to judge this organization\n"+
					"grant the token the scopes the scan warnings name, or raise scan.maxManual if this is expected",
					unread, decidable, opts.scan.MaxManual),
			}
		}
	}

	if opts.scan.FailUnder > 0 && rep.Score.Value < opts.scan.FailUnder {
		return &exitCodeError{
			code: ExitFindings,
			msg:  fmt.Sprintf("score %d is below scan.failUnder %d", rep.Score.Value, opts.scan.FailUnder),
		}
	}

	if !strings.EqualFold(opts.scan.FailOn, "none") && rep.HasFailureAtOrAbove(opts.scan.FailOn) {
		return &exitCodeError{
			code: ExitFindings,
			msg:  failureSummary(rep, opts.scan.FailOn),
		}
	}
	return nil
}

// failureSummary describes the failures without inflating them: how many
// controls failed, and across how many findings.
func failureSummary(rep *engine.Report, failOn string) string {
	controls := map[string]bool{}
	failed := 0
	for _, f := range rep.Findings {
		// Accepted failures do not fail the run, so they are not what this
		// line explains.
		if f.Status == engine.StatusFail && f.Waiver == nil {
			controls[f.CheckID] = true
			failed++
		}
	}
	msg := fmt.Sprintf("%s failed", console.Pluralize(len(controls), "control"))
	if failed > len(controls) {
		msg += fmt.Sprintf(" across %s", console.Pluralize(failed, "finding"))
	}
	return msg + fmt.Sprintf(", including at least one at or above %s severity", strings.ToUpper(failOn))
}

func logf(cmd *cobra.Command, opts *scanOptions, format string, args ...any) {
	emit(cmd, opts, console.Info, format, args...)
}

// emit writes one tagged line of narration to stderr. The fetcher calls this
// from the repository goroutines, so the lock covers the whole line.
func emit(cmd *cobra.Command, opts *scanOptions, tag console.Tag, format string, args ...any) {
	if !opts.verbose {
		return
	}
	stderr := cmd.ErrOrStderr()
	w := console.Writer{
		W: stderr,
		P: console.Painter{Enabled: useProgressColor(opts, stderr)},
	}
	opts.logMu.Lock()
	defer opts.logMu.Unlock()
	w.Line(tag, format, args...)
}

// StderrWriter returns a tagged writer for the process's final line.
func StderrWriter() console.Writer {
	return console.Writer{
		W: os.Stderr,
		P: console.Painter{Enabled: isTerminal(os.Stderr) && !hasNoColorEnv()},
	}
}
