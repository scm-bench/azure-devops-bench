package cli

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/scm-bench/azure-devops-bench/internal/console"
)

// The demo exists for the reader who has not configured anything yet, so it
// must work from a bare binary: no instance, no checkout, no flags beyond the
// one. It evaluates the same sample TestBundledSnapshotStillEvaluates covers
// from disk — this test is about the embedded copy reaching the same result.
func TestDemoEvaluatesTheBundledExample(t *testing.T) {
	stdout, stderr, code := run(t, "scan", "--demo", "-o", "json", "-c", configWithFailOn(t, "none"))

	if code != ExitOK {
		t.Fatalf("exit code = %d, want %d\n%s", code, ExitOK, stderr)
	}

	var rep struct {
		Metadata struct {
			Platform string `json:"platform"`
		} `json:"metadata"`
		Findings []struct {
			Status string `json:"status"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(stdout), &rep); err != nil {
		t.Fatalf("decode report: %v", err)
	}
	if rep.Metadata.Platform == "" {
		t.Error("the embedded sample does not record its platform")
	}
	if len(rep.Findings) == 0 {
		t.Fatal("the demo produced no findings, so it demonstrates nothing")
	}

	// The stderr line is what stays on the terminal when stdout is redirected.
	if !strings.Contains(stderr, "bundled example") {
		t.Errorf("stderr never says the scan was a demo:\n%s", stderr)
	}
}

// The table report must say it is example data where the eye lands first. The
// header names dev.azure.com/fabrikam, but nothing else would say the tool made
// that instance up.
func TestDemoTableIsMarkedAsExampleData(t *testing.T) {
	stdout, _, _ := run(t, "scan", "--demo", "-c", configWithFailOn(t, "none"))

	if !strings.Contains(stdout, "EXAMPLE DATA") {
		t.Errorf("table output carries no example-data banner:\n%s", stdout)
	}
}

// A real report must never carry the banner: it is the one line that tells a
// reader to discount everything below it.
func TestRealScanCarriesNoExampleBanner(t *testing.T) {
	fixture := writeSnapshotFixture(t)
	stdout, _, _ := run(t, "scan", "--snapshot-in", fixture, "-c", configWithFailOn(t, "none"))

	if strings.Contains(stdout, "EXAMPLE DATA") {
		t.Error("a snapshot scan was marked as example data")
	}
}

// The demo demonstrates the whole contract, exit code included: the sample
// carries HIGH failures, so under the default --fail-on high it exits 1
// exactly as a real scan of that instance would.
func TestDemoHonoursTheExitCodeContract(t *testing.T) {
	if _, _, code := run(t, "scan", "--demo"); code != ExitFindings {
		t.Errorf("exit code = %d, want %d for the sample's HIGH failures", code, ExitFindings)
	}
}

// A typed flag the demo would silently ignore is refused — the same rule
// --snapshot-in already applies to --project. Values merely inherited from the
// environment are not typed, and must not make the demo argue.
func TestDemoRejectsFlagsItWouldIgnore(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"url", []string{"scan", "--demo", "--url", "https://example.invalid"}},
		{"token", []string{"scan", "--demo", "--token", "t"}},
		{"project", []string{"scan", "--demo", "-p", "PRJ"}},
		{"repository", []string{"scan", "--demo", "-r", "PRJ/app"}},
		{"snapshot-in", []string{"scan", "--demo", "--snapshot-in", "x.json"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, code := run(t, tc.args...); code != ExitError {
				t.Errorf("exit code = %d, want %d", code, ExitError)
			}
		})
	}
}

func TestDemoIgnoresInheritedCredentials(t *testing.T) {
	t.Setenv("AZURE_DEVOPS_URL", "https://stale.example.com")
	t.Setenv("AZURE_DEVOPS_TOKEN", "stale")

	stdout, _, code := run(t, "scan", "--demo", "-o", "json", "-c", configWithFailOn(t, "none"))
	if code != ExitOK {
		t.Fatalf("exit code = %d; an exported AZURE_DEVOPS_URL must not break the demo", code)
	}
	if strings.Contains(stdout, "stale.example.com") {
		t.Error("the environment's URL leaked into the demo report")
	}
}

// The error a pipeline gets with nothing configured has to list every way
// out, the demo included: it is the reader's first contact with the tool, and
// "a flag is required" teaches less than showing the three exits.
func TestMissingInstanceErrorListsEveryWayOut(t *testing.T) {
	t.Setenv("AZURE_DEVOPS_URL", "")

	root := NewRootCommand()
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	root.SetIn(strings.NewReader(""))
	root.SetArgs([]string{"scan"})

	err := root.Execute()
	if err == nil {
		t.Fatal("scan with nothing configured succeeded")
	}
	for _, want := range []string{"--url", "AZURE_DEVOPS_URL", "--demo", "--snapshot-in"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error never mentions %s:\n%s", want, err)
		}
	}
}

// Enter alone lands on entering the credentials: the menu's job is to get an
// instance configured, and the default has to be the main road, not the
// detour.
func TestFirstRunPromptDefaultsToEnteringCredentials(t *testing.T) {
	var out bytes.Buffer
	res, err := promptFirstRun(
		strings.NewReader("\nhttps://dev.azure.com/fabrikam\nsekrit\nn\n"), &out, false)
	if err != nil {
		t.Fatalf("prompt: %v", err)
	}
	if res.demo {
		t.Error("Enter landed on the demo instead of the credentials")
	}
	if res.url != "https://dev.azure.com/fabrikam" {
		t.Errorf("url = %q", res.url)
	}
	// The menu must show all three exits before asking.
	for _, want := range []string{"1.", "2.", "3.", "no organization configured"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("menu is missing %q:\n%s", want, out.String())
		}
	}
	if strings.Contains(out.String(), "\033[") {
		t.Error("ANSI escapes with colour disabled")
	}
}

func TestFirstRunPromptCollectsCredentials(t *testing.T) {
	for name, tc := range map[string]struct {
		saveAnswer string
		wantSave   bool
	}{
		// Enter defaults to yes: the reader who typed a URL and token is
		// exactly the one who does not want to type them again.
		"enter saves":  {"\n", true},
		"yes saves":    {"y\n", true},
		"no does not":  {"n\n", false},
		"eof does not": {"", false},
	} {
		t.Run(name, func(t *testing.T) {
			var out bytes.Buffer
			res, err := promptFirstRun(
				strings.NewReader("1\nhttps://dev.azure.com/fabrikam\nsekrit\n"+tc.saveAnswer), &out, false)
			if err != nil {
				t.Fatalf("prompt: %v", err)
			}
			if res.demo {
				t.Error("choice 1 landed on the demo")
			}
			if res.url != "https://dev.azure.com/fabrikam" {
				t.Errorf("url = %q", res.url)
			}
			if res.token != "sekrit" {
				t.Errorf("token = %q", res.token)
			}
			if res.save != tc.wantSave {
				t.Errorf("save = %v, want %v", res.save, tc.wantSave)
			}
			// Consent must be informed: the question names the destination.
			if !strings.Contains(out.String(), "instance.yaml") {
				t.Errorf("the save question never names the file:\n%s", out.String())
			}
		})
	}
}

// writeSavedInstance stages a saved instance in a private config dir, the way
// an earlier run's menu would have left it.
func writeSavedInstance(t *testing.T, yaml string) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("AZURE_DEVOPS_BENCH_CONFIG_DIR", dir)
	if err := os.WriteFile(filepath.Join(dir, "instance.yaml"), []byte(yaml), 0o600); err != nil {
		t.Fatalf("write instance: %v", err)
	}
}

// The feature itself: a URL saved by an earlier run answers the next scan
// without a menu and without a flag. The scan then fails on the unreachable
// address — under a --max-duration so the client's transport retries cannot
// slow the suite — but by then it has already said whose credentials it took.
func TestScanUsesTheSavedInstance(t *testing.T) {
	writeSavedInstance(t, "url: https://127.0.0.1:1\ntoken: saved\n")

	_, stderr, code := run(t, "scan", "-c", configWithScan(t, "maxDuration: 1ms"))
	if code != ExitError {
		t.Fatalf("exit code = %d, want %d for an unreachable saved instance", code, ExitError)
	}
	if !strings.Contains(stderr, "using saved organization https://127.0.0.1:1") {
		t.Errorf("stderr never says where the URL came from:\n%s", stderr)
	}
}

// A typed flag or an exported variable always beats the file: saved is the
// answer of last resort, not a preference.
func TestSavedInstanceYieldsToExplicitConfiguration(t *testing.T) {
	writeSavedInstance(t, "url: https://127.0.0.1:1\ntoken: saved\n")

	_, stderr, _ := run(t, "scan", "--url", "https://127.0.0.1:2", "-c", configWithScan(t, "maxDuration: 1ms"))
	if strings.Contains(stderr, "using saved instance") {
		t.Errorf("a typed --url was overridden by the file:\n%s", stderr)
	}
}

// The demo evaluates nothing on any instance, saved or otherwise.
func TestSavedInstanceDoesNotTouchTheDemo(t *testing.T) {
	writeSavedInstance(t, "url: https://127.0.0.1:1\ntoken: saved\n")

	_, stderr, code := run(t, "scan", "--demo", "-o", "json", "-c", configWithFailOn(t, "none"))
	if code != ExitOK {
		t.Fatalf("exit code = %d", code)
	}
	if strings.Contains(stderr, "using saved instance") {
		t.Errorf("the demo consulted the saved instance:\n%s", stderr)
	}
}

// A saved file that cannot be understood stops the scan rather than shrugging
// into an anonymous one — same contract as a broken --config.
func TestScanRefusesACorruptSavedInstance(t *testing.T) {
	writeSavedInstance(t, "url: https://127.0.0.1:1\ntokn: oops\n")

	if _, _, code := run(t, "scan"); code != ExitError {
		t.Errorf("exit code = %d, want %d for a corrupt saved instance", code, ExitError)
	}
}

// An empty URL after choosing to enter one is the reader changing their mind,
// not a scan of nowhere.
func TestFirstRunPromptRejectsAnEmptyURL(t *testing.T) {
	var out bytes.Buffer
	if _, err := promptFirstRun(strings.NewReader("1\n\n"), &out, false); err == nil {
		t.Error("an empty URL was accepted")
	}
}

// Quitting, by choice or by EOF, gets the same guided error the
// non-interactive path prints — the menu must not know an exit the pipeline
// does not.
func TestFirstRunPromptQuitPathsCarryTheGuidedError(t *testing.T) {
	for name, input := range map[string]string{
		"choice 3":      "3\n",
		"eof":           "",
		"three retries": "x\ny\nz\n",
	} {
		t.Run(name, func(t *testing.T) {
			var out bytes.Buffer
			_, err := promptFirstRun(strings.NewReader(input), &out, false)
			if err == nil {
				t.Fatal("quit did not error")
			}
			if !strings.Contains(err.Error(), "--demo") {
				t.Errorf("quit error does not guide: %v", err)
			}
		})
	}
}

// The selector's key decoding is pure, so the arrow-key behaviour is testable
// without a pty: this is the contract between what a terminal sends and what
// the pointer does.
func TestDecodeMenuKeys(t *testing.T) {
	for name, tc := range map[string]struct {
		input string
		want  []menuKeyKind
	}{
		"up arrow":          {"\x1b[A", []menuKeyKind{keyUp}},
		"down arrow":        {"\x1b[B", []menuKeyKind{keyDown}},
		"vim up":            {"k", []menuKeyKind{keyUp}},
		"vim down":          {"j", []menuKeyKind{keyDown}},
		"enter":             {"\r", []menuKeyKind{keyEnter}},
		"newline":           {"\n", []menuKeyKind{keyEnter}},
		"quit":              {"q", []menuKeyKind{keyQuit}},
		"ctrl-c":            {"\x03", []menuKeyKind{keyQuit}},
		"bare esc":          {"\x1b", []menuKeyKind{keyQuit}},
		"right arrow idles": {"\x1b[C", []menuKeyKind{keyNone}},
		"stray letter":      {"x", []menuKeyKind{keyNone}},
		// One read can carry several events — a paste, a fast pty. Taking
		// only the first would swallow the Enter behind the arrow.
		"arrow then enter": {"\x1b[B\r", []menuKeyKind{keyDown, keyEnter}},
	} {
		t.Run(name, func(t *testing.T) {
			keys := decodeMenuKeys([]byte(tc.input))
			if len(keys) != len(tc.want) {
				t.Fatalf("decoded %d events, want %d", len(keys), len(tc.want))
			}
			for i, k := range keys {
				if k.kind != tc.want[i] {
					t.Errorf("event %d = kind %d, want %d", i, k.kind, tc.want[i])
				}
			}
		})
	}
}

func TestDecodeMenuKeysMapsDigitsToOptions(t *testing.T) {
	keys := decodeMenuKeys([]byte("2"))
	if len(keys) != 1 || keys[0].kind != keyDigit || keys[0].digit != 1 {
		t.Errorf("typing 2 decoded to %+v, want the second option", keys)
	}
}

// The pointer is the selection signal that has to survive NO_COLOR; colour
// only reinforces it.
func TestMenuLineMarksTheSelection(t *testing.T) {
	plain := console.Painter{Enabled: false}

	selected := menuLine(plain, 1, "show a sample report", true)
	if !strings.Contains(selected, "❯") {
		t.Errorf("selected line carries no pointer: %q", selected)
	}
	unselected := menuLine(plain, 0, "enter the URL", false)
	if strings.Contains(unselected, "❯") {
		t.Errorf("unselected line carries a pointer: %q", unselected)
	}
	if !strings.HasPrefix(unselected, "  1. ") {
		t.Errorf("unselected line lost its column alignment: %q", unselected)
	}
	for _, l := range []string{selected, unselected} {
		if strings.Contains(l, "\033[") {
			t.Errorf("ANSI escapes with colour disabled: %q", l)
		}
	}
}

// readLine feeds a prompt that may hand the very next read to
// term.ReadPassword on the raw descriptor, so it must consume exactly one
// line — buffering past the newline would be input silently lost.
func TestReadLineConsumesExactlyOneLine(t *testing.T) {
	in := strings.NewReader("first\r\nsecond\n")

	got, err := readLine(in)
	if err != nil || got != "first" {
		t.Fatalf("readLine = %q, %v", got, err)
	}
	rest, _ := io.ReadAll(in)
	if string(rest) != "second\n" {
		t.Errorf("readLine read ahead; %q was left", rest)
	}
}
