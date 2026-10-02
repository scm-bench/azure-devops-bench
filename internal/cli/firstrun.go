package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"

	"github.com/scm-bench/azure-devops-bench/examples"
	"github.com/scm-bench/azure-devops-bench/internal/config"
	"github.com/scm-bench/azure-devops-bench/internal/console"
	"github.com/scm-bench/azure-devops-bench/internal/scm"
)

// This file is what `azure-devops-bench scan` does before it has an organization to scan.
//
// A pipeline with nothing configured gets an error that lists every way out —
// that is errNoInstance. A person at a terminal gets a menu instead, because
// the moment someone runs the tool bare is the one moment they demonstrably do
// not know the flags yet, and an error saying "go configure things" turns away
// exactly the reader who wanted to see what a report looks like.

// demoNotice marks the demo report as example data. It leads the table output,
// because the report's header names an organization and nothing else would say
// the tool made it up.
const demoNotice = "EXAMPLE DATA — this report describes the bundled sample organization, not yours. Pass --url to scan your own."

// demoSnapshot decodes the sample that is compiled into the binary, so the
// demo works for someone who installed a release archive and has no checkout.
func demoSnapshot() (*scm.Snapshot, error) {
	return parseSnapshot(examples.SnapshotJSON, "the bundled example")
}

// errNoInstance is the way out for every path that ends without an
// organization: the non-interactive error, and the menu's quit. It lists all
// three exits rather than naming one flag, because the reader who hits it has
// not chosen between them yet.
func errNoInstance() error {
	return errors.New(`no organization configured: pass --url, or set AZURE_DEVOPS_URL
  scan an organization:    azure-devops-bench scan --url https://dev.azure.com/fabrikam --token "$AZURE_DEVOPS_TOKEN"
  see a sample report:     azure-devops-bench scan --demo
  evaluate a saved file:   azure-devops-bench scan --snapshot-in snapshot.json`)
}

// firstRunResult is what the menu settled on: the demo, or an instance —
// and, for an instance, whether to remember it once it has proven to work.
type firstRunResult struct {
	demo  bool
	url   string
	token string
	save  bool
}

// The menu's options, by index. Entering the credentials is the default
// selection: the menu's job is to get an instance configured, and the demo is
// the detour for the reader who cannot do that yet — a detour should be a
// step away, not the road.
const (
	optCredentials = iota
	optDemo
	optQuit
)

// promptFirstRun offers the choice on out and reads the answer from in. The
// caller has already established that both ends are terminals; a real one gets
// the arrow-key selector, and anything else — including a stdin that merely
// stats like a terminal, such as `scan < /dev/null` — falls through to a
// numbered prompt whose immediate EOF becomes the guided error, not a hang.
func promptFirstRun(in io.Reader, out io.Writer, color bool) (firstRunResult, error) {
	p := console.Painter{Enabled: color}
	w := console.Writer{W: out, P: p}

	w.Line(console.Warn, "no organization configured — scan needs an Azure DevOps URL and a token")
	w.Blank()

	options := []string{
		"enter the URL and token now",
		"show a sample report from the bundled example",
		"quit",
	}

	choice := optQuit
	if f, ok := in.(*os.File); ok && isTerminal(f) {
		c, err := selectWithArrows(f, out, p, options, optCredentials)
		if err != nil {
			// Raw mode was refused; the numbered prompt asks the same question.
			c = selectByNumber(in, out, p, options)
		}
		choice = c
	} else {
		choice = selectByNumber(in, out, p, options)
	}

	switch choice {
	case optCredentials:
		return promptCredentials(in, out)
	case optDemo:
		return firstRunResult{demo: true}, nil
	default:
		return firstRunResult{}, errNoInstance()
	}
}

// menuLine renders one option row. The pointer is the selection signal that
// survives NO_COLOR — colour and weight only reinforce it — and the unselected
// rows keep the same two-column lead so the text does not shift as the pointer
// moves.
func menuLine(p console.Painter, index int, text string, selected bool) string {
	line := fmt.Sprintf("%d. %s", index+1, text)
	if selected {
		return p.Paint(console.Cyan+console.Bold, "❯ "+line)
	}
	return "  " + line
}

// selectWithArrows is the menu a real terminal gets: ↑/↓ (or j/k) move the
// pointer with wrap-around, Enter takes the highlighted option, a digit jumps
// straight to that option, and q or Esc backs out. Returns the chosen index,
// or optQuit for backing out.
//
// The terminal goes raw so single keys arrive without a line buffer in the
// way. Raw mode belongs to the terminal device rather than to one descriptor,
// so output post-processing is off too: every line break written while the
// selector runs must be a literal \r\n.
func selectWithArrows(f *os.File, out io.Writer, p console.Painter, options []string, selected int) (int, error) {
	fd := int(f.Fd())
	oldState, err := term.MakeRaw(fd)
	if err != nil {
		return 0, err
	}
	defer term.Restore(fd, oldState)

	// Parked, the cursor would sit blinking wherever the last redraw left it.
	fmt.Fprint(out, "\033[?25l")
	defer fmt.Fprint(out, "\033[?25h")

	hint := p.Paint(console.Dim, fmt.Sprintf("↑/↓ move · Enter select · 1-%d jump · q quit", len(options)))
	rows := len(options) + 1

	buf := make([]byte, 16)
	for first := true; ; first = false {
		if !first {
			fmt.Fprintf(out, "\033[%dA", rows)
		}
		for i, opt := range options {
			fmt.Fprintf(out, "\r\033[K%s\r\n", menuLine(p, i, opt, i == selected))
		}
		fmt.Fprintf(out, "\r\033[K%s\r\n", hint)

		n, readErr := f.Read(buf)
		if readErr != nil {
			// Nobody on the other end after all: the same exit as q.
			return optQuit, nil
		}
		// Every event in the read is handled, not just the first. A paste, a
		// fast pty, or a held key can deliver "\x1b[B\r" in one read, and
		// taking only the arrow would swallow the Enter behind it.
		for _, key := range decodeMenuKeys(buf[:n]) {
			switch key.kind {
			case keyUp:
				selected = (selected + len(options) - 1) % len(options)
			case keyDown:
				selected = (selected + 1) % len(options)
			case keyEnter:
				return selected, nil
			case keyDigit:
				if key.digit < len(options) {
					return key.digit, nil
				}
			case keyQuit:
				return optQuit, nil
			}
		}
	}
}

// menuKeyKind classifies one key event inside the selector.
type menuKeyKind int

const (
	keyNone menuKeyKind = iota
	keyUp
	keyDown
	keyEnter
	keyDigit
	keyQuit
)

type menuKey struct {
	kind menuKeyKind
	// digit is the option index a typed digit names, when kind is keyDigit.
	digit int
}

// decodeMenuKeys splits one terminal read into key events: three bytes for a
// CSI escape sequence, one for everything else.
func decodeMenuKeys(b []byte) []menuKey {
	var keys []menuKey
	for len(b) > 0 {
		if b[0] == 0x1b && len(b) >= 3 && b[1] == '[' {
			keys = append(keys, decodeMenuKey(b[:3]))
			b = b[3:]
			continue
		}
		keys = append(keys, decodeMenuKey(b[:1]))
		b = b[1:]
	}
	return keys
}

func decodeMenuKey(b []byte) menuKey {
	if len(b) == 0 {
		return menuKey{kind: keyNone}
	}
	switch b[0] {
	case '\r', '\n':
		return menuKey{kind: keyEnter}
	case 'q', 0x03, 0x04: // q, Ctrl-C, Ctrl-D
		return menuKey{kind: keyQuit}
	case 'k':
		return menuKey{kind: keyUp}
	case 'j':
		return menuKey{kind: keyDown}
	case 0x1b:
		if len(b) >= 3 && b[1] == '[' {
			switch b[2] {
			case 'A':
				return menuKey{kind: keyUp}
			case 'B':
				return menuKey{kind: keyDown}
			}
			// Some other CSI sequence — a right arrow, a function key.
			return menuKey{kind: keyNone}
		}
		// Esc on its own.
		return menuKey{kind: keyQuit}
	}
	if b[0] >= '1' && b[0] <= '9' {
		return menuKey{kind: keyDigit, digit: int(b[0] - '1')}
	}
	return menuKey{kind: keyNone}
}

// selectByNumber is the same question asked without a terminal to draw on:
// numbered options, one typed answer. Enter alone lands on entering the
// credentials, so both selectors keep one default.
func selectByNumber(in io.Reader, out io.Writer, p console.Painter, options []string) int {
	for i, opt := range options {
		fmt.Fprintf(out, "%s\n", menuLine(p, i, opt, false))
	}
	fmt.Fprintln(out)

	// Three attempts, then the error. An unattended loop on a stdin that keeps
	// producing garbage would spin forever asking a question nobody is there
	// to answer.
	for attempt := 0; attempt < 3; attempt++ {
		fmt.Fprintf(out, "choose [1/2/3] (Enter = 1): ")
		choice, err := readLine(in)
		if err != nil {
			// EOF: nobody is on the other end after all.
			fmt.Fprintln(out)
			return optQuit
		}
		switch strings.TrimSpace(choice) {
		case "", "1":
			return optCredentials
		case "2":
			return optDemo
		case "3", "q":
			return optQuit
		}
	}
	return optQuit
}

func promptCredentials(in io.Reader, out io.Writer) (firstRunResult, error) {
	fmt.Fprintf(out, "Organization URL (e.g. https://dev.azure.com/fabrikam): ")
	url, err := readLine(in)
	if err != nil {
		fmt.Fprintln(out)
		return firstRunResult{}, errNoInstance()
	}
	url = strings.TrimSpace(url)
	if url == "" {
		return firstRunResult{}, errNoInstance()
	}

	fmt.Fprintf(out, "Personal access token or Entra access token (hidden): ")
	token, err := readSecret(in, out)
	if err != nil {
		fmt.Fprintln(out)
		return firstRunResult{}, errNoInstance()
	}
	token = strings.TrimSpace(token)
	if token == "" {
		// The client refuses to run without a credential, so promising an
		// anonymous scan here would dead-end two lines later with an error
		// about flags this person never typed.
		fmt.Fprintln(out, "A token is required: create one at User settings -> Personal access tokens (scopes vso.project and vso.code at least), or use `az account get-access-token --resource 499b84ac-1321-427f-aa17-267ca6975798`.")
		return firstRunResult{}, errNoInstance()
	}

	res := firstRunResult{url: url, token: token}

	// Saving is asked, not assumed: the answer puts a credential on disk. The
	// prompt names the destination so the consent is to something concrete,
	// and the file is only written after the scan proves the credential works
	// — remembering a typo would replay it on every following run.
	if path, err := config.InstancePath(); err == nil {
		fmt.Fprintf(out, "save for future scans? (stored 0600 at %s) [Y/n]: ", path)
		answer, err := readLine(in)
		if err != nil {
			fmt.Fprintln(out)
			// The URL and token were already given; losing them over the
			// follow-up question would be spite. Scan, just don't remember.
			return res, nil
		}
		switch strings.ToLower(strings.TrimSpace(answer)) {
		case "", "y", "yes":
			res.save = true
		}
	}
	return res, nil
}

// readSecret reads the token without echoing it when in is a real terminal.
// This is what golang.org/x/term was finally added for: the two places that
// declined it before needed one boolean and one integer, but a credential
// echoed onto a terminal ends up in scrollback and screen recordings, and
// that is not a trade a security tool gets to make.
func readSecret(in io.Reader, out io.Writer) (string, error) {
	if f, ok := in.(*os.File); ok && isTerminal(f) {
		raw, err := term.ReadPassword(int(f.Fd()))
		// The Enter that submitted the secret was swallowed with it.
		fmt.Fprintln(out)
		if err != nil {
			return "", err
		}
		return string(raw), nil
	}
	return readLine(in)
}

// readLine reads one line, one byte at a time. Deliberately unbuffered: a
// bufio.Reader can read ahead past the newline, and the very next read here
// may be term.ReadPassword going straight to the file descriptor — anything
// sitting in a buffer at that moment would be input the prompt silently lost.
func readLine(in io.Reader) (string, error) {
	var line []byte
	buf := make([]byte, 1)
	for {
		n, err := in.Read(buf)
		if n > 0 {
			if buf[0] == '\n' {
				return strings.TrimRight(string(line), "\r"), nil
			}
			line = append(line, buf[0])
		}
		if err != nil {
			if errors.Is(err, io.EOF) && len(line) > 0 {
				return string(line), nil
			}
			return "", err
		}
	}
}
