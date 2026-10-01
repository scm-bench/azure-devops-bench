package cli

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"
)

// progressWriter renders a single self-overwriting status line on stderr.
//
// It is deliberately only used when stderr is a terminal. A redirected stream
// has no cursor to move, so carriage returns would accumulate as thousands of
// lines in a CI log — the opposite of the point. In that case there is no
// writer at all and the fetcher's callback is nil, so nothing is formatted
// either.
type progressWriter struct {
	out io.Writer

	// requests counts completed HTTP requests, fed by the client's OnRequest
	// hook. Atomic rather than under mu because it is bumped from every
	// repository goroutine on every request.
	requests atomic.Int64

	mu    sync.Mutex
	last  int
	text  string
	frame int

	stop chan struct{}
	done chan struct{}
}

// spinnerFrames is the classic four-frame rotor. ASCII on purpose: this line
// goes to whatever terminal is attached, and a spinner that renders as boxes
// is worse than none.
const spinnerFrames = `|/-\`

// spinnerInterval is how often the rotor turns on its own. Time-driven rather
// than request-driven, so it keeps moving through a slow request — which is
// exactly the moment a person starts wondering whether the scan is stuck.
const spinnerInterval = 120 * time.Millisecond

// newProgressWriter returns a writer for stderr, or nil when progress should
// not be shown: not a terminal, explicitly disabled, or superseded by the
// per-repository logging that --verbose already prints.
func newProgressWriter(out io.Writer, enabled bool) *progressWriter {
	if !enabled || !isTerminal(out) {
		return nil
	}
	return &progressWriter{out: out}
}

// start begins the spinner: the status line appears immediately and the rotor
// turns on a timer until clear.
//
// It exists because the fetcher's progress callback fires only when a whole
// repository has been fetched, and everything before the first one — the
// credential check, the global permissions, the user directory, the project
// listing — is sequential and used to be silent. A person watching a blinking
// cursor for that long has no way to tell a slow instance from a hung one.
func (p *progressWriter) start() {
	if p == nil {
		return
	}
	p.mu.Lock()
	if p.stop != nil {
		p.mu.Unlock()
		return
	}
	// Captured as locals: clear nils the fields before closing, so the
	// goroutine must not read them back through p.
	stop := make(chan struct{})
	done := make(chan struct{})
	p.stop, p.done = stop, done
	p.text = "scanning"
	p.redrawLocked()
	p.mu.Unlock()

	go func() {
		ticker := time.NewTicker(spinnerInterval)
		defer ticker.Stop()
		defer close(done)
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				p.mu.Lock()
				p.frame++
				p.redrawLocked()
				p.mu.Unlock()
			}
		}
	}()
}

// tick records one completed request. The redraw is left to the ticker: a
// large instance completes requests far faster than a terminal is worth
// repainting.
func (p *progressWriter) tick() {
	if p == nil {
		return
	}
	p.requests.Add(1)
}

// update replaces the status text. Safe for concurrent use: the fetcher calls
// this from every repository goroutine.
func (p *progressWriter) update(text string) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.text = text
	p.redrawLocked()
}

// redrawLocked repaints the line. Callers hold p.mu.
func (p *progressWriter) redrawLocked() {
	line := progressLine(spinnerFrame(p.frame), p.text, p.requests.Load())

	// Pad to the previous width so a shorter line cannot leave the tail of a
	// longer one behind it.
	//
	// Width in runes, not bytes. A repository or project name outside ASCII —
	// which an Azure DevOps organization is perfectly free to have — made len() count
	// three bytes per character, so the padding overshot by twice the name's
	// length and wrapped the status line onto the next row instead of
	// overwriting it.
	width := utf8.RuneCountInString(line)
	padding := ""
	if trailing := p.last - width; trailing > 0 {
		padding = strings.Repeat(" ", trailing)
	}
	fmt.Fprintf(p.out, "\r%s%s", line, padding)
	p.last = width
}

// spinnerFrame maps a tick count onto the rotor.
func spinnerFrame(n int) byte {
	return spinnerFrames[n%len(spinnerFrames)]
}

// progressLine is the whole status line: rotor, phase, and how many requests
// have completed — the number that keeps moving even while the phase text
// does not.
func progressLine(frame byte, text string, requests int64) string {
	if requests == 0 {
		return fmt.Sprintf("%c %s", frame, text)
	}
	return fmt.Sprintf("%c %s · %d requests", frame, text, requests)
}

// clear stops the spinner and erases the status line, so the report does not
// begin on a line that still holds a half-finished count.
func (p *progressWriter) clear() {
	if p == nil {
		return
	}
	p.mu.Lock()
	stop, done := p.stop, p.done
	p.stop, p.done = nil, nil
	p.mu.Unlock()
	if stop != nil {
		close(stop)
		<-done // no draws after the erase below
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	if p.last > 0 {
		fmt.Fprintf(p.out, "\r%s\r", strings.Repeat(" ", p.last))
		p.last = 0
	}
}

// callback adapts the writer to what the fetcher expects, returning nil when
// there is no writer so the fetcher can skip formatting entirely.
func (p *progressWriter) callback() func(string) {
	if p == nil {
		return nil
	}
	return p.update
}

// isTerminal reports whether w is a character device, which is the same test
// used to decide on colour.
//
// os.DevNull is excluded by name because it is a character device too, so
// `azure-devops-bench scan > /dev/null` looked like a terminal: colour escapes were
// written into output that had been explicitly thrown away, and the compact
// progress line drew carriage returns at a destination with no cursor. It
// stays a hand-rolled check even though golang.org/x/term is now a dependency
// (the first-run prompt reads the token through it, unechoed): term.IsTerminal
// answers for a file descriptor rather than an io.Writer, and it has no
// opinion about /dev/null.
func isTerminal(w io.Writer) bool {
	file, ok := w.(*os.File)
	if !ok {
		return false
	}
	if file.Name() == os.DevNull {
		return false
	}
	info, err := file.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}
