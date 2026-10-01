package cli

import (
	"bytes"
	"context"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/scm-bench/azure-devops-bench/internal/config"
)

// A redirected stream has no cursor to move, so carriage returns would pile up
// as thousands of lines in a CI log. Nothing should be written at all.
func TestProgressIsSuppressedWhenNotATerminal(t *testing.T) {
	var buf bytes.Buffer
	if p := newProgressWriter(&buf, true); p != nil {
		t.Error("a non-terminal writer should get no progress")
	}
	// A pipe is the shape a redirect actually takes.
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	defer r.Close()
	defer w.Close()
	if p := newProgressWriter(w, true); p != nil {
		t.Error("a pipe should get no progress")
	}
}

func TestProgressDisabledReturnsNothing(t *testing.T) {
	if p := newProgressWriter(os.Stderr, false); p != nil {
		t.Error("progress was disabled but a writer was returned")
	}
}

// The nil writer is the normal case for a redirected run, so every method has
// to tolerate it rather than the caller having to check.
func TestNilProgressWriterIsInert(t *testing.T) {
	var p *progressWriter
	p.start()
	p.tick()
	p.update("something")
	p.clear()
	if cb := p.callback(); cb != nil {
		t.Error("a nil writer should report no callback, so the fetcher can skip formatting")
	}
}

func TestProgressOverwritesInPlace(t *testing.T) {
	var buf bytes.Buffer
	p := &progressWriter{out: &buf}

	p.update("scanning 1/10 repositories")
	p.update("scanning 2/10")

	out := buf.String()
	if strings.Contains(out, "\n") {
		t.Errorf("progress must stay on one line, got %q", out)
	}
	if n := strings.Count(out, "\r"); n != 2 {
		t.Errorf("expected one carriage return per update, got %d in %q", n, out)
	}
	// The shorter second line has to blank the tail of the first, or "1/10
	// repositories" would leave "repositories" stranded on the line.
	if !strings.HasSuffix(out, strings.Repeat(" ", len("scanning 1/10 repositories")-len("scanning 2/10"))) {
		t.Errorf("a shorter update did not pad over the previous line: %q", out)
	}
}

func TestProgressClearLeavesTheLineBlank(t *testing.T) {
	var buf bytes.Buffer
	p := &progressWriter{out: &buf}

	p.update("scanning 1/10")
	buf.Reset()
	p.clear()

	out := buf.String()
	if !strings.HasPrefix(out, "\r") || !strings.HasSuffix(out, "\r") {
		t.Errorf("clear should return the cursor before and after blanking, got %q", out)
	}
	if strings.TrimSpace(strings.ReplaceAll(out, "\r", "")) != "" {
		t.Errorf("clear should write only blanks, got %q", out)
	}
	// Clearing twice must not blank a line that is already gone.
	buf.Reset()
	p.clear()
	if buf.Len() != 0 {
		t.Errorf("a second clear wrote %q", buf.String())
	}
}

// The fetcher calls update from every repository goroutine.
func TestProgressIsSafeForConcurrentUse(t *testing.T) {
	p := &progressWriter{out: &bytes.Buffer{}}

	var wg sync.WaitGroup
	for i := range 50 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			p.update(strings.Repeat("x", i%20))
		}(i)
	}
	wg.Wait()
}

// A deadline the operator set should be named as the cause. The bare error is
// whichever request happened to be in flight, which reads as a network fault.
func TestScanFailureNamesTheDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	<-ctx.Done()

	opts := &scanOptions{scan: config.Scan{MaxDuration: config.Duration(5 * time.Minute)}}
	err := describeScanFailure(ctx, opts, context.DeadlineExceeded)
	if err == nil || !strings.Contains(err.Error(), "scan.maxDuration 5m0s") {
		t.Errorf("error = %v, want it to name the deadline", err)
	}

	// Without a deadline set, the original error must pass through untouched:
	// blaming a limit nobody configured would be worse than saying nothing.
	noDeadline := &scanOptions{}
	original := context.DeadlineExceeded
	if got := describeScanFailure(ctx, noDeadline, original); got != original {
		t.Errorf("error = %v, want the original error unchanged", got)
	}
}

// The status line pads to the previous width so a shorter line cannot leave
// the tail of a longer one behind it. Width in runes: a project or repository
// name outside ASCII — which an instance is free to have — made len() count
// three bytes per character, so the padding overshot by twice the name's
// length and wrapped onto the next row instead of overwriting.
func TestProgressPadsByDisplayWidthNotBytes(t *testing.T) {
	var buf bytes.Buffer
	p := &progressWriter{out: &buf}

	long := "scanning · 平台工程/支付服务 12/40 repositories"
	p.update(long)
	buf.Reset()
	p.update("done")

	// The rendered line carries the spinner prefix, so the expected padding is
	// the rune difference between the two full renders.
	out := buf.String()
	rendered := progressLine(spinnerFrame(0), "done", 0)
	padding := utf8.RuneCountInString(out) - 1 - utf8.RuneCountInString(rendered) // 1 for the \r
	want := utf8.RuneCountInString(progressLine(spinnerFrame(0), long, 0)) - utf8.RuneCountInString(rendered)
	if padding != want {
		t.Errorf("padded %d columns, want %d: byte length over-counts multi-byte runes", padding, want)
	}
}

// The rotor and the request counter are what make a silent phase legible: the
// line exists from the first moment, and the number keeps moving even while
// the phase text does not.
func TestProgressLineCarriesSpinnerAndRequestCount(t *testing.T) {
	if got, want := progressLine('|', "scanning", 0), "| scanning"; got != want {
		t.Errorf("progressLine = %q, want %q (no counter before the first request)", got, want)
	}
	if got, want := progressLine('/', "scanning · PRJ 1/4 repositories", 37), "/ scanning · PRJ 1/4 repositories · 37 requests"; got != want {
		t.Errorf("progressLine = %q, want %q", got, want)
	}
	// Four frames, then round again.
	frames := ""
	for i := range 5 {
		frames += string(spinnerFrame(i))
	}
	if frames != `|/-\|` {
		t.Errorf("spinner frames = %q", frames)
	}
}

// start draws immediately — the point is that something is visible before the
// first repository completes — and clear stops the ticker and erases.
func TestProgressStartDrawsImmediatelyAndClearStops(t *testing.T) {
	var buf syncBuffer
	p := &progressWriter{out: &buf}

	p.start()
	if !strings.Contains(buf.String(), "scanning") {
		t.Errorf("start did not draw: %q", buf.String())
	}
	p.tick()
	p.clear()
	if out := buf.String(); !strings.HasSuffix(out, "\r") {
		t.Errorf("clear should end having blanked the line, got %q", out)
	}
	// Idempotent: a second clear after the ticker is gone must not hang or write.
	before := buf.String()
	p.clear()
	if buf.String() != before {
		t.Error("a second clear wrote output")
	}
}

// syncBuffer is a bytes.Buffer safe for the ticker goroutine and the test to
// share.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// os.DevNull is a character device, so `azure-devops-bench scan > /dev/null` looked like
// a terminal: colour escapes went into output that had been explicitly thrown
// away, and the compact progress line drew carriage returns at a destination
// with no cursor.
func TestDevNullIsNotATerminal(t *testing.T) {
	devnull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Skipf("cannot open %s: %v", os.DevNull, err)
	}
	t.Cleanup(func() { devnull.Close() })

	if isTerminal(devnull) {
		t.Errorf("isTerminal(%s) = true", os.DevNull)
	}
}
