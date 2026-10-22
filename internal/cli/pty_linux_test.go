//go:build linux

package cli

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// terminal is a pseudo-terminal with a scripted person at the far end: the
// slave is what the code under test reads and writes, the master is the
// keyboard and the screen.
type terminal struct {
	t      *testing.T
	master *os.File
	slave  *os.File
	screen syncBuffer
	seen   int
}

func openTerminal(t *testing.T) *terminal {
	t.Helper()
	m, err := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Skipf("no pseudo-terminal available: %v", err)
	}
	// The ioctls go through the raw connection rather than m.Fd(), which
	// would switch the master to blocking mode — and a blocking descriptor
	// is not really closed while the reader below is parked in Read, so the
	// hang-up test would never hang up.
	rc, err := m.SyscallConn()
	if err != nil {
		m.Close()
		t.Skipf("no raw access to the pseudo-terminal: %v", err)
	}
	var n int
	var ioctlErr error
	if err := rc.Control(func(fd uintptr) {
		if ioctlErr = unix.IoctlSetPointerInt(int(fd), unix.TIOCSPTLCK, 0); ioctlErr == nil {
			n, ioctlErr = unix.IoctlGetInt(int(fd), unix.TIOCGPTN)
		}
	}); err != nil || ioctlErr != nil {
		m.Close()
		t.Skipf("cannot set up the pseudo-terminal: %v %v", err, ioctlErr)
	}
	s, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", n), os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		m.Close()
		t.Skipf("cannot open the pseudo-terminal: %v", err)
	}
	term := &terminal{t: t, master: m, slave: s}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 4096)
		for {
			n, err := m.Read(buf)
			term.screen.Write(buf[:n])
			if err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() {
		s.Close()
		m.Close()
		wg.Wait()
	})
	return term
}

// await blocks until text appears on the screen after whatever the previous
// await matched.
func (p *terminal) await(text string) {
	p.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		screen := p.screen.String()
		if i := strings.Index(screen[p.seen:], text); i >= 0 {
			p.seen += i + len(text)
			return
		}
		if time.Now().After(deadline) {
			p.t.Fatalf("never saw %q on the screen:\n%q", text, screen)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func (p *terminal) send(keys string) {
	p.t.Helper()
	if _, err := p.master.Write([]byte(keys)); err != nil {
		p.t.Fatalf("type %q: %v", keys, err)
	}
}

type promptOutcome struct {
	res firstRunResult
	err error
}

func (p *terminal) prompt() <-chan promptOutcome {
	done := make(chan promptOutcome, 1)
	go func() {
		res, err := promptFirstRun(p.slave, p.slave, true)
		done <- promptOutcome{res, err}
	}()
	return done
}

func (p *terminal) outcome(done <-chan promptOutcome) promptOutcome {
	p.t.Helper()
	select {
	case o := <-done:
		return o
	case <-time.After(10 * time.Second):
		p.t.Fatalf("the prompt never returned:\n%q", p.screen.String())
		return promptOutcome{}
	}
}

// The arrow-key menu on a real terminal: every key it knows moves the pointer
// with wrap-around, keys it does not know do nothing, and the credential
// questions that follow read the token without echoing it.
func TestArrowMenuOnATerminal(t *testing.T) {
	term := openTerminal(t)
	done := term.prompt()

	term.await("q quit")
	term.send("j") // down to the demo
	term.await("\033[4A")
	// k: up to the credentials; ↑: wraps to quit; ↓: wraps back; 9: no such
	// option; x and → mean nothing; Enter takes the credentials.
	term.send("k\033[A\033[B9x\033[C\r")
	term.await("Organization URL")
	term.send("https://dev.azure.com/fabrikam\n")
	term.await("(hidden)")
	term.send("sekrit\n")
	term.await("[Y/n]")
	term.send("n\n")

	o := term.outcome(done)
	if o.err != nil {
		t.Fatalf("prompt: %v", o.err)
	}
	if o.res.url != "https://dev.azure.com/fabrikam" || o.res.token != "sekrit" || o.res.save || o.res.demo {
		t.Errorf("result = %+v", o.res)
	}
}

func TestArrowMenuDigitsAndQuitting(t *testing.T) {
	for name, tc := range map[string]struct {
		keys     string
		wantDemo bool
	}{
		"a digit jumps": {"2", true},
		"q backs out":   {"q", false},
		"Esc backs out": {"\033", false},
		"Ctrl-C too":    {"\x03", false},
	} {
		t.Run(name, func(t *testing.T) {
			term := openTerminal(t)
			done := term.prompt()
			term.await("q quit")
			term.send(tc.keys)
			o := term.outcome(done)
			if tc.wantDemo {
				if o.err != nil || !o.res.demo {
					t.Errorf("outcome = %+v, want the demo", o)
				}
				return
			}
			if o.err == nil || !strings.Contains(o.err.Error(), "no organization") {
				t.Errorf("err = %v, want the guided error", o.err)
			}
		})
	}
}

// A terminal that hangs up mid-menu is the same exit as q, not a spin.
func TestArrowMenuWhenTheTerminalGoesAway(t *testing.T) {
	term := openTerminal(t)
	done := term.prompt()
	term.await("q quit")
	term.master.Close()
	if o := term.outcome(done); o.err == nil {
		t.Error("a hung-up terminal produced a choice")
	}
}

// The scan offers the menu when a person is present, and acts on the answer.
func TestScanOffersTheMenuOnATerminal(t *testing.T) {
	t.Run("the demo", func(t *testing.T) {
		t.Setenv("AZURE_DEVOPS_BENCH_CONFIG_DIR", t.TempDir())
		term := openTerminal(t)
		var stdout bytes.Buffer
		done := make(chan error, 1)
		go func() {
			root := NewRootCommand()
			root.SetIn(term.slave)
			root.SetErr(term.slave)
			root.SetOut(&stdout)
			root.SetArgs([]string{"scan", "-o", "json"})
			done <- root.Execute()
		}()
		term.await("q quit")
		term.send("2")
		select {
		case <-done:
		case <-time.After(30 * time.Second):
			t.Fatal("the demo never finished")
		}
		if !strings.Contains(stdout.String(), `"findings"`) {
			t.Errorf("no report on stdout:\n%s", stdout.String())
		}
	})

	for name, tc := range map[string]struct {
		breakSave bool
		want      string
	}{
		"credentials, saved":        {false, "saved to "},
		"credentials, save refused": {true, "could not save the organization"},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			t.Setenv("AZURE_DEVOPS_BENCH_CONFIG_DIR", dir)
			fake := &fakeCollection{methods: map[string]int{}}
			var once sync.Once
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.breakSave {
					// The saved instance was already looked for before the
					// first request; a directory in its place now makes the
					// save at the end fail.
					once.Do(func() { os.Mkdir(filepath.Join(dir, "instance.yaml"), 0o700) })
				}
				fake.ServeHTTP(w, r)
			}))
			defer srv.Close()

			term := openTerminal(t)
			done := make(chan error, 1)
			go func() {
				root := NewRootCommand()
				root.SetIn(term.slave)
				root.SetErr(term.slave)
				root.SetOut(&bytes.Buffer{})
				root.SetArgs([]string{"scan", "-o", "json", "-c", configWithScan(t, "failOn: none")})
				done <- root.Execute()
			}()
			term.await("q quit")
			term.send("\r")
			term.await("Organization URL")
			term.send(srv.URL + "/DefaultCollection\n")
			term.await("(hidden)")
			term.send("pat\n")
			term.await("[Y/n]")
			term.send("y\n")
			select {
			case err := <-done:
				if ExitCode(err) != ExitOK {
					t.Fatalf("exit %d (%v)\n%s", ExitCode(err), err, term.screen.String())
				}
			case <-time.After(30 * time.Second):
				t.Fatalf("the scan never finished:\n%s", term.screen.String())
			}
			term.await(tc.want)
		})
	}
}
