package safefile

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteReportsATemporaryFileItCannotCreate(t *testing.T) {
	orig := createTemp
	t.Cleanup(func() { createTemp = orig })
	createTemp = func(string, string) (*os.File, error) { return nil, os.ErrPermission }
	if err := Write(filepath.Join(t.TempDir(), "r.json"), []byte("x")); !errors.Is(err, os.ErrPermission) {
		t.Errorf("err = %v, want ErrPermission", err)
	}
}

// A temporary file that takes no writes — a full disk, in effect. The old
// destination survives and the temporary file is gone.
func TestWriteThatCannotLandLeavesTheOldFile(t *testing.T) {
	orig := createTemp
	t.Cleanup(func() { createTemp = orig })
	dir := t.TempDir()
	dest := filepath.Join(dir, "r.json")
	if err := os.WriteFile(dest, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	var tmpName string
	createTemp = func(dir, pattern string) (*os.File, error) {
		f, err := orig(dir, pattern)
		if err != nil {
			return nil, err
		}
		tmpName = f.Name()
		f.Close()
		return os.Open(tmpName) // read-only
	}
	if err := Write(dest, []byte("new")); err == nil || !strings.Contains(err.Error(), "write "+dest) {
		t.Fatalf("err = %v, want a write error", err)
	}
	if body, _ := os.ReadFile(dest); string(body) != "old" {
		t.Errorf("destination = %q, want the old content untouched", body)
	}
	if _, err := os.Stat(tmpName); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the temporary file was left behind (%v)", err)
	}
}

// A filesystem that will not take the mode after the rename is reported, not
// trusted.
func TestWriteReportsAModeItCannotSet(t *testing.T) {
	orig := chmod
	t.Cleanup(func() { chmod = orig })
	chmod = func(string, os.FileMode) error { return os.ErrPermission }
	if err := Write(filepath.Join(t.TempDir(), "r.json"), []byte("x")); err == nil || !strings.Contains(err.Error(), "restrict ") {
		t.Errorf("err = %v, want a restrict error", err)
	}
}
