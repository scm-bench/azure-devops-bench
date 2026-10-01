package safefile

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestWriteCreatesAnOwnerOnlyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "report.json")
	if err := Write(path, []byte(`{"ok":true}`)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != `{"ok":true}` {
		t.Fatalf("read back %q, %v", got, err)
	}
	if runtime.GOOS != "windows" {
		info, _ := os.Stat(path)
		if perm := info.Mode().Perm(); perm != Mode {
			t.Errorf("mode = %o, want %o", perm, Mode)
		}
	}
}

// The case os.WriteFile gets wrong: truncating an existing world-readable file
// keeps its mode, so a report written over one stayed readable by everyone.
func TestWriteTightensAnExistingFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not enforce POSIX modes")
	}
	path := filepath.Join(t.TempDir(), "report.sarif")
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	if err := Write(path, []byte("new")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	info, _ := os.Stat(path)
	if perm := info.Mode().Perm(); perm != Mode {
		t.Errorf("mode = %o after overwrite, want %o", perm, Mode)
	}
	if got, _ := os.ReadFile(path); string(got) != "new" {
		t.Errorf("content = %q, want new", got)
	}
}

// Nothing is left behind next to the target, whatever happens.
func TestWriteLeavesNoTemporaryFiles(t *testing.T) {
	dir := t.TempDir()
	if err := Write(filepath.Join(dir, "a.json"), []byte("x")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("directory holds %d entries, want just the target", len(entries))
	}
}

func TestWriteFailsWhenTheDirectoryCannotBeCreated(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := Write(filepath.Join(blocker, "report.json"), []byte("x")); err == nil {
		t.Error("Write succeeded beneath a regular file")
	}
}

// A target that cannot be replaced — here a directory of the same name —
// fails the write and leaves neither a partial file nor the temporary behind.
func TestWriteFailsCleanlyWhenTheTargetCannotBeReplaced(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "report.json")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "keep"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Write(target, []byte("{}")); err == nil {
		t.Fatal("writing over a directory succeeded")
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("directory holds %d entries after a failed write, want only the original", len(entries))
	}
}

// A directory nobody may write to fails at the temporary file, before
// anything about the target has changed.
func TestWriteFailsWhenTheDirectoryIsReadOnly(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("directory permission bits do not stop this user writing")
	}
	dir := filepath.Join(t.TempDir(), "locked")
	if err := os.Mkdir(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0o700) })
	if err := Write(filepath.Join(dir, "report.json"), []byte("{}")); err == nil {
		t.Fatal("writing into a read-only directory succeeded")
	}
}
