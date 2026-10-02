// Package safefile writes the files this tool produces about an organization:
// reports, snapshots, the snapshot cache and the saved credential. All four are
// a map of the organization's weak points or a key to it, so they share one
// write path with one set of guarantees.
package safefile

import (
	"fmt"
	"os"
	"path/filepath"
)

// Mode is the permission every file written here ends up with.
const Mode os.FileMode = 0o600

// Write replaces path with data, owner-readable only, atomically.
//
// Atomic because a report or snapshot that a crash or a full disk leaves
// half-written looks like a complete one: a CI step reading it would gate on a
// truncated finding list. The data goes to a temporary file in the same
// directory — a rename is only atomic within one filesystem — and is renamed
// over the target once it is fully on disk.
//
// 0600 even when the file already existed. os.WriteFile keeps the mode of a
// file it truncates, so a report written over a world-readable file from an
// earlier run, or from someone's `touch`, stayed world-readable; the rename
// here replaces the inode, and the temporary file is created 0600 and chmod'ed
// to it explicitly in case a umask or a filesystem widened it. Windows does
// not enforce POSIX modes, and the README says so.
func Write(path string, data []byte) error {
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create %s: %w", dir, err)
		}
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return fmt.Errorf("create a temporary file next to %s: %w", path, err)
	}
	tmpName := tmp.Name()
	// Removed on every failure path; after a successful rename it no longer
	// exists and the removal is a harmless no-op.
	defer os.Remove(tmpName)

	if err := tmp.Chmod(Mode); err != nil {
		tmp.Close()
		return fmt.Errorf("restrict %s: %w", tmpName, err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	// The rename carried the temporary file's mode over, but a filesystem
	// that ignored the chmod above (some network mounts do) is caught here
	// rather than trusted.
	if err := os.Chmod(path, Mode); err != nil {
		return fmt.Errorf("restrict %s: %w", path, err)
	}
	return nil
}
