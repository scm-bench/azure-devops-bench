package config

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// noUserConfigDir makes os.UserConfigDir fail on every platform CI runs on.
func noUserConfigDir(t *testing.T) {
	t.Helper()
	for _, k := range []string{configDirEnv, "XDG_CONFIG_HOME", "HOME", "AppData", "home"} {
		t.Setenv(k, "")
	}
}

// aFile returns the path of a regular file, for a "directory" that is not one.
func aFile(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "plain")
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDurationMustBeAString(t *testing.T) {
	if _, err := Load(writeConfig(t, "scan:\n  timeout: [30]\n")); err == nil || !strings.Contains(err.Error(), "a duration is a string") {
		t.Errorf("err = %v, want the duration spelling explained", err)
	}
}

func TestNegativeDurationsAreRejected(t *testing.T) {
	for _, mutate := range []func(*Config){
		func(c *Config) { c.Scan.Timeout = Duration(-time.Second) },
		func(c *Config) { c.Scan.MaxDuration = Duration(-time.Second) },
	} {
		cfg := Default()
		mutate(&cfg)
		if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "must not be negative") {
			t.Errorf("err = %v, want a negative-duration error", err)
		}
	}
}

// Without a user config directory there is nothing to discover there, and
// nothing to save to or read from: those say so instead of guessing a place.
func TestNoUserConfigDirectory(t *testing.T) {
	t.Chdir(t.TempDir())
	noUserConfigDir(t)
	if got := Discover(); got != "" {
		t.Errorf("Discover() = %q, want none", got)
	}
	if _, err := SnapshotCachePath("https://dev.azure.com/org"); err == nil {
		t.Error("SnapshotCachePath succeeded with no config directory")
	}
	if _, err := LatestSnapshotCache(); err == nil {
		t.Error("LatestSnapshotCache succeeded with no config directory")
	}
	if _, _, err := LoadInstance(); err == nil {
		t.Error("LoadInstance succeeded with no config directory")
	}
	if _, err := SaveInstance(Instance{URL: "https://dev.azure.com/org"}); err == nil {
		t.Error("SaveInstance succeeded with no config directory")
	}
}

func TestUserConfigDirUsesThePlatformDefault(t *testing.T) {
	base := t.TempDir()
	t.Setenv(configDirEnv, "")
	t.Setenv("XDG_CONFIG_HOME", base)
	t.Setenv("HOME", base)
	t.Setenv("AppData", base)
	got, err := userConfigDir()
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(got) != "azure-devops-bench" {
		t.Errorf("userConfigDir() = %q, want an azure-devops-bench directory", got)
	}
}

// A config "directory" that is a file blocks every write under it, and each
// write says where it was blocked.
func TestConfigDirectoryThatIsAFile(t *testing.T) {
	t.Setenv(configDirEnv, aFile(t))
	if _, err := SnapshotCachePath("https://dev.azure.com/org"); err == nil || !strings.Contains(err.Error(), "create ") {
		t.Errorf("SnapshotCachePath: err = %v, want a create error", err)
	}
	if _, err := SaveInstance(Instance{URL: "https://dev.azure.com/org"}); err == nil || !strings.Contains(err.Error(), "create ") {
		t.Errorf("SaveInstance: err = %v, want a create error", err)
	}
	// Windows answers a path under a file with "path not found", which
	// reads as nothing cached and nothing saved rather than as an error.
	if runtime.GOOS != "windows" {
		if _, err := LatestSnapshotCache(); err == nil || !strings.Contains(err.Error(), "read snapshot cache") {
			t.Errorf("LatestSnapshotCache: err = %v, want a read error", err)
		}
		if _, _, err := LoadInstance(); err == nil || !strings.Contains(err.Error(), "read saved instance") {
			t.Errorf("LoadInstance: err = %v, want a read error", err)
		}
	}
}

// The instance file's place is taken by a directory: the write cannot land.
func TestSaveInstanceReportsAWriteItCannotMake(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(configDirEnv, dir)
	if err := os.Mkdir(filepath.Join(dir, instanceFile), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := SaveInstance(Instance{URL: "https://dev.azure.com/org"}); err == nil || !strings.Contains(err.Error(), "write saved instance") {
		t.Errorf("err = %v, want a write error", err)
	}
}

// An entry whose details cannot be read is passed over, not fatal: the scan
// cache is a convenience, and one unreadable file must not hide the others.
func TestLatestSnapshotCacheSkipsWhatItCannotStat(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs POSIX permissions enforced on this user")
	}
	dir := t.TempDir()
	t.Setenv(configDirEnv, dir)
	cache := filepath.Join(dir, cacheDirName)
	if err := os.Mkdir(cache, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cache, "a.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Readable but not searchable: the names list, their details do not.
	if err := os.Chmod(cache, 0o400); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(cache, 0o700) })
	got, err := LatestSnapshotCache()
	if err != nil || got != "" {
		t.Errorf("LatestSnapshotCache() = %q, %v; want nothing it could not stat", got, err)
	}
}
