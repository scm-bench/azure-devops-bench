package config

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// The snapshot cache: every successful network scan leaves its snapshot in
// this directory so a later `scan --last` can re-render it without another
// fetch. It lives under the config directory rather than the platform cache
// directory on purpose: a snapshot is a map of the organization's weak points,
// not disposable derived data; AZURE_DEVOPS_BENCH_CONFIG_DIR already pins this
// location for tests and pipelines; and deleting one directory must be enough
// to forget everything azure-devops-bench has written down.
const cacheDirName = "cache"

// SnapshotCachePath is where a scan of baseURL caches its snapshot: one file
// per organization, so alternating between two never records one's posture
// under the other's name. It creates the cache directory 0700 — the listing
// alone says which organizations someone audits.
func SnapshotCachePath(baseURL string) (string, error) {
	dir, err := userConfigDir()
	if err != nil {
		return "", err
	}
	cacheDir := filepath.Join(dir, cacheDirName)
	if err := os.MkdirAll(cacheDir, 0o700); err != nil {
		return "", fmt.Errorf("create %s: %w", cacheDir, err)
	}
	return filepath.Join(cacheDir, cacheFileName(baseURL)), nil
}

// cacheFileName reduces a base URL to a filename: the lowercased host and
// port, and the path, with anything a filesystem might object to replaced.
//
// The path is part of it, which bitbucket-bench never needed: every Azure
// DevOps Services organization lives on dev.azure.com, and a name built from
// the host alone made `scan --last` after scanning two organizations replay
// whichever had been written second — under the first one's name. The URL was
// good enough to scan with by the time this runs, so a parse failure falls back
// to sanitizing the raw string rather than failing the write.
func cacheFileName(baseURL string) string {
	name := baseURL
	if u, err := url.Parse(baseURL); err == nil && u.Host != "" {
		name = u.Host
		if p := strings.Trim(u.Path, "/"); p != "" {
			name += "_" + p
		}
	}
	sanitized := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '-':
			return r
		case r >= 'A' && r <= 'Z':
			return r + ('a' - 'A')
		default:
			return '_'
		}
	}, name)
	return sanitized + ".json"
}

// LatestSnapshotCache returns the most recently written cached snapshot, or
// "" when there is none — the normal state before any scan has run, not an
// error.
func LatestSnapshotCache() (string, error) {
	dir, err := userConfigDir()
	if err != nil {
		return "", err
	}
	cacheDir := filepath.Join(dir, cacheDirName)
	entries, err := os.ReadDir(cacheDir)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", fmt.Errorf("read snapshot cache %s: %w", cacheDir, err)
	}
	var newest string
	var newestMod time.Time
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") || strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		if newest == "" || info.ModTime().After(newestMod) {
			newest, newestMod = filepath.Join(cacheDir, entry.Name()), info.ModTime()
		}
	}
	return newest, nil
}
