// Package examples ships the bundled sample inside the binary.
//
// snapshot.json began as a file this repository carries for people with no
// organization to test against — but a file in a git checkout helps nobody who
// installed a release binary, which is exactly the person who has not seen a
// report yet. Embedding it is what lets `azure-devops-bench scan --demo` (and the
// first-run menu behind it) work with nothing on disk.
//
// The file stays checked in here rather than moving next to the CLI, because
// it is also documentation: the README points at it, and
// `--snapshot-in examples/snapshot.json` remains a way to evaluate it from a
// checkout. Embedding from where it already lives keeps one copy.
package examples

import _ "embed"

// SnapshotJSON is examples/snapshot.json, byte for byte.
//
//go:embed snapshot.json
var SnapshotJSON []byte
