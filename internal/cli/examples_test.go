package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// examplesDir is the checked-in examples/ directory, reached from this package.
const examplesDir = "../../examples"

// The bundled sample is the first command the README tells anyone to run, and
// it is what CONTRIBUTING points at for people with no instance to test
// against. Nothing referenced it, so a schema change would have left both
// instructions failing with no test to notice — and the failure would land on
// a newcomer's first attempt at using the tool.
func TestBundledSnapshotStillEvaluates(t *testing.T) {
	stdout, _, code := run(t, "scan",
		"--snapshot-in", filepath.Join(examplesDir, "snapshot.json"),
		"-o", "json", "-c", configWithFailOn(t, "none"))

	if code != ExitOK {
		t.Fatalf("exit code = %d, want %d\n%s", code, ExitOK, stdout)
	}

	var rep struct {
		Metadata struct {
			Platform string `json:"platform"`
		} `json:"metadata"`
		Findings []struct {
			CheckID string `json:"checkId"`
			Status  string `json:"status"`
			Details string `json:"details"`
		} `json:"findings"`
		Score struct {
			Value int `json:"value"`
		} `json:"score"`
	}
	if err := json.Unmarshal([]byte(stdout), &rep); err != nil {
		t.Fatalf("decode report: %v", err)
	}

	if rep.Metadata.Platform == "" {
		t.Error("the sample does not record which platform it came from")
	}
	if len(rep.Findings) == 0 {
		t.Fatal("the sample produced no findings, so it demonstrates nothing")
	}
	for _, f := range rep.Findings {
		if f.Details == "" {
			t.Errorf("%s produced an empty details string", f.CheckID)
		}
	}

	// The sample exists to show the shape of a real result, so it has to have
	// one of each: something wrong, something right, and something the tool
	// admits it cannot decide.
	seen := map[string]bool{}
	for _, f := range rep.Findings {
		seen[f.Status] = true
	}
	for _, want := range []string{"PASS", "FAIL", "MANUAL"} {
		if !seen[want] {
			t.Errorf("the sample contains no %s finding; it is meant to show what each looks like", want)
		}
	}
}

// The sample config is documented as the annotated full set, and it is the
// file a user copies to start from. An unknown key in it is fatal at load
// time — KnownFields is on — so a field renamed in Go without updating the
// example hands everyone a config that refuses to start.
func TestBundledConfigStillLoads(t *testing.T) {
	_, stderr, code := run(t, "scan",
		"--snapshot-in", filepath.Join(examplesDir, "snapshot.json"),
		"-c", filepath.Join(examplesDir, "config.yaml"),
		"-o", "json", "-c", configWithFailOn(t, "none"))

	if code != ExitOK {
		t.Fatalf("exit code = %d, want %d\n%s", code, ExitOK, stderr)
	}
}

// The example is only worth calling "the annotated full set" if it is one.
func TestBundledConfigDocumentsEverySupportedField(t *testing.T) {
	raw := readFile(t, filepath.Join(examplesDir, "config.yaml"))

	for _, field := range []string{
		"minApprovers", "minRepositoryAdmins", "minOrgAdmins", "maxOrgAdmins",
		"staleBranchDays", "maxStaleBranches", "inactiveUserDays",
		"maxBypassPrincipals", "maxRepositoryCreators",
		"signatureStatusChecks", "nonLinearMergeStrategies", "securityPolicyPaths",
		"everyoneAllowedPermissions", "allowedBypassPrincipals", "allowPublicRepositories",
		"skipArchivedRepositories", "exceptions", "exclude", "include",
		"caFile", "allowIncomplete",
	} {
		if !strings.Contains(raw, field) {
			t.Errorf("examples/config.yaml never mentions %q", field)
		}
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(raw)
}
