# Contributing

Thanks for looking. The most useful contributions here are usually not code: a
control that fires wrongly against a real Azure DevOps organization, or
remediation text that does not match what the UI actually says, is worth more
than a refactor.

This document is how the work is done *here*. What a verdict, a `metadata.json`
and a score are *required* to mean is specified once for the whole family, in
[scm-bench](https://github.com/scm-bench/scm-bench/blob/main/docs/bench-contract.md).
The two agree; where a change would make them disagree, the specification is the
one that has to move first, because the other benches read it too.

## Getting set up

```bash
git clone https://github.com/scm-bench/azure-devops-bench
cd azure-devops-bench

make check      # gofmt, vet, race-enabled tests, Rego compile + policy tests
make policy     # just the Rego: compile and unit tests (CI also holds coverage at 100%)
make build      # binary into bin/
make vuln       # govulncheck against what this code actually reaches
make snapshot   # full release build locally, without publishing
```

Go 1.26+; `go.mod` pins a patched toolchain, which Go fetches on its own.
[`opa`](https://www.openpolicyagent.org/docs/latest/#running-opa) is needed for
the policy half of `make check`. Nothing else — the bundle is embedded and there
is no code generation step.

No organization to test against? Everything except the fetcher runs offline:

```bash
./bin/azure-devops-bench scan --demo
./bin/azure-devops-bench scan --snapshot-in examples/snapshot.json
```

## The one rule that matters

**A control that cannot be evaluated reports `MANUAL`, never `PASS` or `FAIL`.**

If the token lacks a scope, if the deployment has no such API (Azure DevOps
Server has no Graph, entitlement or Advanced Security API), if the API never
returned the field — the answer is "I could not tell", and the control leaves
the score. A confident wrong answer is the worst thing this tool can do, because
it teaches people to ignore its output. The rest of the design follows: the
fetcher records what it could not read in `available` and never substitutes a
zero for missing data, and policies check availability *before* they check the
setting.

Azure DevOps makes one more demand. Much of what this bench reads — how a
policy's scope is matched, how a security namespace inherits, which groups an
everyone group contains — is documented loosely or not at all. Where the
fetcher has to infer, the inference is written so that being wrong produces
`MANUAL`: two answers that disagree make the setting unknown, a group that
cannot be expanded makes a set a lower bound, and a lower bound can fail a
control but never pass it.

## How the pieces fit

```
internal/
  scm/                  normalized snapshot types (the fetcher/policy contract)
    azuredevops/        REST client, fetcher, ACL evaluation, identity
                        expansion, branch policy scope resolution
  checks/policies/      one directory per control: check.rego, check_test.rego,
                        metadata.json
  engine/               compiles the bundle once, evaluates, applies
                        exceptions, scores
  report/               table, json, sarif, junit
  diff/                 compares two evaluations; backs `azure-devops-bench diff`
  config/               thresholds handed to Rego as input.config, exceptions
  safefile/             the one way this tool writes a file: atomic, 0600
  cli/                  flags, exit codes, the scan trace
  console/              the table renderer both reports draw with, plus the
                        tagged lines the tool writes about itself on stderr
hack/recon/             read-only probe that captures a real organization's
                        responses, so the stand-in can be checked against them
```

Policy scopes, security tokens, permission inheritance and group expansion are
resolved in Go rather than Rego. They are fiddly, deployment-dependent, and are
not policy. The fetcher hands Rego a boolean or a principal set with a
completeness flag: a rule asks *"is the default branch protected?"*, not
*"does a `Prefix` scope on `refs/heads/rel` cover `refs/heads/release/2`?"*

## Adding a control

Create a directory under `internal/checks/policies/azuredevops/`. No Go changes
— the bundle is embedded and discovered at load time. Three files:

**`check.rego`** returns a single `result` document.

```rego
package scmbench.rules.cis_1_1_4

import rego.v1

import data.scmbench.lib

result := lib.change_na if {
	lib.change_not_applicable
} else := {"status": "MANUAL", "details": "The branch policies could not be read."} if {
	not lib.available("unapproveOnUpdate")
} else := {"status": "PASS", "details": "Approvals are reset on new pushes."} if {
	lib.pr_setting("unapproveOnUpdate", false) == true
} else := {
	"status": "FAIL",
	"details": "Approvals survive new pushes, so unreviewed code can be completed.",
	"evidence": ["no required minimum-reviewer policy resets approval votes"],
}
```

The `MANUAL` branch comes before the verdicts on purpose: deciding what the data
says is only sound once you have established that you have the data. The `NA`
branch comes first of all, for disabled and empty repositories, where there is
no change to control.

**Read every list through `lib.list`**, never `object.get`. A nil Go slice
marshals to JSON `null`, and `object.get` only substitutes its default for an
*absent* key — a key present with a null value comes back null, and passing that
to `concat` or `sort` makes the rule undefined, so the control reports nothing
at all. `TestZeroValuedSnapshotProducesAVerdictForEveryControl` guards this.

**A principal set is only as good as its `complete` flag.** A set with
`complete: false` holds the members that could be resolved; more may exist.
Use it to fail (a count already over the limit stays over it) and never to pass.
`everyone: true` means an everyone group — Project Valid Users, Project
Collection Valid Users — holds the right, which fails any control that limits
who holds it.

**`check_test.rego`** is not optional. Every PASS, FAIL, MANUAL and NA branch
is covered and CI holds the bundle at 100% — an uncovered branch is a verdict
nobody has ever seen the rule produce. Run them with `make policy`.

**`metadata.json`** carries the ID, severity, scope and remediation, all in
English: the tool has one output language, so there is nothing to translate.
Remediation is written twice, at two lengths:

- `remediation` — the full paragraph: the exact UI path, the project-wide
  variant at Project settings -> Repositories -> All Repositories covering every
  repository at once, the exemptions worth granting, and the config key that
  changes what the control counts.
- `fixSummary` — the first move in one imperative line, under 100 characters:
  `Reset approval votes on push at Project settings -> Repositories -> <repo> -> Policies.`
  This is what each finding's table cell prints, so it must stand alone.

Both must name a concrete place — a settings path, a file to add, or an explicit
statement that nothing applies. `TestRemediationSaysWhereToAct` enforces it.
Vague remediation is worse than none: it wastes the reader's time before they
discover it does not help.

The full field list is the family's, not this repository's: it is specified in
[the bench contract](https://github.com/scm-bench/scm-bench/blob/main/docs/bench-contract.md#5-metadatajson),
with a JSON Schema at
[`schemas/metadata.schema.json`](https://github.com/scm-bench/scm-bench/blob/main/schemas/metadata.schema.json)
you can validate a new file against before opening a pull request. `Load` in
`internal/checks/registry.go` enforces the same rules at startup.

Then add the control to the coverage table in both READMEs.

## Testing

Two suites, because the project is written in two languages and `go test -cover`
cannot see Rego. Go covers the fetcher, engine, reporters and CLI; Rego covers
the controls, held at 100%.

The Go suite runs every control against hardened, misconfigured, unreadable and
zero-valued fixtures, asserting each produces a verdict in every case. Add your
control's expected status to each. **The zero-valued case is not optional** — it
catches the bug where a rule silently produces no verdict, which looks exactly
like a passing test run.

The fetcher is tested against a stand-in organization that serves Microsoft's
published Learn samples verbatim where they exist
(`internal/scm/azuredevops/testdata/learn`) and builds the rest in the same
shapes: continuation tokens in a header and in a body, the 203 sign-in page, 401,
403 and the two kinds of 404, `Retry-After` on a successful response, Entra
groups that cannot be expanded, policy scopes by repository, prefix and default
branch, disabled and empty repositories, and an Azure DevOps Server collection.
That proves the code is self-consistent; it does **not** prove Azure DevOps
behaves like the stand-in. If you have an organization, running
[`hack/recon/probe.sh`](hack/recon/README.md) against it and reporting what
differed is the single most valuable thing you can do here.

## Releasing

Push a tag, or run the **Release** workflow from the Actions tab and give it the
tag to create. The workflow does the rest.

```bash
git tag -a v0.1.0 -m "azure-devops-bench v0.1.0" && git push origin v0.1.0
```

Three things that have each gone wrong once in this family:

- **All three components, and the `v`** — `v0.1.0`, never `v0.1`. Go accepts
  `v0.1` as a semver string but not a canonical one, so the module system
  ignores the tag and `go install ...@latest` will not find it. goreleaser
  builds it happily and produces artifacts nobody can install.
- **Publish the draft goreleaser made.** Never start a new release from the
  Releases page: it gets the notes and none of the files.
- **Use `-rc.N` while something is unverified.** Go's `@latest` resolves to the
  newest *release* version, so a prerelease reaches only those who ask for it by
  name, and you can iterate without spending `v0.1.0`.

Notes are written by hand in the draft; goreleaser fills in the parts carrying a
version number. Signing needs nothing from you — cosign works keylessly from the
workflow's OIDC token. Before publishing, check `checksums.txt.bundle` and the
SBOMs are attached: a release whose signing step was skipped looks complete
otherwise.

## Pull requests

- One change per pull request.
- **Label it.** Release notes are grouped by label and an unlabelled pull
  request lands under "Other changes". The labels are shared by the family, in
  [`scm-bench/.github`](https://github.com/scm-bench/.github/blob/main/labels.json);
  the mapping to release note sections is in
  [`.github/release.yml`](.github/release.yml).
- Explain what you verified, and say plainly what you could not.

Commit messages take a Conventional Commits prefix — `feat:`, `fix:`, `docs:`,
`test:`, `build:`, with `!` for a breaking change — and a body explaining *why*
the change is right. The diff shows what it does; the body is for the reasoning,
what was tried and rejected, and what is still not covered.

## Reporting a problem

- **A control is wrong** — tell us whether it is Services or Server (and which
  Server version), what the setting actually is, and what the tool said. A
  redacted `--snapshot-out` file is ideal.
- **A security issue** — do not open an issue. See [SECURITY.md](SECURITY.md).

## Licence

Contributions are accepted under [Apache 2.0](LICENSE).
