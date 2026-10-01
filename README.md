<!--
  The banner lives in scm-bench/.github (brand/), which is also where the
  organization profile and the uploaded avatar draw from, so there is one copy
  rather than one per repository. The URLs are absolute for two reasons: a
  relative path cannot cross repositories, and README.md ships inside every
  release tarball, where a repository-relative image resolves to nothing.
-->
<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/scm-bench/.github/main/brand/banner-azure-devops-bench-dark-1760x440.png">
    <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/scm-bench/.github/main/brand/banner-azure-devops-bench-light-1760x440.png">
    <img src="https://raw.githubusercontent.com/scm-bench/.github/main/brand/banner-azure-devops-bench-light-1760x440.png" alt="azure-devops-bench — audit Azure DevOps against the CIS supply chain benchmark" width="880">
  </picture>
</p>

<p align="center">
  <a href="https://github.com/scm-bench/azure-devops-bench/actions/workflows/ci.yml"><img src="https://github.com/scm-bench/azure-devops-bench/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/scm-bench/azure-devops-bench/releases"><img src="https://img.shields.io/github/v/release/scm-bench/azure-devops-bench?include_prereleases&sort=semver" alt="Release"></a>
  <a href="https://goreportcard.com/report/github.com/scm-bench/azure-devops-bench"><img src="https://goreportcard.com/badge/github.com/scm-bench/azure-devops-bench" alt="Go report card"></a>
  <a href="https://pkg.go.dev/github.com/scm-bench/azure-devops-bench"><img src="https://pkg.go.dev/badge/github.com/scm-bench/azure-devops-bench.svg" alt="Go reference"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-blue" alt="Apache 2.0"></a>
</p>

Audit **Azure DevOps** — Azure Repos and the project and organization settings
around it — against the **Source Code** section of the
[CIS Software Supply Chain Security Guide](https://www.cisecurity.org/benchmark/software-supply-chain-security).

azure-devops-bench captures a **read-only** snapshot of an Azure DevOps Services
organization (or an Azure DevOps Server 2022+ collection), evaluates it against
policies written in Rego, and tells you what is misconfigured — along with the
exact settings path to fix it, and the project-wide setting that fixes every
repository at once.

**v0.1** maps 24 controls: 21 are evaluated automatically, and 3 are carried as
documented manual checks so the mapping is complete rather than quietly
partial.

This is the Azure DevOps bench of [scm-bench](https://github.com/scm-bench/scm-bench),
a family of tools that audit one platform each and report in the same shape.
It implements the family's
[bench contract](https://github.com/scm-bench/scm-bench/blob/main/docs/bench-contract.md)
and its [SCM snapshot schema](https://github.com/scm-bench/scm-bench/blob/main/docs/scm-snapshot.md).

[简体中文](README.zh-CN.md) · [Contributing](CONTRIBUTING.md) · [Security](SECURITY.md) · [Spec](#the-specification-it-implements)

---

## The one design decision worth knowing

**A control that could not be evaluated reports `MANUAL`, never `PASS` or `FAIL`.**

If your token cannot read permissions, if the deployment has no such API (Azure
DevOps Server has no user entitlement API), if Azure DevOps answers with a
sign-in page instead of data — the tool says so, and that control is excluded
from the score. A scan is never inflated by questions it could not ask, and
never penalises you for them either.

Azure DevOps makes one more demand. Much of what an audit needs — which policies
apply to a branch, who inherits a permission, who is in an Entra group — is
documented loosely or not at all, so the tool is built to fail safe wherever it
has to infer:

- **Two answers that disagree make a setting unknown.** The policies the server
  says apply to a branch are cross-checked against every policy in the project;
  a mismatch either way turns the policy-based controls on that repository to
  `MANUAL` rather than trusting either side.
- **A set that could not be fully read is a lower bound.** An Entra group lists
  its members only once they have signed in, so a count drawn from one can
  prove a `FAIL` ("at least these people can force push") but never a `PASS`.
- **An empty answer is not a permissive one.** A permission list that comes back
  with nothing in it, where every project has entries by default, is treated as
  unreadable, not as "nobody holds anything".

The inferences, and the read-only probe that checks each one against a real
organization, are listed in [`hack/recon`](hack/recon/README.md).

---

## Install

**Binary** — download from [releases](https://github.com/scm-bench/azure-devops-bench/releases):

```bash
# The archive name carries the version, so resolve the latest tag first.
VERSION=$(curl -fsSL https://api.github.com/repos/scm-bench/azure-devops-bench/releases/latest |
  sed -n 's/.*"tag_name": *"v\([^"]*\)".*/\1/p')

curl -fsSL "https://github.com/scm-bench/azure-devops-bench/releases/download/v${VERSION}/azure-devops-bench_${VERSION}_linux_amd64.tar.gz" | tar xz
./azure-devops-bench version
```

**Docker:**

```bash
docker run --rm -e AZURE_DEVOPS_TOKEN ghcr.io/scm-bench/azure-devops-bench:latest \
  scan --url https://dev.azure.com/fabrikam
```

**From source** (Go 1.26+; the build pins a patched toolchain and will fetch it):

```bash
go install github.com/scm-bench/azure-devops-bench/cmd/azure-devops-bench@latest
```

### Verifying what you downloaded

`checksums.txt` and the container images are signed with
[cosign](https://docs.sigstore.dev/), keylessly — the signing identity is this
repository's release workflow, so there is no key to trust or to leak. Every
archive's digest is in `checksums.txt`, so one signature covers the whole
release, and archives also carry a SLSA build provenance attestation. Each
release's notes carry the exact `cosign verify-blob` and `gh attestation verify`
commands with the identity flags filled in — those flags are the part that
matters: without them a verification only confirms that *somebody* signed the
file.

---

## Quick start

```bash
export AZURE_DEVOPS_URL=https://dev.azure.com/fabrikam
export AZURE_DEVOPS_TOKEN=<personal access token, or an Entra access token>

# Scan everything
azure-devops-bench scan

# Scan one project, or one repository
azure-devops-bench scan --project Fabrikam-Fiber
azure-devops-bench scan --repository Fabrikam-Fiber/payments-api

# Machine-readable output
azure-devops-bench scan -o json  --output-file report.json
azure-devops-bench scan -o sarif --output-file report.sarif
azure-devops-bench scan -o junit --output-file report.xml
```

`--url` takes any of the three forms Azure DevOps is reached by:

| URL | Deployment |
|---|---|
| `https://dev.azure.com/{organization}` | Azure DevOps Services |
| `https://{organization}.visualstudio.com` | Azure DevOps Services, legacy host (the core APIs stay on it) |
| `https://{server}/{collection}` (or `…/tfs/{collection}`) | Azure DevOps Server 2022 or later |

A URL pointing *inside* an organization — a project page pasted from the
browser — is refused with the `--project` that says what was meant, rather
than silently scanning the whole organization. A `--project` or `--repository`
that does not exist (or that the token cannot see) is an error, exit `2`, not
an empty report.

No organization handy? A sample ships inside the binary, so the first report is
one flag away:

```bash
azure-devops-bench scan --demo
```

Run `azure-devops-bench scan` bare on a terminal and it offers the same choice
interactively: enter a URL and token, or see the sample first. If you enter
them, scan offers — it asks, it does not assume — to save them once they have
proven to work. They go to `instance.yaml` under your user config directory
(`~/.config/azure-devops-bench/` on Linux; `AZURE_DEVOPS_BENCH_CONFIG_DIR`
overrides it), mode `0600` since the token is a live credential. A typed `--url`
or an exported `AZURE_DEVOPS_URL` always wins over the file, and every scan
that uses it says so on stderr.

Repositories are fetched concurrently, projects side by side under one shared
bound: `scan.concurrency` (default **4**, half of bitbucket-bench's 8) because
Azure DevOps Services throttles per identity over a sliding five-minute window,
and a scan that trips it spends longer sleeping than it saved. `Retry-After` is
honoured on every response, including the `200`s Azure DevOps sends it on
before it starts delaying requests.

### Watching the scan

By default a scan shows one self-overwriting progress line, then the report.
`--verbose` logs every request instead, grouped by repository, and ends — like
every scan, verbose or not — with an account of what the token was used for
(abridged):

```
[INFO] listing projects
[INFO]   GET  /projects?stateFilter=wellFormed                     200   41ms
[INFO] reading Project Collection Administrators
[INFO]   GET  identity:/identities?filterValue=Project Collection Administrators&searchFilter=General 200   88ms
[INFO]   GET  /accesscontrollists/2e9eb7ed…?recurse=false&token=repoV2(0) 200   63ms
[INFO]   GET  /{project}/policy/configurations                     200   57ms
[INFO] listing repositories in Fabrikam-Fiber
[INFO]   GET  /{project}/git/repositories?includeHidden=true       200   38ms

[INFO]   Fabrikam-Fiber/payments-api
[INFO]     GET  /{project}/git/repositories/278d5cd2…/refs?filter=heads/ 200   35ms
[INFO]     GET  /{project}/git/policy/configurations?refName=refs/heads/main&repositoryId=278d5cd2-584d-4b63-824a-2ba458937249 200   49ms
[INFO]     GET  /{project}/git/repositories/278d5cd2…/stats/branches 200   44ms
[INFO] ✓ 61 requests · 61 GET · 0 writes · read-only
```

**The closing line is the point.** It counts the methods actually sent, not the
promise that they are all `GET`; a non-read request would be reported as
`✗ … NOT READ-ONLY` rather than folded into the total.

`scan.progress` selects how much to show: `compact` (default), `full` (implied
by `--verbose`), or `off`. Redirected or in CI, `full` falls back to `off` on
its own; the closing line is printed regardless, because an account of what a
token was used for belongs in a CI log too. `scan.maxDuration` abandons a scan
that runs too long (exit `2`); `scan.timeout` bounds one request (default 30s).

### What the token needs

azure-devops-bench issues **only `GET` requests** — enforced by a test, and
counted on every run by the closing line above. What it can *read* is up to the
credential:

| Scope | Enables | Without it |
|---|---|---|
| `vso.project` | Listing projects; the credential check before the scan | the scan cannot start (exit `2`) |
| `vso.code` | Repositories, branches, files and branch policies: CIS-1.1.2–1.1.4, 1.1.8, 1.1.9, 1.1.11–1.1.13, 1.2.1, and the `FAIL` side of 1.1.15–1.1.17 | no repository can be listed (exit `2`) |
| `vso.security_manage` | Git permissions: who can bypass policies, force push, delete branches or repositories, administer or create them — CIS-1.1.5, 1.1.14, 1.1.15–1.1.17, 1.2.2, 1.2.3, 1.3.7, 1.3.8 | those report `MANUAL`; 1.1.15–1.1.17 and 1.3.8 can still fail |
| `vso.identity` | Resolving who holds a permission; group expansion on Server | permission sets are incomplete: they can fail, not pass |
| `vso.graph` | Group expansion on Services, including Project Collection Administrators (CIS-1.3.3) | sets are lower bounds |
| `vso.memberentitlementmanagement` | Users and their last access (CIS-1.3.1, Services) | CIS-1.3.1 reports `MANUAL` |
| `vso.advsec` | Advanced Security enablement (CIS-1.5.1, Services) | CIS-1.5.1 reports `MANUAL` |

**Minimum:** `vso.project vso.code` — the policy-based controls, and nothing
about people. **Recommended:** add `vso.graph vso.identity vso.security_manage
vso.memberentitlementmanagement` (and `vso.advsec` if you license Advanced
Security).

**Be aware that `vso.security_manage` can write.** Azure DevOps has no read-only
scope for its security APIs: the scope that lets a token read access control
lists also lets it change them. The tool never sends anything but `GET`, but
the token itself is more powerful than the tool needs, so treat it accordingly:
a PAT never exceeds its owner's rights, so issue it from an account that holds
no *Manage permissions* anywhere, keep its lifetime short, and store it as a
secret. If that trade is not acceptable, leave the scope out — the permission
controls report `MANUAL` and the rest of the scan is unaffected.

**Use an organization-scoped PAT.** Global PATs stop working on
**1 December 2026**; one scoped to the organization you scan keeps working.

**The enterprise path avoids PATs entirely:** a Microsoft Entra service
principal (or managed identity) added to the organization with **Basic** access
(Stakeholder cannot read Repos) and made a member of **Readers** in each
project, with no administrator group. Scopes do not apply to an Entra token —
the identity's own permissions are the limit, which here are read-only. Pass its
token as the token; anything shaped like a JWT is sent as a bearer token:

```bash
export AZURE_DEVOPS_TOKEN=$(az account get-access-token \
  --resource 499b84ac-1321-427f-aa17-267ca6975798 --query accessToken -o tsv)
azure-devops-bench scan --url https://dev.azure.com/fabrikam
```

Whether a Readers-only identity can read every permission list the scan asks
for is one of the things [`hack/recon`](hack/recon/README.md) checks (its run 3);
whatever it cannot read reports `MANUAL`, and the scan's warnings name what was
missing.

A credential Azure DevOps **rejects** is checked before the scan starts and
exits `2` with what to do about it: a `203` sign-in page, a `401`, a redirect or
a non-JSON answer to `GET _apis/projects?$top=1` all mean the same thing.
Treating a rejected credential like a missing permission would turn a mistyped
token into a full report of `MANUAL` — which looks like an audit result rather
than a typo. Every request carries `X-TFS-FedAuthRedirect: Suppress`, and no
redirect is ever followed.

Azure DevOps Server takes a PAT. Credentials embedded in the URL are stripped
before the URL reaches a snapshot or a report, and never used.

### Transport

The token can read every repository it can see, so it is not put on the wire in
the clear: an `http://` URL is refused before the first request, unless the host
is loopback or `scan.allowPlaintext` says the network is trusted.

For an Azure DevOps Server behind an internal certificate authority, give its
certificate to `scan.caFile` — a PEM bundle **added** to the system roots, not
replacing them, and checked at startup so a bad file is a configuration error
rather than a mid-scan failure. `scan.insecure` skips verification altogether
and is almost never the right answer; the two are mutually exclusive. Proxies
come from the usual `HTTPS_PROXY`/`NO_PROXY` environment variables.

All of these are configuration rather than flags on purpose: weakening transport
security should be a decision written into a file someone can review. Each
leaves a line in the report's scan warnings and in any snapshot captured that
way.

---

## Services and Server

The scan reads the same things from both where both have them, and says so
where one does not:

| What the scan reads | Services | Server 2022+ | Where it is missing |
|---|---|---|---|
| Projects, repositories, branches, files, branch policies | yes | yes | — |
| Git permissions and identities | yes | yes | — |
| Group expansion | Graph memberships | IMS (`queryMembership=ExpandedDown`) | — |
| Users' last access | user entitlements | no API | CIS-1.3.1 reports `MANUAL`, naming Server |
| GitHub Advanced Security | yes | not offered | CIS-1.5.1 reports `MANUAL`, naming Server |
| Directory groups | Entra groups: members known once signed in | Active Directory groups: synced members | either way a lower bound |

Server 2022 speaks REST `api-version` 7.0 and 2022.1 and later 7.1; the scan
asks for 7.1 and steps down to 7.0 on its own. Older Servers lack APIs this
bench depends on and are refused with exit `2`.

---

## Coverage

21 controls evaluated automatically:

| CIS | Control | Severity | Decided from |
|---|---|---|---|
| 1.1.2 | Changes trace to a work item | LOW | A required "Check for linked work items" policy on the default branch |
| 1.1.3 | Two independent approvals | HIGH | The required minimum-reviewer policy, less one when requestors may approve their own changes |
| 1.1.4 | Approvals reset on new pushes | MEDIUM | "Reset all approval votes" or "Reset all code reviewer votes" on that policy |
| 1.1.5 | Review cannot be overridden at will | MEDIUM | Who holds "Bypass policies when completing pull requests", groups expanded |
| 1.1.8 | Abandoned branches are pruned | LOW | Branch tip commit dates against `staleBranchDays` |
| 1.1.9 | Checks must pass before merge | HIGH | A required build validation or status check policy without a path filter |
| 1.1.11 | Comments resolved before merge | LOW | A required "Check for comment resolution" policy |
| 1.1.12 | Commit signatures are verified | MEDIUM | A required status check named in `signatureStatusChecks` |
| 1.1.13 | Linear history | LOW | The merge types "Limit merge types" leaves allowed |
| 1.1.14 | Protection binds administrators | MEDIUM | Administrators (Manage permissions, Project Collection Administrators) holding either bypass |
| 1.1.15 | No direct pushes to the default branch | HIGH | A required branch policy, and who holds "Bypass policies when pushing" |
| 1.1.16 | No force pushes | HIGH | Who holds Force push — under a required policy, together with the push bypass |
| 1.1.17 | No branch deletion | MEDIUM | A required branch policy, and who holds Force push and the push bypass |
| 1.2.1 | A security policy is published | LOW | `SECURITY.md` (or a configured path) on the default branch |
| 1.2.2 | Repository creation is limited | MEDIUM | Per project, who holds Create repository without administering the project |
| 1.2.3 | Repository deletion is limited | MEDIUM | Who holds Delete repository without administering the repository |
| 1.3.1 | Dormant users are removed | MEDIUM | Each user's last access, and invitations never accepted (Services) |
| 1.3.3 | Organization administrators are bounded (2–5) | HIGH | Project Collection Administrators, groups expanded |
| 1.3.7 | Each repository has ≥2 administrators | LOW | Who holds Manage permissions, organization administrators aside |
| 1.3.8 | Default repository access is restricted | MEDIUM | Project visibility, and what everyone groups hold beyond `everyoneAllowedPermissions` |
| 1.5.1 | Pushed secrets are blocked | MEDIUM | Advanced Security secret protection with "Block secrets on push" (Services) |

3 controls carried as documented manual checks — reported, explained, and
excluded from the score:

| CIS | Control | Why it is not automated |
|---|---|---|
| 1.1.6 | Code owners | Azure Repos has no CODEOWNERS. Required, path-filtered "Automatically included reviewers" are the mechanism, and the report lists the ones it found — but which paths are sensitive is a judgement no API holds. |
| 1.3.5 | MFA is enforced | Enforced by Microsoft Entra Conditional Access (or the directory in front of Server), which the Azure DevOps API does not expose. A verdict from Azure DevOps data would be invented. |
| 1.3.9 | Organization is verified | Azure DevOps has no verified-organization concept. Reported `NA`. |

```bash
azure-devops-bench list-checks          # all controls, with severity and scope
azure-devops-bench list-checks --json   # full metadata, including remediation text
```

### What protects a branch in Azure Repos

Azure Repos has no branch restrictions of its own; a branch is protected by
**required branch policies**, and only as far as the people they bind. The scan
derives the protection from both halves:

- **Direct pushes** (1.1.15) are blocked when any required branch policy applies
  to the default branch. Whoever holds *Bypass policies when pushing* is not
  bound by it.
- **Force pushes** (1.1.16) take *Force push*; under a required policy they also
  take the push bypass. Azure Repos grants a branch's creator Force push on it,
  so the person who first pushed `main` can rewrite it unless that grant was
  removed — the scan reads branch-level permissions and counts them.
- **Deletion** (1.1.17) is blocked by a required policy except for holders of
  both Force push and the push bypass; without one, anyone holding Force push
  can delete the branch.
- **Pull request bypass** (1.1.5) is *Bypass policies when completing pull
  requests*; **administrators** (1.1.14) are the holders of either bypass who
  also administer the repository or the organization.

Which policies apply is the server's answer — `git/policy/configurations` for
the repository and its default branch, covering project-wide, prefix and
"default branch of each repository" scopes — cross-checked against the
project's full policy list, as described above. A policy that is optional
(not *Required*) appears in the evidence but protects nothing.

Who holds a permission is the server's own evaluation (`effectiveAllow`) for
every identity with an entry anywhere from the organization down to the
branch, with groups expanded to people and personal denies taken back out.
The verdict then counts people:

```yaml
thresholds:
  maxBypassPrincipals: 0                    # how many may slip the protection
allowedBypassPrincipals: [Project Collection Build Service (fabrikam)]   # the ones that do not count
```

`allowedBypassPrincipals` is the one to reach for first: a build identity often
does need to push past a policy, and without somewhere to say so the threshold
would have to be raised high enough to hide the people. A count that is a lower
bound and already over the threshold fails; one that is not reports `MANUAL`.

CIS-1.1.12 **fails by default**: Azure Repos cannot verify a commit signature
itself, so the only enforcement is a required status check posted by a service
that does — and which service that is, is a fact about your deployment. Name it
in `signatureStatusChecks` (`genre/name`, or `name`).

Disabled repositories are recorded without a single Git request and, with
`skipArchivedRepositories` (the default), left out of the evaluation; with it
off, their change controls report `NA`. Empty repositories report `NA` for the
same controls.

---

## Scoring

```
score = ⌊ Σ weight(passed) / Σ weight(passed + failed) × 100 ⌋
```

with `HIGH = 3`, `MEDIUM = 2`, `LOW = 1`. `MANUAL` and `NA` are in neither sum.
The score is floored, never rounded: 99.9 is 99, so 100 always means every
decided finding passed.

The table output prints the arithmetic (`weighted 73/136 (HIGH=3, MEDIUM=2,
LOW=1; manual and n/a excluded)`) so the number is checkable rather than
something you have to trust. When **nothing** was decidable the score is `0`,
not `100`. Treat the score as a trend line; the failures by severity are what
decide whether a result is acceptable.

---

## Output formats

**`table`** (default) — a line-oriented findings report: each failure is one
self-contained record, and the score block closes it.

```
azure-devops-bench v0.1.0  ·  https://dev.azure.com/fabrikam  ·  2026-10-01 00:00:00 UTC

Fabrikam-Fiber/legacy-portal  CIS-1.1.3 HIGH: Pull requests into master require 0 independent
    approval(s); at least 2 are needed.
    fix: Require 2+ reviewers at Project settings -> Repositories -> <repo> -> Policies.
    · independent approvals required: 0 (minimumApproverCount 0)

...

Fabrikam-Fiber/legacy-portal  CIS-1.1.16 HIGH: alice@fabrikam.com can force push master, rewriting
    or erasing the history reviewers approved.
    fix: Remove "Force push" at Repos -> Branches -> <default branch> -> Branch security.
    · can force push: alice@fabrikam.com
    · 1 in total; thresholds.maxBypassPrincipals is 0

...

Fabrikam-Fiber/legacy-portal  CIS-1.1.5 MEDIUM: bob@fabrikam.com, chen@fabrikam.com can complete
    pull requests into master without the approvals and checks its policies require.
    fix: Revoke "Bypass policies when completing pull requests" at Project settings -> Repositories.
    · Bypass policies when completing pull requests: bob@fabrikam.com, chen@fabrikam.com
    · 2 in total; thresholds.maxBypassPrincipals is 0
    · through groups: [Fabrikam-Fiber]\Release Managers

... one record per failing resource and control, severity descending ...

CIS-1.3.5 MANUAL (instance): Multi-factor authentication is enforced by Microsoft Entra ID
    Conditional Access (or the directory in front of Azure DevOps Server), which the Azure DevOps
    API does not expose. Verify enforcement there.
    fix: Require MFA with Conditional Access at Entra admin center -> Protection -> Conditional
    Access.

...

8 controls could not be read (Unread) on Fabrikam-Fiber/shared-infra; see Scan warnings below.

Scan warnings

  - group "[fabrikam]\Platform Engineers (Entra)" is a Microsoft Entra group; Azure DevOps lists its
    members only once they have signed in, so counts derived from it are lower bounds

Rules

  CIS-1.1.3   https://learn.microsoft.com/en-us/azure/devops/repos/git/branch-policies#require-a-minimum-number-of-reviewers

... one line per control in the report, with Microsoft's documentation page ...

SCORE 53/100   39 passed  32 failed  14 manual  15 n/a
      20 controls failed across 32 findings
      weighted 73/136 (HIGH=3, MEDIUM=2, LOW=1; manual and n/a excluded)
      scored 71 of 85 findings (83%); 14 could not be evaluated
```

That is the real output of `azure-devops-bench scan --demo` at `COLUMNS=100`,
abbreviated where a line is marked `...`.

**A failure is one record**: `<resource> <CHECK-ID> <SEVERITY>: <details>`, the
one-line fix beneath it, the evidence as `·` lines under that — so `grep
'HIGH:'` is the list of severe findings, each with its own context. **Controls
that need a person aggregate to one line each**, keyed by control and reason.
What the scan could not *read* collapses into one sentence above the scan
warnings, which say why. `Rules` closes the findings with Microsoft's
documentation page for each control, and a control failing on every repository
of a project says that one project-wide setting fixes them all.

`--details` renders a table per resource instead, with the full remediation
paragraphs; `--details=Fabrikam-Fiber/payments-api` or `--details=CIS-1.1.9`
narrows it. `--show-passed` lists passing controls too, `--no-remediations`
drops the fixes, `--max-resources` caps the per-resource sections. Colour is
used only on a terminal and honours `NO_COLOR`. Output is English only, by
decision: a verdict's text is built by its rule, so a second language would be a
second copy of every rule's message construction.

**`json`** — the full report: every finding, its evidence, why the control
exists, its remediation, any exception accepting it, and the score breakdown.

**`sarif`** — SARIF 2.1.0 for code scanning. Failures and manual reviews are
emitted, passes and `NA` are not. Every result carries a `physicalLocation` —
GitHub code scanning silently drops results without one — whose URI names the
platform, organization and repository (`azure-devops/dev.azure.com/fabrikam/Fabrikam-Fiber/payments-api`),
with a `logicalLocation` beside it saying what it really is. Results are
fingerprinted so an alert survives re-runs, `automationDetails` separates
organizations scanned into one repository, an accepted finding carries a
`suppressions` entry, and scan warnings travel as notifications so a partial
scan is never mistaken for a clean one. GitHub's 5,000-result ceiling is
respected by keeping the most severe and saying how many were withheld.

**`junit`** — JUnit XML, for the CI systems that draw test results natively:
Azure Pipelines' *Publish Test Results*, Jenkins, GitLab. One suite per control,
one test case per resource; an unaccepted `FAIL` is a failure, `MANUAL`, `NA`
and accepted findings are skipped with the reason; a scan that missed projects
carries a failing `scan` suite of its own.

Reports are written `0600` and atomically, like snapshots: a report names every
repository that can be force pushed and every account that should have been
removed, and a CI step must never read a half-written one as complete.

---

## Configuration

Every threshold a reasonable person might disagree with is configurable, and
the settings that describe the deployment rather than any one run — exit
thresholds, transport, concurrency, progress — live here rather than in flags.

```bash
azure-devops-bench init            # writes a commented azure-devops-bench.yaml with every key
azure-devops-bench scan            # finds it in the working directory on its own
```

Discovery order: `--config` when given, else `azure-devops-bench.yaml` (or
`.azure-devops-bench.yaml`) in the working directory, else `config.yaml` under
the user config directory. The file used is always named on stderr: a config a
pull request drops into the working directory changes how the CI gate judges
the organization, and must not do it silently. `--set` overrides any key for one
run (`--set scan.failOn=none`, `--set thresholds.minApprovers=1`).

See [`examples/config.yaml`](examples/config.yaml) for the annotated full set.
The most commonly adjusted:

```yaml
scan:
  failOn: high            # exit 1 at or above this severity: high, medium, low, none
  maxManual: -1           # exit 1 when this % of automatable findings went unread; -1 off
  concurrency: 4          # parallel repository fetches, shared across projects
  caFile: ""              # PEM bundle added to the system roots (Server behind an internal CA)
  allowIncomplete: false  # true: a project whose repositories could not be listed does not exit 2

thresholds:
  minApprovers: 2          # CIS-1.1.3
  staleBranchDays: 90      # CIS-1.1.8
  inactiveUserDays: 90     # CIS-1.3.1
  minOrgAdmins: 2          # CIS-1.3.3
  maxOrgAdmins: 5
  minRepositoryAdmins: 2   # CIS-1.3.7
  maxBypassPrincipals: 0   # CIS-1.1.5, 1.1.14–1.1.17; -1 turns the bypass check off
  maxRepositoryCreators: 0 # CIS-1.2.2

allowedBypassPrincipals: [Project Collection Build Service (fabrikam)]
signatureStatusChecks: [security/verify-signatures]   # CIS-1.1.12 fails while this is empty
everyoneAllowedPermissions: [GenericRead]             # CIS-1.3.8
exclude: [CIS-1.1.13]                                 # or include: to run a subset
```

A config file only states what it changes; lists replace the default wholesale.
An unrecognised key is an error, not a shrug — `minApprover` for `minApprovers`
would otherwise parse, change nothing, and yield a report the reader believes was
evaluated at their threshold. So is a blank list entry, a negative threshold,
and an `everyoneAllowedPermissions` entry that names no Git permission.

### Exceptions

Some findings are known and accepted — a legacy repository on its way out, a
build identity that has to push. An exception records that decision, with a
reason and an end date:

```yaml
exceptions:
  - control: CIS-1.1.16
    resources: [Fabrikam-Fiber/legacy-*]   # globs; * does not cross "/"; "instance" for organization controls
    reason: Read-only mirror, retired with the Q1 migration
    owner: platform-team@fabrikam.com
    expires: 2027-03-31                     # applies through that day, UTC
```

An accepted finding **is still reported, still `FAIL`, and still counts in the
score** — the score describes the organization, and accepting a finding does
not change it. What it stops doing is failing the run on `scan.failOn` (or, for
a `MANUAL` finding, counting against `scan.maxManual`). The table lists accepted
findings under their own heading with the reason and expiry, JSON carries a
`waiver`, SARIF a `suppressions` entry, JUnit a skip.

There is no exception without a reason and an expiry. When one lapses the
finding fails the run again and the scan says why on stderr, whatever the
verbosity; an exception that matches nothing — the finding was fixed or the
repository renamed — is reported so it can be removed.

---

## In CI

The thresholds live in an `azure-devops-bench.yaml` committed next to the
pipeline, so the pipeline and a laptop read the same file and disagree about
nothing:

```yaml
# azure-devops-bench.yaml
scan:
  failOn: high
  maxManual: 40
```

**Azure Pipelines** — the results land in the run's *Tests* tab through
`PublishTestResults`:

```yaml
- script: |
    azure-devops-bench scan --url "$(System.CollectionUri)" \
      -o junit --output-file "$(Agent.TempDirectory)/azure-devops-bench.xml"
  displayName: Audit Azure DevOps
  env:
    AZURE_DEVOPS_TOKEN: $(AUDIT_TOKEN)   # a secret variable: a PAT, or an Entra token for the scanner's service principal

- task: PublishTestResults@2
  condition: succeededOrFailed()
  inputs:
    testResultsFormat: JUnit
    testResultsFiles: $(Agent.TempDirectory)/azure-devops-bench.xml
    testRunTitle: azure-devops-bench
    failTaskOnFailedTests: false   # the scan's exit code is the gate
```

The token is a PAT or a Microsoft Entra token for a service principal set up
as in [What the token needs](#what-the-token-needs). The pipeline's own
identity, `$(System.AccessToken)`, is deliberately not the recommendation: it
is limited to the pipeline's project unless that setting was relaxed, and
whether its build service identity can read the permission, Graph and
entitlement APIs this scan depends on has not been verified. A scan that cannot
read them reports `MANUAL` rather than wrong verdicts, so trying it is safe,
but expect gaps. Secret variables reach a script only through `env:`, as above.

**GitHub Actions** — upload the SARIF to code scanning. The scan exits `1`
when it finds something, which is the point, but that would end the job before
the upload; the failure is deferred to the last step. The upload needs
`security-events: write` in the job's `permissions` — and, in a private
repository, `actions: read` and `contents: read` too.

```yaml
- name: Audit Azure DevOps
  id: audit
  continue-on-error: true
  run: |
    azure-devops-bench scan --url "${{ vars.AZURE_DEVOPS_URL }}" \
      -o sarif --output-file azure-devops-bench.sarif
  env:
    AZURE_DEVOPS_TOKEN: ${{ secrets.AZURE_DEVOPS_TOKEN }}

- name: Upload to code scanning
  if: always()
  uses: github/codeql-action/upload-sarif@v4
  with:
    sarif_file: azure-devops-bench.sarif
    category: azure-devops-bench

- name: Fail the job if the audit did
  if: steps.audit.outcome == 'failure'
  run: exit 1
```

Alerts land against the synthetic path in each result's `physicalLocation`,
not against a file in the repository, because a finding is a setting rather
than a line of code; `json` is the better input for a dashboard.

**Jenkins** — the JUnit publisher draws the result in the build's test view:

```groovy
stage('Audit Azure DevOps') {
  steps {
    withCredentials([string(credentialsId: 'azure-devops-bench-token', variable: 'AZURE_DEVOPS_TOKEN')]) {
      sh '''
        azure-devops-bench scan --url https://dev.azure.com/fabrikam \
          -o junit --output-file azure-devops-bench.xml
      '''
    }
  }
  post {
    always {
      // Draws the report; the scan's exit code has already decided the build.
      junit testResults: 'azure-devops-bench.xml', allowEmptyResults: true, skipMarkingBuildUnstable: true
    }
  }
}
```

In every recipe **the scan's exit code decides the build and the report only
draws it.** A test report cannot carry the gate: JUnit has no notion of
severity, so every unaccepted `FAIL` is a failing test — `LOW` included — and
a publisher left to fail the build on failing tests gates on something
stricter than `failOn`. And a scan whose exit code is thrown away lets a
breached `maxManual` or `failUnder` through — as a yellow build, since
Jenkins' `junit` step marks failing tests `UNSTABLE` rather than failed, or as
a green one when nothing happened to fail as a test.

Exit codes:

| Code | Meaning |
|---|---|
| `0` | The scan ran and breached no threshold |
| `1` | The scan ran and breached one |
| `2` | The scan could not complete — or cannot vouch for what it covered |

Three settings drive exit `1`, and they answer different questions:

| Setting | Asks |
|---|---|
| `scan.failOn` | Are there failures this severe? `high` (default), `medium`, `low`, `none` |
| `scan.failUnder` | Is the score acceptable? 0–100; `0` disables |
| `scan.maxManual` | Did the scan see enough to have an opinion? A percentage; `-1` disables |

Start at `failOn: high` and tighten once the first round of findings is
cleared; [exceptions](#exceptions) are for the findings that will not be.

`scan.maxManual` is worth setting early. Findings that could not be read are
excluded from the score rather than counted against it — right for one control,
misleading in aggregate, because a token that has lost a scope shrinks the
denominator and can score *higher* than a working one. `scan.failUnder` cannot
catch that; `scan.maxManual` can.

Exit `2` covers a bad config or a rejected credential, an unknown `--project`
or `--repository`, a control that failed to evaluate — and two scans that ran
but cannot vouch for their coverage: one that **evaluated no repository** (a
`--project` the token cannot read, a token that sees nothing, an organization
whose every repository is disabled), and one that **could not list some
project's repositories**, which are then missing from the report with no
finding to say so. The report is still written, and says so itself: the SARIF
run is marked unsuccessful with an error notification, and the JUnit file
carries a failing `scan.coverage` case. `scan.allowIncomplete: true` accepts
the second if you mean to.

### Splitting capture from evaluation

The snapshot is a self-contained artifact, so the credential-holding step and
the evaluating step can be different steps, on different machines:

```bash
# On a runner that can reach Azure DevOps and holds the token
azure-devops-bench scan --snapshot-out snapshot.json -o json --set scan.failOn=none

# Anywhere, later — no credentials, no network
azure-devops-bench scan --snapshot-in snapshot.json -o sarif
```

Snapshots are written `0600`: they are a precise map of an organization's weak
points. So are reports and the saved `instance.yaml`. That is a Unix mode — on
Windows the file inherits its directory's ACL, so put snapshots and reports
somewhere already restricted.

### Asking the follow-up without another scan

Every network scan leaves its snapshot behind (`0600`, one per organization,
under the user config directory), and `--last` re-renders the most recent one:

```bash
azure-devops-bench scan                     # the overview; the snapshot is kept
azure-devops-bench scan --last --details    # expand it, without touching Azure DevOps
```

A `--last` run says which organization the snapshot came from and how old it
is, warning past a day. `scan.cache: false` keeps snapshots off disk.

### Catching regressions

`diff` evaluates two snapshots with the running build and configuration, and
reports what moved:

```bash
azure-devops-bench diff last-week.json today.json
```

Only `PASS → FAIL` is a regression and exits `1` (`--fail-on-regression=false`
makes it report-only). A new repository arriving with failures is not a
regression, and nor is anything involving `MANUAL` — a token losing a scope is
the scan's blind spot, not the organization getting worse. Comparing snapshots
of two different organizations is refused unless `--allow-other-instance` says
it is deliberate.

---

## How it works

```
Azure DevOps REST  ──►  fetcher  ──►  snapshot.json  ──►  Rego policies  ──►  report
                     (Go, GET only)   (normalized)      (one per control)   table/json/sarif/junit
```

- **The fetcher never decides anything.** It normalizes — resolves policy
  scopes, evaluates permissions, expands groups — and records what it could not
  read, and how sure it is of each set it hands over.
- **Policies never make HTTP calls.** They read one JSON document and return a
  verdict, checking availability before the setting.

No Azure SDK is involved: the client is a small read-only HTTP client, so every
request it can make is visible in one file. The package layout, the policy
contract, how to add a control and how to run the two test suites are in
[CONTRIBUTING.md](CONTRIBUTING.md); the inferences the fetcher makes about
undocumented behaviour, and the probe that checks them, are in
[`hack/recon`](hack/recon/README.md).

---

## The specification it implements

The four statuses, the rule that an unevaluable control reports `MANUAL`, the
`metadata.json` fields, the scoring formula, the snapshot schema and the SARIF
shape are specified in [scm-bench](https://github.com/scm-bench/scm-bench), the
family's umbrella repository. Nothing is imported from it at build time.

| Document | What it fixes |
| --- | --- |
| [bench contract](https://github.com/scm-bench/scm-bench/blob/main/docs/bench-contract.md) | The parts every bench shares, whatever it audits. |
| [SCM snapshot schema](https://github.com/scm-bench/scm-bench/blob/main/docs/scm-snapshot.md) | The `snapshot.json` shape, shared with bitbucket-bench. Azure DevOps adds fields Bitbucket has no equivalent for — who may bypass a policy, Advanced Security — additively. |
| [config conventions](https://github.com/scm-bench/scm-bench/blob/main/docs/config-conventions.md) | Where the config file is found and how its keys merge. |

---

## Roadmap

**v0.2** — replay the [recon](hack/recon/README.md) captures as fixtures and
retire each inference they settle; audit streams as evidence for the logging
controls; organization security policies once Microsoft documents an API for
them.

---

## License

Apache 2.0. See [LICENSE](LICENSE).
