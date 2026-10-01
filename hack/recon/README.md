# Recon: checking the stand-in against a real organization

`azure-devops-bench` is tested against a stand-in organization
(`internal/scm/azuredevops/fake_test.go`) that serves Microsoft's published
Learn samples verbatim where they exist and builds everything else in the same
shapes. That proves the fetcher is self-consistent. It does not prove Azure
DevOps behaves like the stand-in — and in several places the documentation is
silent, so the stand-in encodes an inference.

Every inference is written so that being wrong produces `MANUAL`, never a false
`PASS`: two answers that disagree make a setting unknown, a group that cannot be
expanded makes a set a lower bound, a missing evaluation makes a set
incomplete. Wrong inferences therefore cost coverage, not correctness. This
directory exists to find them anyway: `probe.sh` asks a real organization the
same questions the fetcher asks and saves the answers, and the table below says
which answer settles which inference.

## Safety

`probe.sh` is meant to be run with a credential for a real organization, so it
is held to the same rules as the scanner, and `probe_test.go` checks each one:

- **GET only.** One function, `get`, runs curl, and it passes `--request GET`
  and nothing that carries a body. Redirects are saved as answers, never
  followed.
- **The token stays out of sight.** It is read from `AZURE_DEVOPS_TOKEN`,
  removed from the environment before any child process starts, and handed to
  curl on stdin — never in an argument list, where any user's `ps` would show
  it. It is never printed, tracing is switched off before it is read, and every
  saved file has the token (raw, as Basic credentials, and base64-encoded)
  replaced with `[REDACTED]` should a response ever echo it.
- **Nothing sensitive in headers.** Only the response headers the fetcher reads
  or that explain a refusal are kept (`Content-Type`, `x-ms-continuationtoken`,
  `Retry-After`, `X-RateLimit-*`, `Location`, `WWW-Authenticate`,
  `X-TFS-ServiceError`); cookies and session identifiers never reach the disk.
  JSON keys named like `password`, `secret`, `accessToken` or `cookie` are
  redacted wherever they appear.
- **Owner-only, never committed.** Captures are written `0600` in a `0700`
  directory under `hack/recon/out/`, which `.gitignore` excludes.

The captures hold no credential, but they do name the organization's projects,
repositories, groups and people. Review them before sharing; pseudonymize them
before they go anywhere near the repository (see *Replay*).

## Running it

Needs `bash`, `curl`, `jq`, `awk`, `od`, `iconv` and `base64` — all present on
macOS, on Microsoft-hosted agents and on GitHub runners.

```bash
export AZURE_DEVOPS_URL=https://dev.azure.com/fabrikam
read -rs AZURE_DEVOPS_TOKEN && export AZURE_DEVOPS_TOKEN   # paste, then Enter
hack/recon/probe.sh recon-hardened app
hack/recon/probe.sh recon-weak app
```

The arguments name a project and a repository; without them the first project
and its first enabled repository with a default branch are probed. Each run
writes about 40 files to `hack/recon/out/<host>-<time>/`, with an `index.tsv`
listing every request, its status and its file, and a `probe.txt` recording
what was probed.

Run it more than once, because the credential is part of what is being probed:

| Run | Credential | What it settles |
|---|---|---|
| 1 | PAT with the recommended scopes: `vso.project vso.code vso.graph vso.identity vso.security_manage vso.memberentitlementmanagement vso.advsec` | every shape below |
| 2 | PAT with only `vso.project vso.code` | what a missing scope looks like on each API (401, 403 or 203) — the fetcher treats all three as unreadable, and this checks nothing else comes back |
| 3 | Entra access token for the service principal the README recommends (`az account get-access-token --resource 499b84ac-1321-427f-aa17-267ca6975798 --query accessToken -o tsv`) | that the enterprise path reads the same as a PAT |
| 4 | Azure DevOps Server 2022.1 or later collection URL with a PAT, and a 2022 (RTW) one if available | the Server shapes: identities on the collection, and `api-version` negotiation down to 7.0 on 2022 RTW |

Set `PROBE_OUT` to keep runs apart if they would otherwise share a timestamp.
`PROBE_MAX_PAGES` (default 3) bounds how far a paged list is followed, and
`AZURE_DEVOPS_CA_FILE` trusts a private CA for a Server.

## Setting up the organization

The captures are only as informative as the configuration they record. A
sandbox organization arranged as below exercises every automated control in
both directions; MANUAL comes from run 2, where the scopes are missing. Use a
sandbox: `recon-weak` is deliberately insecure.

Two projects, each with a repository named `app` initialized with a README:

- **`recon-hardened`** — everything configured the way the controls want it.
- **`recon-weak`** — everything left open, plus `legacy` (disabled at
  Project settings -> Repositories -> legacy -> Settings -> Disable repository)
  and `empty` (created without initializing). Both must come back `NA`, and
  `legacy` must cause no Git request at all.

Branch policies are set at Project settings -> Repositories -> app -> Policies
-> Branch Policies -> main, except where a project-wide policy is named.

| Control | `recon-hardened` (PASS) | `recon-weak` (FAIL) |
|---|---|---|
| CIS-1.1.2 | Check for linked work items: Required | — |
| CIS-1.1.3 | Require a minimum number of reviewers: 2; "Allow requestors to approve their own changes" off | Minimum 1, requestors may approve their own changes |
| CIS-1.1.4 | When new changes are pushed: "Reset all approval votes" | "Require at least one approval on the last iteration" only |
| CIS-1.1.5 | Nobody holds "Bypass policies when completing pull requests" | Contributors granted it at Project settings -> Repositories -> All Repositories -> Security |
| CIS-1.1.6 | Automatically included reviewers, required, path filter `/infra/*` (evidence for the manual review) | — |
| CIS-1.1.8 | No branch older than 90 days | A branch whose tip has an old committer date (`GIT_COMMITTER_DATE=2024-01-01T00:00:00Z git commit --allow-empty -m old`, pushed as `stale`) |
| CIS-1.1.9 | Build validation: required, no path filter, "Immediately when main is updated" | Build validation: optional |
| CIS-1.1.11 | Check for comment resolution: Required | — |
| CIS-1.1.12 | Status checks: required, genre `signing`, name `verify` (scan with `signatureStatusChecks: [signing/verify]`) | — |
| CIS-1.1.13 | Limit merge types: Squash merge and Rebase and fast-forward only | Basic merge and Semi-linear merge allowed |
| CIS-1.1.14 | No bypass holders | Project Administrators granted "Bypass policies when pushing" |
| CIS-1.1.15 | Any required policy on main; nobody holds "Bypass policies when pushing" | No required policy |
| CIS-1.1.16 | Nobody holds Force push on main (remove the branch creator's own grant at Repositories -> app -> Security -> main) | Contributors granted Force push |
| CIS-1.1.17 | A required policy on main, and nobody with both Force push and "Bypass policies when pushing" | As 1.1.16 |
| CIS-1.2.1 | `SECURITY.md` at the root of main | none |
| CIS-1.2.2 | Only Project Administrators hold Create repository (the default) | Contributors granted Create repository at All Repositories -> Security |
| CIS-1.2.3 | Delete repository held by administrators only (the default) | Contributors granted Delete repository on `app` |
| CIS-1.3.1 | Every user has signed in within 90 days | One user invited and never signed in (status *pending*) |
| CIS-1.3.3 | 2 to 5 people in Project Collection Administrators | Decided by thresholds: replay with `minOrgAdmins: 6` |
| CIS-1.3.7 | Two named people, not organization administrators, hold Manage permissions on `app` | An Entra group in Project Administrators (a lower bound: may FAIL, never PASS) |
| CIS-1.3.8 | Project Valid Users hold Read only (the default) | Project Valid Users granted Contribute on `app` |
| CIS-1.5.1 | Advanced Security on, with "Block secrets on push" | Advanced Security off |

The policy *scopes* matter as much as the settings, because how the server
answers "which policies apply to this branch" is the largest inference here.
Give the organization one of each:

- in `recon-hardened`, the minimum-reviewer policy set project-wide at
  Project settings -> Repositories -> All Repositories -> Policies -> "Protect
  the default branch of each repository" (scope `DefaultBranch`, no ref);
- in `recon-hardened`, a second policy on the pattern `release/*` across all
  repositories (scope `Prefix`, no repository), and a `release/1.0` branch;
- the remaining policies on `app`'s `main` itself (scope `Exact`);
- in `recon-weak`, two more build validation policies on `app`, one "After 12
  hours if main has been updated" and one "Never", so the expiry settings can
  be read off all three.

## What each capture settles

The fetcher's inferences, the capture that confirms or refutes each, and what
the bench reports meanwhile if the inference is wrong.

| # | The fetcher assumes | If wrong, the bench reports | Settled by | Look for |
|---|---|---|---|---|
| I-1 | `git/policy/configurations?repositoryId&refName` returns every policy that applies to the branch, project-wide and `DefaultBranch` scopes included | the policy-based controls on that repository go MANUAL (the answer is cross-checked against the project list both ways) | `16-policies-project`, `17-policies-branch` | every policy in 16 whose scope covers `app`/`main` appears in 17, and nothing else does |
| I-2 | `matchKind` is `Exact`, `Prefix` or `DefaultBranch` (with `refName` null), compared case-insensitively; refs compare case-sensitively | an unknown kind makes the scope unknown, so MANUAL | `16-policies-project` | the spelling of `matchKind` for each scope set up above |
| I-3 | Paged lists continue through an `x-ms-continuationtoken` header (projects, refs, policies) or a body `continuationToken` (entitlements) | a list that pages differently is refused as incomplete rather than truncated | `04-projects-paging`, `11-refs-paging`, `16-policies-project-paging`, `30-user-entitlements` | the header on page 1, and page 2 being the next item rather than the first again |
| I-4 | With `X-TFS-FedAuthRedirect: Suppress`, a rejected credential gets 401; without it, 203 and a sign-in page | the preflight already treats 203, 401, 3xx and non-JSON 2xx alike as "credential rejected" | `00-no-credential`, `01-invalid-credential`, `02-invalid-credential-no-suppress` | 401 for 00/01, 203 or a redirect for 02 |
| I-5 | A missing PAT scope is 401 or 403 (or 203), never an empty 200 | an empty listing is the one answer that could read as "nobody holds it"; the fetcher refuses an empty project ACL (I-19) and treats a missing evaluation entry as incomplete, and run 2 checks nothing else slips through | run 2: `07`, `08`, `19`–`29`, `30`, `31` | no 200 with an empty `value` where run 1 had entries |
| I-6 | A repository that cannot be seen is 404 `TF401019`; a path that does not exist is 404 `TF401174` | anything else on the items API is unreadable, not "no SECURITY.md" | `14-items-absent-path`, `15-items-absent-repository` | the two error codes in `message`/`typeKey` |
| I-7 | `includeExtendedInfo=true` with `descriptors=` returns an entry for every descriptor asked about, explicit ACE or not, whose `effectiveAllow`/`effectiveDeny` include what it inherits from parent tokens | a descriptor with no entry makes the set incomplete, so the control can fail but not pass. Groups are evaluated in their own right and expanded, so a person's own answer is used only to take a personal deny back out | `27`–`29-acl-evaluate-*`, with members from `23` and `26` | an entry for every requested descriptor; a group whose only grant is on the project showing it on the branch token |
| I-8 | Project Collection Administrators' Git rights appear as an ACE on `repoV2`, not only as system permissions | if they were system-only, organization administrators would be missing from the bypass and force-push holders | `07-acl-organization` | the PCA descriptor among the `repoV2` entries |
| I-9 | A branch's creator receives an explicit ACE on that branch's token (Force push, Manage permissions) | the creator would be missing from force-push holders | `11-refs` (creator), `19-acl-repository` | an ACE for the creator's descriptor on the `refs/heads/6d00610069006e00/` token |
| I-10 | IMS `queryMembership=ExpandedDown` and Graph `Memberships?direction=down` agree on a group's members on Services | members found by one and not the other make the set a lower bound | `23`, `24`, `25` | the same people, by descriptor |
| I-11 | Entra groups are `aadgp.` subjects whose members are only partly known; everyone groups carry `SpecialType: EveryoneApplicationGroup` or the well-known names | Entra groups make sets lower bounds; an unrecognised everyone group would be counted as an ordinary group | `22-identities`, `25` | the subject prefixes and the `SpecialType` property |
| I-12 | A user who never signed in has `lastAccessedDate` `0001-01-01T00:00:00Z` and an invited one has status `pending` | users are unknown individually, and CIS-1.3.1 cannot pass while any is | `30-user-entitlements` | the pending user's two fields |
| I-13 | Projects carry `visibility` on the single-project GET even when the list omits it | missing visibility is unknown, and CIS-1.3.8 goes MANUAL | `04-projects`, `05-project` | `visibility` in 05 |
| I-14 | Build validation expiry is `queueOnSourceUpdateOnly` plus `validDuration`: false/0 immediately, true/N after N minutes, true/0 never | CIS-1.1.9 accepts only an unconditional, required build, so a misreading shows up as evidence, not a verdict | `16-policies-project` (recon-weak) | the three policies' settings |
| I-15 | Status check policies name their check as `statusGenre`/`statusName` | CIS-1.1.12 fails with the policies listed as evidence | `16-policies-project` | the field names on the `signing/verify` policy |
| I-16 | Advanced Security's `blockPushes` is null unless `includeAllProperties=true` | null is unknown, so CIS-1.5.1 goes MANUAL rather than FAIL | `31-advanced-security` | `blockPushes` present for `recon-hardened/app` |
| I-17 | Azure DevOps Server 2022 before 2022.1 rejects `api-version=7.1` with `VssVersionOutOfRangeException` (or another 400 naming the version), and 7.0 is accepted | the scan stops with exit 2 naming the version | run 4 on 2022 RTW: `03-preflight`, `03-preflight-7.0` | the error's `typeKey` and message |
| I-18 | `Retry-After` can arrive on a 200 and is honoured on any status | the client waits regardless; nothing to decide | any `.headers` file, if the run was throttled | the header on a 200 |
| I-19 | Every project has explicit entries on its All Repositories token (`repoV2/{project}`) for its default groups | an empty answer is treated as unreadable, so if this is wrong the permission-based controls of such a project go MANUAL | `08-acl-project` | entries for Project Administrators, Contributors and Readers |

Not settled by any capture, because they need a write or a person:

- **Force push plus "Bypass policies when pushing" can delete a branch protected
  by a required policy.** CIS-1.1.17 counts those holders as able to delete;
  check it in the sandbox by deleting `release/1.0` as such a user.
- **What "Allow (system)" covers.** If I-8 shows no PCA entry on `repoV2`,
  confirm in the UI (Project settings -> Repositories -> Security) what an
  organization administrator holds on `app`.

## Replay

The captures become tests in four steps, none of which has happened yet:

1. **Pseudonymize.** Replace names, e-mail addresses and display names
   consistently across a run's files (the same person becomes the same
   placeholder everywhere, including inside `ClaimsIdentity` descriptors), and
   leave GUIDs, security tokens and descriptor prefixes alone: the fetcher's
   behaviour depends on their shape.
2. **Promote.** Copy a reviewed run into
   `internal/scm/azuredevops/testdata/recon/<label>/`, keeping `index.tsv`,
   which maps each request to its status and file.
3. **Serve.** A replay handler in the stand-in answers each request from the
   capture whose path and query match (query order and `api-version` ignored).
   Evaluation requests (`descriptors=`) are answered by filtering the captured
   entries to the descriptors asked for, since the fetcher's candidate set will
   not match the probe's exactly. A request no capture covers gets 404 — which
   the fetcher reads as unreadable, so a gap in the capture shows up as
   `MANUAL`, never as `PASS`.
4. **Assert.** The fetcher runs against the replay and the evaluated report is
   compared, control by control, with the verdicts the table under *Setting up
   the organization* says each project must produce. Where a capture
   contradicts the stand-in, the stand-in is corrected and the inference above
   is marked confirmed or refuted, with the date.
