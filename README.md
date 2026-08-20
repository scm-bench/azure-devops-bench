<!--
  The banner lives in scm-bench/.github (brand/), which is also where the
  organization profile and the uploaded avatar draw from, so there is one copy
  rather than one per repository. The URLs are absolute because a relative path
  cannot cross repositories.
-->
<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/scm-bench/.github/main/brand/banner-azure-devops-bench-dark-1760x440.png">
    <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/scm-bench/.github/main/brand/banner-azure-devops-bench-light-1760x440.png">
    <img src="https://raw.githubusercontent.com/scm-bench/.github/main/brand/banner-azure-devops-bench-light-1760x440.png" alt="azure-devops-bench — audit Azure DevOps against the CIS supply chain benchmark" width="880">
  </picture>
</p>

# azure-devops-bench

Audit **Azure DevOps** — Azure Repos and the project settings around it —
against the **Source Code** section of the
[CIS Software Supply Chain Security Guide](https://www.cisecurity.org/benchmark/software-supply-chain-security).

**Status: planned.** There is no code here yet. This repository exists so the
work has a home and a name before it has commits.

## What it will be

A read-only CLI, in the shape every bench in this family takes: capture a
normalized snapshot of an organization over the REST API, evaluate it with Rego
policies — one directory per control — and print what is misconfigured along with
the exact settings path to fix it.

Azure DevOps is the closest platform to the one already covered. Its
organization → project → repository layout, its branch policies, and its required
reviewers and build validation map onto the family's existing
[SCM snapshot schema](https://github.com/scm-bench/scm-bench/blob/main/docs/scm-snapshot.md)
directly. So this bench implements that schema rather than inventing one, and the
controls already written for Bitbucket become mostly a question of writing
another fetcher.

That claim is exactly what building this will test. A schema is only
platform-neutral once a second platform has been through it.

## Before contributing

- The [bench contract](https://github.com/scm-bench/scm-bench/blob/main/docs/bench-contract.md)
  — what a verdict, a control's metadata and a score are required to mean. Start
  here.
- The [SCM snapshot schema](https://github.com/scm-bench/scm-bench/blob/main/docs/scm-snapshot.md)
  — the shape this bench produces.
- [bitbucket-bench](https://github.com/scm-bench/bitbucket-bench) — the reference
  implementation of both. Read it before writing anything here.

The rule that outranks the rest: **a control that cannot be evaluated reports
`MANUAL`, never `PASS` or `FAIL`.** A scan is never credited for a question it
could not ask, and never penalised for one either.

## License

Apache 2.0. See [LICENSE](LICENSE).

<sub>Not affiliated with CIS or Microsoft.</sub>
