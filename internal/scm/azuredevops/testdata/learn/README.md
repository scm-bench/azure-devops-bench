# Microsoft Learn sample responses

These files are the sample responses printed on Microsoft's Azure DevOps REST
API reference (api-version 7.1), copied verbatim on 2026-10-02. The reference
is generated from the specifications Microsoft publishes, with their examples,
in [MicrosoftDocs/vsts-rest-api-specs](https://github.com/MicrosoftDocs/vsts-rest-api-specs)
under the MIT licence. The fetcher
tests serve them from the stand-in server, so the shapes the tests prove are
the shapes Microsoft documents — including its quirks: the project list carries
no `visibility`, the repository list omits `defaultBranch` for an empty
repository, Graph membership samples use bare base64 descriptors, and an
identity descriptor is a string although the reference calls it an object.

Where a test needs a shape no sample shows, it builds one in the same form and
says so beside it.

| file | page |
| --- | --- |
| projects-list.json | core/projects/list |
| repositories-list.json | git/repositories/list |
| repository-get.json | git/repositories/get-repository |
| refs-list.json | git/refs/list |
| stats-branches.json | git/stats/list |
| items-scope-path.json | git/items/get |
| policy-configurations-list.json | policy/configurations/list |
| acl-extended-info.json | security/access-control-lists/query (include extended info) |
| acl-filter-by-descriptors.json | security/access-control-lists/query (filter by descriptors) |
| identities-by-descriptors.json | ims/identities/read-identities (by identity descriptors) |
| identities-by-subject-descriptors.json | ims/identities/read-identities (by subject descriptors) |
| identities-by-name.json | ims/identities/read-identities (by name) |
| graph-memberships-down.json | graph/memberships/list (direction down) |

These are fixtures, not proof that a live organization answers the same way.
`hack/recon/probe.sh` captures the real responses; replaying those is how the
gap between the two gets closed.
