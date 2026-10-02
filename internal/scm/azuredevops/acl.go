package azuredevops

import (
	"context"
	"encoding/hex"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf16"

	"github.com/scm-bench/azure-devops-bench/internal/scm"
)

// The Git Repositories permission bits this bench decides on.
const (
	bitGenericRead             int64 = 2
	bitForcePush               int64 = 8
	bitPolicyExempt            int64 = 128
	bitCreateRepository        int64 = 256
	bitDeleteRepository        int64 = 512
	bitManagePermissions       int64 = 8192
	bitPullRequestBypassPolicy int64 = 32768
)

// Security tokens in the Git Repositories namespace.
//
//	repoV2                                   every repository in every project
//	repoV2/{projectId}                       every repository in one project
//	repoV2/{projectId}/{repoId}              one repository
//	repoV2/{projectId}/{repoId}/refs/heads/{segment}/…/   one branch
//
// Each path segment of a branch name is encoded as the hex of its UTF-16LE
// bytes, with "/" kept as the separator, so "main" is 6d00610069006e00/ and
// "user/x" is 7500730065007200/7800/ (Microsoft, "Git repo tokens for the
// security service").
func projectToken(projectID string) string { return "repoV2/" + strings.ToLower(projectID) }

func repoToken(projectID, repoID string) string {
	return projectToken(projectID) + "/" + strings.ToLower(repoID)
}

func branchToken(projectID, repoID, ref string) string {
	name := strings.TrimPrefix(ref, "refs/heads/")
	var b strings.Builder
	b.WriteString(repoToken(projectID, repoID))
	b.WriteString("/refs/heads/")
	for _, segment := range strings.Split(name, "/") {
		b.WriteString(encodeTokenSegment(segment))
		b.WriteString("/")
	}
	return b.String()
}

func encodeTokenSegment(s string) string {
	units := utf16.Encode([]rune(s))
	raw := make([]byte, 0, len(units)*2)
	for _, u := range units {
		raw = append(raw, byte(u), byte(u>>8))
	}
	return hex.EncodeToString(raw)
}

// tokenCovers reports whether permissions set on parent are inherited by
// child: the same token, or an ancestor in the slash-separated hierarchy.
// Security tokens are case-insensitive.
func tokenCovers(parent, child string) bool {
	p := strings.TrimSuffix(strings.ToLower(parent), "/")
	c := strings.TrimSuffix(strings.ToLower(child), "/")
	return c == p || strings.HasPrefix(c, p+"/")
}

// queryACLs reads the access control lists at a token, without the server's
// evaluation — the explicit entries, which is where candidate holders come
// from.
func (f *Fetcher) queryACLs(ctx context.Context, token string, recurse bool) ([]apiACL, error) {
	query := url.Values{
		"token":               []string{token},
		"recurse":             []string{strconv.FormatBool(recurse)},
		"includeExtendedInfo": []string{"false"},
		"api-version":         []string{f.client.APIVersion()},
	}
	return getAll[apiACL](ctx, f.client, ServiceCore, "/_apis/accesscontrollists/"+scm.GitNamespaceID, query, pageOptions{})
}

// aclEval is the server's own evaluation of a set of identities on one token.
type aclEval struct {
	// complete is false when any identity asked about came back without an
	// evaluation. Its rights are then unknown, and so is every set built from
	// them.
	complete bool
	allow    map[string]int64
	deny     map[string]int64
}

func (e aclEval) has(descriptor string, bit int64) bool {
	k := descriptorKey(descriptor)
	return e.allow[k]&bit != 0 && e.deny[k]&bit == 0
}

func (e aclEval) denied(descriptor string, bit int64) bool {
	return e.deny[descriptorKey(descriptor)]&bit != 0
}

// evaluate asks the server for the effective rights of each descriptor on a
// token, using extendedInfo.effectiveAllow: the combination of every explicit
// and inherited permission for the identity, which is what Azure DevOps itself
// uses to decide whether a request is allowed and what its permissions page
// shows. Re-implementing inheritance from raw entries would mean
// re-implementing the rules for "Allow (inherited)", explicit-beats-inherited
// and deny-beats-allow, and getting one wrong is a wrong verdict.
func (f *Fetcher) evaluate(ctx context.Context, token string, descriptors []string) (aclEval, error) {
	out := aclEval{complete: true, allow: map[string]int64{}, deny: map[string]int64{}}
	if len(descriptors) == 0 {
		return out, nil
	}
	for _, batch := range chunk(descriptors) {
		query := url.Values{
			"token":               []string{token},
			"descriptors":         []string{strings.Join(batch, ",")},
			"includeExtendedInfo": []string{"true"},
			"recurse":             []string{"false"},
			"api-version":         []string{f.client.APIVersion()},
		}
		acls, err := getAll[apiACL](ctx, f.client, ServiceCore, "/_apis/accesscontrollists/"+scm.GitNamespaceID, query, pageOptions{})
		if err != nil {
			return aclEval{}, err
		}
		var acl *apiACL
		for i := range acls {
			if strings.EqualFold(strings.TrimSuffix(acls[i].Token, "/"), strings.TrimSuffix(token, "/")) {
				acl = &acls[i]
				break
			}
		}
		if acl == nil {
			// The documented behaviour is an entry for the token with one
			// ACE per requested identity, evaluated, even where none is set
			// explicitly. Anything else means the evaluation this bench
			// relies on did not happen, and nobody's rights are known.
			out.complete = false
			continue
		}
		byDescriptor := map[string]apiACE{}
		for key, ace := range acl.AcesDictionary {
			d := ace.Descriptor
			if d == "" {
				d = key
			}
			byDescriptor[descriptorKey(d)] = ace
		}
		evaluated := acl.IncludeExtendedInfo != nil && *acl.IncludeExtendedInfo
		for _, d := range batch {
			ace, ok := byDescriptor[descriptorKey(d)]
			if !ok {
				out.complete = false
				continue
			}
			switch {
			case ace.ExtendedInfo != nil:
				// Zero fields are omitted on the wire, so an absent
				// effectiveDeny inside a present extendedInfo is zero.
				out.allow[descriptorKey(d)] = ace.ExtendedInfo.EffectiveAllow
				out.deny[descriptorKey(d)] = ace.ExtendedInfo.EffectiveDeny
			case evaluated:
				// The ACL says it was evaluated and this entry carries no
				// extended information: every value was zero and omitted.
				out.allow[descriptorKey(d)] = 0
				out.deny[descriptorKey(d)] = 0
			default:
				// Explicit bits alone would miss every inherited grant,
				// which is how a group holding Force push at the project
				// level would disappear from the branch's answer.
				out.complete = false
			}
		}
	}
	return out, nil
}

// holders is who holds a bit, as granted: the identities whose own effective
// rights include it.
type holders struct {
	// granted are the holders before expansion.
	granted []*principal
	// denied are people and service identities whose own evaluation denies
	// the bit. A deny on the identity itself beats an allow through any group
	// — Azure DevOps's documented rule — so they are taken back out of the
	// expansion of a group that holds it.
	denied map[string]bool
	// complete is false when the evaluation was partial or a holder could not
	// be resolved to a person or a group.
	complete bool
}

// holdersOf picks the identities holding bit out of an evaluation.
func holdersOf(eval aclEval, resolved map[string]*principal, candidates []string, bit int64) holders {
	h := holders{denied: map[string]bool{}, complete: eval.complete}
	for _, d := range candidates {
		k := descriptorKey(d)
		if eval.denied(d, bit) {
			h.denied[k] = true
			continue
		}
		if !eval.has(d, bit) {
			continue
		}
		p, ok := resolved[k]
		if !ok {
			// Someone holds it and the scan cannot tell who: a person, or a
			// group of a thousand. The set is a lower bound from here.
			h.complete = false
			continue
		}
		h.granted = append(h.granted, p)
	}
	return h
}

// expandHolders turns holders into the set of people and service identities
// they reach.
func (f *Fetcher) expandHolders(ctx context.Context, h holders) *pset {
	out := f.dir.expandAll(ctx, h.granted)
	for k := range h.denied {
		delete(out.humans, k)
		delete(out.services, k)
	}
	out.complete = out.complete && h.complete
	return out
}
