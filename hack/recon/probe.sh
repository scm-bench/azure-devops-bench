#!/usr/bin/env bash
# Tracing goes off before anything touches the token: `bash -x probe.sh` would
# otherwise print it in every expansion that carries it.
{ set +x; } 2>/dev/null
#
# hack/recon/probe.sh — capture, read-only, the Azure DevOps responses
# azure-devops-bench decides from.
#
# The fetcher's tests run against a stand-in organization built from
# Microsoft's published samples. Where the documentation is silent the
# stand-in encodes an inference, and every inference is written so that being
# wrong yields MANUAL rather than a false PASS. This script asks a real
# organization the same questions, so each inference can be checked and the
# stand-in corrected. README.md says which capture settles which inference.
#
#   export AZURE_DEVOPS_URL=https://dev.azure.com/fabrikam
#   export AZURE_DEVOPS_TOKEN=...        # in the environment, never as an argument
#   hack/recon/probe.sh [PROJECT [REPOSITORY]]
#
# Without PROJECT the first project is probed; without REPOSITORY, its first
# enabled repository that has a default branch. Pick ones whose settings you
# have arranged as README.md describes: the captures are only as informative
# as the configuration they record.
#
# Guarantees, each exercised by probe_test.go:
#   - every request is a GET, sent by get(), the only function that runs curl;
#   - redirects are never followed;
#   - the token is read from the environment and removed from it, handed to
#     curl on stdin (never in argv, where any user's `ps` would show it), never
#     printed, and replaced in every saved file should a response echo it;
#   - captures are written owner-only, under hack/recon/out/ unless
#     PROBE_OUT says otherwise; git ignores that directory.
#
# Optional settings:
#   PROBE_OUT            capture directory (default hack/recon/out/<host>-<time>)
#   PROBE_MAX_PAGES      pages to follow on a paged list (default 3)
#   PROBE_API_VERSION    api-version to ask for first (default 7.1; Azure
#                        DevOps Server 2022 before 2022.1 speaks only 7.0, which
#                        is tried on its own)
#   AZURE_DEVOPS_CA_FILE PEM bundle to trust instead of the system roots, for a
#                        Server behind a private CA
# Proxies come from the usual https_proxy / no_proxy variables, which curl reads.
set -euo pipefail
umask 077

PROBE_VERSION=1
GIT_NAMESPACE=2e9eb7ed-3c0a-47d4-87c1-0ffdd275fd87
MAX_PAGES=${PROBE_MAX_PAGES:-3}
API_VERSION=${PROBE_API_VERSION:-7.1}
# The descriptor lists sent in one URL stay under this many characters, as the
# fetcher's do.
MAX_QUERY=6000

die() {
	printf 'probe: %s\n' "$*" >&2
	exit 2
}

for tool in curl jq awk od iconv base64; do
	command -v "$tool" >/dev/null 2>&1 || die "$tool is required"
done
case $MAX_PAGES in '' | *[!0-9]*) die "PROBE_MAX_PAGES must be a number" ;; esac

# --- the credential ----------------------------------------------------------

[ -n "${AZURE_DEVOPS_URL:-}" ] || die "set AZURE_DEVOPS_URL, e.g. https://dev.azure.com/fabrikam"
[ -n "${AZURE_DEVOPS_TOKEN:-}" ] || die "set AZURE_DEVOPS_TOKEN to a PAT or a Microsoft Entra access token"
TOKEN=$AZURE_DEVOPS_TOKEN
# Out of the environment, so neither curl nor jq nor awk inherits it.
unset AZURE_DEVOPS_TOKEN
case $TOKEN in
*[!A-Za-z0-9._~+/=-]*)
	# Also what keeps the token safe inside curl's config syntax below.
	die "AZURE_DEVOPS_TOKEN holds characters no PAT or Entra token does; check how it was exported"
	;;
esac
# Every saved file has the token replaced wherever it occurs; a value this
# short would be found inside ordinary words and mangle the captures.
[ ${#TOKEN} -ge 20 ] || die "AZURE_DEVOPS_TOKEN is too short to be a PAT or an Entra token"

jwt_re='^eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$'
if [[ $TOKEN =~ $jwt_re ]]; then
	AUTH_METHOD=bearer
	AUTH_VALUE="Bearer $TOKEN"
	CREDENTIAL=$TOKEN
else
	# A PAT is Basic with an empty user name. printf is a builtin, so the
	# token reaches base64 on a pipe, not in an argument list.
	AUTH_METHOD=pat
	CREDENTIAL=$(printf ':%s' "$TOKEN" | base64 | tr -d '\n')
	AUTH_VALUE="Basic $CREDENTIAL"
fi
TOKEN_B64=$(printf '%s' "$TOKEN" | base64 | tr -d '\n')
INVALID_AUTH="Basic $(printf ':%s' 'azure-devops-bench-recon-not-a-credential' | base64 | tr -d '\n')"

# auth_config MODE prints the curl config line carrying the Authorization
# header, for curl to read on stdin: token, invalid, or none.
auth_config() {
	case $1 in
	token) printf 'header = "Authorization: %s"\n' "$AUTH_VALUE" ;;
	invalid) printf 'header = "Authorization: %s"\n' "$INVALID_AUTH" ;;
	none) : ;;
	esac
}

# --- where the organization lives --------------------------------------------

url=${AZURE_DEVOPS_URL%/}
case $url in
https://* | http://*) ;;
*://*) die "AZURE_DEVOPS_URL must be an https URL" ;;
*) url="https://$url" ;;
esac
scheme=${url%%://*}
rest=${url#*://}
case $rest in
*/*)
	host=${rest%%/*}
	path=/${rest#*/}
	;;
*)
	host=$rest
	path=
	;;
esac
case $host in *@*) die "AZURE_DEVOPS_URL carries credentials; put the token in AZURE_DEVOPS_TOKEN instead" ;; esac
case $rest in *\?* | *\#*) die "AZURE_DEVOPS_URL must not carry a query or a fragment" ;; esac
case $host in
\[*) hostname="${host%%]*}]" ;;
*) hostname=${host%%:*} ;;
esac
hostname=$(printf '%s' "$hostname" | tr '[:upper:]' '[:lower:]')
path=${path%/}

PROTO='=https'
if [ "$scheme" = http ]; then
	case $hostname in
	localhost | 127.0.0.1 | \[::1\] | *.localhost) PROTO='=http' ;;
	*) die "refusing to send the token in cleartext to $hostname; use https" ;;
	esac
fi

ENTITLEMENTS=
ADVSEC=
case $hostname in
dev.azure.com)
	org=${path#/}
	org=${org%%/*}
	[ -n "$org" ] || die "$url names no organization; use https://dev.azure.com/{organization}"
	[ "$path" = "/$org" ] || die "$url points inside the organization; use $scheme://dev.azure.com/$org and pass the project as an argument"
	DEPLOYMENT=services
	CORE="$scheme://dev.azure.com/$org"
	;;
*.visualstudio.com)
	org=${hostname%.visualstudio.com}
	case $path in '' | /[Dd]efault[Cc]ollection) ;; *) die "$url points inside the organization; use $scheme://$host" ;; esac
	DEPLOYMENT=services
	CORE="$scheme://$host"
	;;
*)
	[ -n "$path" ] || die "$url names no collection; Azure DevOps Server URLs look like https://$host/{collection}"
	org=${path##*/}
	DEPLOYMENT=server
	CORE="$scheme://$host$path"
	;;
esac
if [ "$DEPLOYMENT" = services ]; then
	IDENTITY="$scheme://vssps.dev.azure.com/$org"
	ENTITLEMENTS="$scheme://vsaex.dev.azure.com/$org"
	ADVSEC="$scheme://advsec.dev.azure.com/$org"
else
	# Server answers identities on the collection, and has no Graph, user
	# entitlement or Advanced Security API at all.
	IDENTITY=$CORE
fi

CA_ARGS=
if [ -n "${AZURE_DEVOPS_CA_FILE:-}" ]; then
	[ -r "$AZURE_DEVOPS_CA_FILE" ] || die "AZURE_DEVOPS_CA_FILE $AZURE_DEVOPS_CA_FILE is not readable"
	CA_ARGS=$AZURE_DEVOPS_CA_FILE
fi

# --- output ------------------------------------------------------------------

here=$(cd "$(dirname "$0")" && pwd)
OUT=${PROBE_OUT:-$here/out/$hostname-$(date -u +%Y%m%dT%H%M%SZ)}
mkdir -p "$OUT"
chmod 700 "$OUT"
[ ! -e "$OUT/index.tsv" ] || die "$OUT already holds a capture; choose another PROBE_OUT"
# The unscrubbed temporaries never outlive the run, however it ends.
trap 'rm -f "$OUT"/.*.raw "$OUT"/.*.hdr "$OUT"/.*.err "$OUT"/*.tmp 2>/dev/null' EXIT
printf 'id\tstatus\tcontent-type\trequest\n' >"$OUT/index.tsv"

# scrub FILE: the file with every form of the credential replaced, on stdout.
# awk reads the values from its environment — readable only by this user,
# unlike an argument list — one per line.
scrub() {
	PROBE_SCRUB="$TOKEN
$CREDENTIAL
$TOKEN_B64" awk '
		BEGIN { n = split(ENVIRON["PROBE_SCRUB"], secrets, "\n") }
		{
			line = $0
			for (i = 1; i <= n; i++) {
				s = secrets[i]
				if (s == "") continue
				out = ""
				while ((at = index(line, s)) > 0) {
					out = out substr(line, 1, at - 1) "[REDACTED]"
					line = substr(line, at + length(s))
				}
				line = out line
			}
			print line
		}' "$1"
}

# Keys whose values are secrets wherever they appear, defence in depth for
# JSON bodies: none of the APIs probed returns one, and a capture is the wrong
# place to find out otherwise. ACL "token" keys are security tokens, not
# credentials, and are kept.
JQ_SCRUB='def scrubbed:
	if type == "object" then
		with_entries(if (.key | ascii_downcase | test("password|secret|accesstoken|refreshtoken|authorization|cookie|privatekey|sessiontoken"))
			then .value = "[REDACTED]" else .value |= scrubbed end)
	elif type == "array" then map(scrubbed)
	else . end;
	scrubbed'

# Only these response headers are kept: the ones the fetcher reads, and the
# ones that explain a refusal. Set-Cookie and session identifiers never reach
# the disk.
keep_headers() {
	tr -d '\r' <"$1" | grep -iE '^(HTTP/|content-type:|x-ms-continuationtoken:|retry-after:|x-ratelimit-[a-z-]+:|location:|www-authenticate:|x-tfs-serviceerror:)' || true
}

header_value() {
	grep -i "^$2:" "$1" 2>/dev/null | tail -n 1 | cut -d: -f2- | sed 's/^ *//' || true
}

# enc VALUE: VALUE percent-encoded for a query string.
enc() { jq -rn --arg v "$1" '$v | @uri'; }

lower() { printf '%s' "$1" | tr '[:upper:]' '[:lower:]'; }

LAST_STATUS=
LAST_FILE=
LAST_HEADERS=

# get ID URL [AUTH [SUPPRESS]] — one GET, saved as ID.{json,html,body} with
# ID.headers beside it and a line in index.tsv. AUTH is token (default),
# invalid or none; SUPPRESS=no leaves out X-TFS-FedAuthRedirect. This is the
# only function that runs curl, and it can only send a GET.
get() {
	local id=$1 url=$2 auth=${3:-token} suppress=${4:-yes}
	local raw="$OUT/.$id.raw" hdr="$OUT/.$id.hdr" err="$OUT/.$id.err" status ctype out
	local -a args
	# No --location: a redirect is saved as the answer, never followed, and
	# --max-redirs 0 keeps it that way should a curlrc add one.
	args=(--request GET --silent --show-error --max-redirs 0 --proto "$PROTO"
		--connect-timeout 15 --max-time 180
		--header "Accept: application/json"
		--header "User-Agent: azure-devops-bench-recon/$PROBE_VERSION"
		--dump-header "$hdr" --output "$raw" --write-out '%{http_code}')
	if [ "$suppress" = yes ]; then
		args+=(--header "X-TFS-FedAuthRedirect: Suppress")
	fi
	if [ -n "$CA_ARGS" ]; then
		args+=(--cacert "$CA_ARGS")
	fi
	: >"$raw"
	: >"$hdr"
	status=$(auth_config "$auth" | curl --config - "${args[@]}" "$url" 2>"$err") || true
	[ -n "$status" ] || status=000
	ctype=$(header_value "$hdr" content-type | tr -d '\r')
	keep_headers "$hdr" >"$OUT/$id.headers"
	case $ctype in
	*json*) out="$OUT/$id.json" ;;
	*html*) out="$OUT/$id.html" ;;
	*) out="$OUT/$id.body" ;;
	esac
	scrub "$raw" >"$out.tmp"
	if [ "${out%.json}" != "$out" ] && jq "$JQ_SCRUB" "$out.tmp" >"$out" 2>/dev/null; then
		rm -f "$out.tmp"
	else
		mv "$out.tmp" "$out"
	fi
	if [ -s "$err" ]; then
		scrub "$err" >"$OUT/$id.curl-error"
	fi
	rm -f "$raw" "$hdr" "$err"
	printf '%s\t%s\t%s\t%s\n' "$id" "$status" "${ctype:-none}" "$url" >>"$OUT/index.tsv"
	printf '  %-34s %s\n' "$id" "$status"
	LAST_STATUS=$status
	LAST_FILE=$out
	LAST_HEADERS="$OUT/$id.headers"
}

# get_pages ID URL header|body [PAGES] — get, following continuation tokens
# from the x-ms-continuationtoken header or the body's continuationToken, up
# to PAGES (default PROBE_MAX_PAGES) pages saved as ID.p1, ID.p2, ...
get_pages() {
	local id=$1 url=$2 mode=$3 limit=${4:-$MAX_PAGES} page=1 next='' u sep
	while :; do
		u=$url
		if [ -n "$next" ]; then
			case $u in *\?*) sep='&' ;; *) sep='?' ;; esac
			u="$u${sep}continuationToken=$(enc "$next")"
		fi
		get "$id.p$page" "$u"
		if [ "$mode" = header ]; then
			next=$(header_value "$LAST_HEADERS" x-ms-continuationtoken)
		else
			next=$(jq -r '.continuationToken // empty' "$LAST_FILE" 2>/dev/null || true)
		fi
		if [ -z "$next" ] || [ "$page" -ge "$limit" ]; then
			break
		fi
		page=$((page + 1))
	done
}

# field FILE FILTER: a jq answer from a capture, or nothing.
field() { jq -r "$2 // empty" "$1" 2>/dev/null | head -n 1 || true; }

# utf16hex SEGMENT: the hex of SEGMENT's UTF-16LE bytes, as security tokens
# spell branch names.
utf16hex() { printf '%s' "$1" | iconv -f UTF-8 -t UTF-16LE | od -An -v -tx1 | tr -d ' \n'; }

branch_token() {
	local token name=${3#refs/heads/} segment
	token="repoV2/$(lower "$1")/$(lower "$2")/refs/heads/"
	local IFS=/
	set -f
	for segment in $name; do
		token="$token$(utf16hex "$segment")/"
	done
	set +f
	printf '%s' "$token"
}

# join_limited LIST: newline-separated values joined with commas, stopping
# before the encoded query would pass MAX_QUERY characters.
join_limited() {
	local joined='' size=0 v n
	while IFS= read -r v; do
		[ -n "$v" ] || continue
		n=$(($(enc "$v" | wc -c) + 3))
		if [ -n "$joined" ] && [ $((size + n)) -gt "$MAX_QUERY" ]; then
			break
		fi
		joined="${joined:+$joined,}$v"
		size=$((size + n))
	done
	printf '%s' "$joined"
}

printf 'probing %s (%s, %s credential), saving to %s\n' "$CORE" "$DEPLOYMENT" "$AUTH_METHOD" "$OUT"

# --- credentials and the preflight -------------------------------------------

V=$API_VERSION
get 00-no-credential "$CORE/_apis/projects?\$top=1&api-version=$V" none
get 01-invalid-credential "$CORE/_apis/projects?\$top=1&api-version=$V" invalid
get 02-invalid-credential-no-suppress "$CORE/_apis/projects?\$top=1&api-version=$V" invalid no
get 03-preflight "$CORE/_apis/projects?\$top=1&api-version=$V"
if [ "$LAST_STATUS" = 400 ] && grep -qi 'version' "$LAST_FILE"; then
	# Azure DevOps Server 2022 before 2022.1 tops out at 7.0; the fetcher
	# negotiates down the same way.
	V=7.0
	get 03-preflight-7.0 "$CORE/_apis/projects?\$top=1&api-version=$V"
fi
# 203 is Azure DevOps's sign-in page, the usual answer to a credential it
# does not accept: only a 200 carrying JSON is an accepted one.
if [ "$LAST_STATUS" != 200 ] || [ "${LAST_FILE%.json}" = "$LAST_FILE" ]; then
	die "the preflight answered $LAST_STATUS, so the credential is not accepted; the captures so far are in $OUT"
fi

# --- projects ----------------------------------------------------------------

get_pages 04-projects "$CORE/_apis/projects?stateFilter=wellFormed&api-version=$V" header
# One item to a page, so the continuation mechanism shows even in an
# organization too small to need it.
get_pages 04-projects-paging "$CORE/_apis/projects?stateFilter=wellFormed&\$top=1&api-version=$V" header 2
PROJECT=${1:-$(field "$OUT/04-projects.p1.json" '.value[0].name')}
[ -n "$PROJECT" ] || die "no project to probe; name one as the first argument"
get 05-project "$CORE/_apis/projects/$(enc "$PROJECT")?api-version=$V"
PID=$(field "$LAST_FILE" '.id')
[ -n "$PID" ] || die "project $PROJECT could not be read ($LAST_STATUS); the captures so far are in $OUT"

get 06-security-namespace "$CORE/_apis/securitynamespaces/$GIT_NAMESPACE?api-version=$V"
get 07-acl-organization "$CORE/_apis/accesscontrollists/$GIT_NAMESPACE?token=repoV2&recurse=false&includeExtendedInfo=false&api-version=$V"
get 08-acl-project "$CORE/_apis/accesscontrollists/$GIT_NAMESPACE?token=$(enc "repoV2/$(lower "$PID")")&recurse=false&includeExtendedInfo=false&api-version=$V"

# --- the repository ----------------------------------------------------------

get 09-repositories "$CORE/$PID/_apis/git/repositories?includeHidden=true&api-version=$V"
REPOSITORY=${2:-$(field "$LAST_FILE" '[.value[] | select(.isDisabled != true and .defaultBranch != null)][0].name')}
[ -n "$REPOSITORY" ] || die "project $PROJECT has no enabled repository with a default branch; name one as the second argument"
get 10-repository "$CORE/$PID/_apis/git/repositories/$(enc "$REPOSITORY")?api-version=$V"
RID=$(field "$LAST_FILE" '.id')
REF=$(field "$LAST_FILE" '.defaultBranch')
[ -n "$RID" ] && [ -n "$REF" ] || die "repository $REPOSITORY could not be read or has no default branch ($LAST_STATUS)"
BRANCH=${REF#refs/heads/}
VERSION_DESCRIPTOR="versionDescriptor.version=$(enc "$BRANCH")&versionDescriptor.versionType=branch"

get_pages 11-refs "$CORE/$PID/_apis/git/repositories/$RID/refs?filter=heads/&\$top=1000&api-version=$V" header
get_pages 11-refs-paging "$CORE/$PID/_apis/git/repositories/$RID/refs?filter=heads/&\$top=1&api-version=$V" header 2
CREATOR=$(jq -r --arg ref "$REF" '[.value[]? | select(.name == $ref)][0].creator.descriptor // empty' "$OUT/11-refs.p1.json" 2>/dev/null || true)
get 12-branch-stats "$CORE/$PID/_apis/git/repositories/$RID/stats/branches?api-version=$V"
get 13-items-root "$CORE/$PID/_apis/git/repositories/$RID/items?scopePath=/&recursionLevel=OneLevel&$VERSION_DESCRIPTOR&api-version=$V"
get 14-items-absent-path "$CORE/$PID/_apis/git/repositories/$RID/items?scopePath=/.azure-devops-bench-recon-absent&recursionLevel=OneLevel&$VERSION_DESCRIPTOR&api-version=$V"
get 15-items-absent-repository "$CORE/$PID/_apis/git/repositories/00000000-0000-0000-0000-000000000000/items?scopePath=/&recursionLevel=OneLevel&api-version=$V"

# --- branch policies ---------------------------------------------------------

get_pages 16-policies-project "$CORE/$PID/_apis/policy/configurations?\$top=100&api-version=$V" header
get_pages 16-policies-project-paging "$CORE/$PID/_apis/policy/configurations?\$top=1&api-version=$V" header 2
get_pages 17-policies-branch "$CORE/$PID/_apis/git/policy/configurations?repositoryId=$RID&refName=$(enc "$REF")&\$top=100&api-version=$V" header
get_pages 18-policies-repository "$CORE/$PID/_apis/git/policy/configurations?repositoryId=$RID&\$top=100&api-version=$V" header

# --- permissions and the identities behind them ------------------------------

get 19-acl-repository "$CORE/_apis/accesscontrollists/$GIT_NAMESPACE?token=$(enc "repoV2/$(lower "$PID")/$(lower "$RID")")&recurse=true&includeExtendedInfo=false&api-version=$V"

get 20-identity-collection-administrators "$IDENTITY/_apis/identities?searchFilter=General&filterValue=$(enc 'Project Collection Administrators')&queryMembership=None&api-version=$V"
PCA=$(field "$LAST_FILE" '.value[0].descriptor')
PCA_SUBJECT=$(field "$LAST_FILE" '.value[0].subjectDescriptor')
CREATOR_DESCRIPTOR=
if [ -n "$CREATOR" ]; then
	get 21-identity-branch-creator "$IDENTITY/_apis/identities?subjectDescriptors=$(enc "$CREATOR")&queryMembership=None&api-version=$V"
	CREATOR_DESCRIPTOR=$(field "$LAST_FILE" '.value[0].descriptor')
fi

# Candidates: every descriptor holding an entry on the organization, project,
# repository or any of its branches, plus the collection administrators and
# the default branch's creator — the fetcher's candidate set.
CANDIDATES=$({
	for f in "$OUT/07-acl-organization.json" "$OUT/08-acl-project.json" "$OUT/19-acl-repository.json"; do
		jq -r '.value[]?.acesDictionary // {} | keys[]' "$f" 2>/dev/null || true
	done
	printf '%s\n%s\n' "$PCA" "$CREATOR_DESCRIPTOR"
} | awk 'NF && !seen[tolower($0)]++')
if [ -n "$CANDIDATES" ]; then
	get 22-identities "$IDENTITY/_apis/identities?descriptors=$(enc "$(printf '%s\n' "$CANDIDATES" | join_limited)")&queryMembership=None&api-version=$V"
fi

SAMPLE_MEMBERS=
if [ -n "$PCA" ]; then
	get 23-collection-administrators-expanded "$IDENTITY/_apis/identities?descriptors=$(enc "$PCA")&queryMembership=ExpandedDown&api-version=$V"
	SAMPLE_MEMBERS=$(jq -r '.value[0].members[]? // empty' "$LAST_FILE" 2>/dev/null | grep -v '^Microsoft.TeamFoundation.Identity;S-1-9-' | head -n 5 || true)
	get 24-collection-administrators-direct "$IDENTITY/_apis/identities?descriptors=$(enc "$PCA")&queryMembership=Direct&api-version=$V"
fi
if [ "$DEPLOYMENT" = services ] && [ -n "$PCA_SUBJECT" ]; then
	get 25-collection-administrators-graph "$IDENTITY/_apis/graph/Memberships/$(enc "$PCA_SUBJECT")?direction=down&api-version=7.1-preview.1"
fi
PA=$(jq -r '.value[]? | select(.providerDisplayName? // "" | test("\\\\Project Administrators$")) | .descriptor' "$OUT/22-identities.json" 2>/dev/null | head -n 1 || true)
if [ -n "$PA" ]; then
	get 26-project-administrators-expanded "$IDENTITY/_apis/identities?descriptors=$(enc "$PA")&queryMembership=ExpandedDown&api-version=$V"
	SAMPLE_MEMBERS=$(printf '%s\n%s\n' "$SAMPLE_MEMBERS" "$(jq -r '.value[0].members[]? // empty' "$LAST_FILE" 2>/dev/null | grep -v '^Microsoft.TeamFoundation.Identity;S-1-9-' | head -n 5 || true)")
fi

# The server's own evaluation for the candidates and for a few users who hold
# rights only through a group: whether effectiveAllow folds a group's grant
# into a member's answer is one of the inferences under test.
EVALUATE=$(printf '%s\n%s\n' "$CANDIDATES" "$SAMPLE_MEMBERS" | awk 'NF && !seen[tolower($0)]++' | join_limited)
if [ -n "$EVALUATE" ]; then
	for target in "27-acl-evaluate-project repoV2/$(lower "$PID")" \
		"28-acl-evaluate-repository repoV2/$(lower "$PID")/$(lower "$RID")" \
		"29-acl-evaluate-branch $(branch_token "$PID" "$RID" "$REF")"; do
		get "${target%% *}" "$CORE/_apis/accesscontrollists/$GIT_NAMESPACE?token=$(enc "${target#* }")&descriptors=$(enc "$EVALUATE")&includeExtendedInfo=true&recurse=false&api-version=$V"
	done
fi

# --- users and Advanced Security (Services only) ------------------------------

if [ "$DEPLOYMENT" = services ]; then
	get_pages 30-user-entitlements "$ENTITLEMENTS/_apis/userentitlements?api-version=7.1" body
	get 31-advanced-security "$ADVSEC/_apis/management/enablement?includeAllProperties=true&api-version=7.2-preview.3"
fi

{
	printf 'probe version: %s\n' "$PROBE_VERSION"
	printf 'captured at:   %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
	printf 'organization:  %s\n' "$CORE"
	printf 'deployment:    %s\n' "$DEPLOYMENT"
	printf 'api-version:   %s\n' "$V"
	printf 'credential:    %s\n' "$AUTH_METHOD"
	printf 'project:       %s (%s)\n' "$PROJECT" "$PID"
	printf 'repository:    %s (%s), default branch %s\n' "$REPOSITORY" "$RID" "$REF"
} >"$OUT/probe.txt"

count=$(($(wc -l <"$OUT/index.tsv") - 1))
printf '\n%d responses saved to %s\n' "$count" "$OUT"
printf 'Every request was a GET. The captures hold no credential, but they do name\n'
printf 'projects, repositories, groups and people: review them before sharing, and\n'
printf 'never commit them.\n'
