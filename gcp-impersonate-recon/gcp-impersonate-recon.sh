#!/usr/bin/env bash
#
# gcp-impersonate-recon.sh
#
# Mint access tokens for a set of target service accounts via a delegation
# chain, then use each minted token to gain situational awareness AS that
# identity:
#     - list visible projects (cloudresourcemanager.projects.list)
#     - test a matrix of IAM permissions against one or more projects
#
# Two minting primitives, both delegation-aware (-m / --method):
#   token  generateAccessToken  -> direct token  (needs iam.serviceAccounts.getAccessToken)
#   jwt    signJwt              -> sign a self-issued JWT (needs iam.serviceAccounts.signJwt),
#                                  then exchange it at oauth2/token for an access token
#   auto   try token, fall back to jwt when getAccessToken is denied (default)
# getAccessToken and signJwt are DIFFERENT permissions, so a delegate may hold one
# but not the other. Custom roles like svcDelegation / svcJwtSigner often grant only
# signJwt + delegation, in which case you want -m jwt.
#
# Delegation direction: the SA in --sa is the final identity you get a token for;
# --delegate SAs are the intermediate hops your caller walks to reach it. Your caller
# needs getAccessToken/signJwt (or implicitDelegation) on the first delegate, each
# delegate needs it on the next, and the last delegate needs it on the target. You
# never get a token for a delegate itself, so a target that is also a delegate is
# skipped.
#
# Everything is rooted in your gcloud credentials (or --caller-token-file), so you
# only ever reach what your own principal is authorized to reach.
# Intended for authorized red-team / lab use.
#
# ---------------------------------------------------------------------------
# Usage:
#   ./gcp-impersonate-recon.sh (-f sa.txt | -s "sa1,sa2" | SA...) [options]
#
# Target service accounts (combine freely):
#   -f, --sa-file FILE        File with one target SA per line (# comments ok)
#   -s, --sa "SA[,SA...]"     Target SA(s), comma/space separated; repeatable
#       (bare positional args are also treated as targets)
#
# Delegation:
#   -d, --delegate SA         Delegate hop; repeat in chain order (optional)
#   -m, --method M            token | jwt | auto   (default auto)
#
# Recon:
#   -p, --project ID|NUMBER   Project to run the permission matrix against; repeatable
#       --enum-discovered     Also run the matrix on every project the identity can see
#       --perms-file FILE     Custom permission list (one per line) instead of the default set
#       --scope "S[,S...]"    OAuth scope(s) (default: cloud-platform)
#       --no-list             Skip project listing
#       --no-recon            Mint tokens only; no listing or permission testing
#
# Misc:
#   Caller (chain-root) token source, in precedence order:
#   -t, --caller-token T      Token value on the CLI (handy; visible in ps/proc — see note)
#       --caller-token-file F Read the caller bearer token from a file
#       CALLER_TOKEN env      e.g.  CALLER_TOKEN="$token" ./gcp-impersonate-recon.sh ...
#       (default)             gcloud auth print-access-token
#   -o, --outdir DIR          Output directory (default: impersonate-<timestamp>)
#       --throttle SECONDS    Delay between per-permission fallback calls (default 0.1)
#   -h, --help                This help
# ---------------------------------------------------------------------------

set -uo pipefail

# defaults
DELEGATES=(); TARGETS=(); PROJECTS=()
SCOPES="https://www.googleapis.com/auth/cloud-platform"
OUTDIR="impersonate-$(date +%Y%m%d-%H%M%S)"
CALLER_TOKEN_FILE=""; CALLER_TOKEN_ARG=""; PERMS_FILE=""
DO_LIST=1; DO_RECON=1; ENUM_DISCOVERED=0
THROTTLE="0.1"; METHOD="auto"
MINT_ERR=""; MINT_OUT=""

DEFAULT_PERMS=(
    resourcemanager.projects.get resourcemanager.projects.getIamPolicy
    serviceusage.services.list compute.instances.list compute.instances.get
    storage.buckets.list storage.objects.list bigquery.datasets.list
    bigquery.tables.list cloudfunctions.functions.list cloudfunctions.functions.get
    artifactregistry.repositories.list pubsub.topics.list pubsub.subscriptions.list
    iam.serviceAccounts.list iam.roles.list run.services.list run.services.get
    run.routes.invoke secretmanager.secrets.list secretmanager.versions.access
)

IAMCRED="https://iamcredentials.googleapis.com/v1"
CRM="https://cloudresourcemanager.googleapis.com/v1"
TOKEN_URI="https://oauth2.googleapis.com/token"

log()  { echo "[*] $*"; }
ok()   { echo "✓ $*"; }
warn() { echo "[!] $*" >&2; }
die()  { echo "[x] $*" >&2; exit 1; }
# robust: print the Usage banner between the marker and the next dashed rule
usage() { sed -n '/^# Usage:/,/^# ---/p' "$0" | sed '$d; s/^# \{0,1\}//'; exit "${1:-0}"; }

# curl that passes the bearer token via a config fd, keeping it out of argv/logs.
authcurl() { local tok="$1"; shift; curl -sS \
    --config <(printf 'header = "Authorization: Bearer %s"\n' "$tok") "$@"; }

# arg parsing
while (($#)); do
    case "$1" in
        -f|--sa-file)   PERMS_SA_FILE="$2"; shift 2;;   # read below
        -s|--sa)        IFS=', ' read -ra _t <<<"$2"; TARGETS+=("${_t[@]}"); shift 2;;
        -d|--delegate)  DELEGATES+=("$2"); shift 2;;
        -m|--method)    METHOD="$2"; shift 2;;
        -p|--project)   PROJECTS+=("$2"); shift 2;;
        --enum-discovered) ENUM_DISCOVERED=1; shift;;
        --perms-file)   PERMS_FILE="$2"; shift 2;;
        --scope)        SCOPES="$2"; shift 2;;
        --no-list)      DO_LIST=0; shift;;
        --no-recon)     DO_RECON=0; DO_LIST=0; shift;;
        -t|--caller-token)   CALLER_TOKEN_ARG="$2"; shift 2;;
        --caller-token-file) CALLER_TOKEN_FILE="$2"; shift 2;;
        -o|--outdir)    OUTDIR="$2"; shift 2;;
        --throttle)     THROTTLE="$2"; shift 2;;
        -h|--help)      usage 0;;
        -*)             die "unknown option: $1 (try --help)";;
        *)              TARGETS+=("$1"); shift;;
    esac
done

command -v jq   >/dev/null 2>&1 || die "jq is required"
command -v curl >/dev/null 2>&1 || die "curl is required"
case "$METHOD" in token|jwt|auto) ;; *) die "invalid --method: $METHOD (token|jwt|auto)";; esac

# target SAs from file (guard handles a final line with no trailing newline)
if [[ -n "${PERMS_SA_FILE:-}" ]]; then
    [[ -r "$PERMS_SA_FILE" ]] || die "cannot read SA file: $PERMS_SA_FILE"
    while IFS= read -r line || [[ -n "$line" ]]; do
        line="${line%%$'\r'}"; line="${line#"${line%%[![:space:]]*}"}"
        [[ -z "$line" || "$line" == \#* ]] && continue
        TARGETS+=("$line")
    done < "$PERMS_SA_FILE"
fi
((${#TARGETS[@]})) || die "no target service accounts given (use -f, -s, or positional args)"

# scopes -> array
IFS=',' read -ra SCOPE_ARR <<<"$SCOPES"
for i in "${!SCOPE_ARR[@]}"; do SCOPE_ARR[$i]="${SCOPE_ARR[$i]//[[:space:]]/}"; done

# permission set
if [[ -n "$PERMS_FILE" ]]; then
    [[ -r "$PERMS_FILE" ]] || die "cannot read perms file: $PERMS_FILE"
    mapfile -t PERM_SET < <(grep -vE '^[[:space:]]*(#|$)' "$PERMS_FILE")
else
    PERM_SET=("${DEFAULT_PERMS[@]}")
fi

# caller (chain-root) token, resolved once. precedence, most explicit first:
#   --caller-token (-t)  >  --caller-token-file  >  $CALLER_TOKEN env  >  gcloud
if [[ -n "$CALLER_TOKEN_ARG" ]]; then
    CALLER_TOKEN="$CALLER_TOKEN_ARG"
    warn "note: -t/--caller-token places the token in argv (visible via ps / /proc/<pid>/cmdline); use \$CALLER_TOKEN on shared hosts"
elif [[ -n "$CALLER_TOKEN_FILE" ]]; then
    [[ -r "$CALLER_TOKEN_FILE" ]] || die "cannot read caller token file: $CALLER_TOKEN_FILE"
    CALLER_TOKEN="$(<"$CALLER_TOKEN_FILE")"
elif [[ -n "${CALLER_TOKEN:-}" ]]; then
    :   # inherited from the environment, e.g.  CALLER_TOKEN="$token" ./gcp-impersonate-recon.sh ...
else
    command -v gcloud >/dev/null 2>&1 \
        || die "no token source: use -t, --caller-token-file, \$CALLER_TOKEN, or install gcloud"
    CALLER_TOKEN="$(gcloud auth print-access-token 2>/dev/null)" \
        || die "failed to obtain caller access token"
fi
CALLER_TOKEN="${CALLER_TOKEN//[[:space:]]/}"
[[ -n "$CALLER_TOKEN" ]] || die "empty caller token"

umask 077
mkdir -p "$OUTDIR" || die "cannot create outdir: $OUTDIR"

# delegates -> JSON array ["projects/-/serviceAccounts/<email>", ...]
delegates_json() {
    if ((${#DELEGATES[@]})); then
        printf '%s\n' "${DELEGATES[@]}" \
            | jq -R 'select(length>0)|"projects/-/serviceAccounts/\(.)"' | jq -sc .
    else
        echo '[]'
    fi
}

# is_delegate SA -> 0 if SA is present in the delegate chain
is_delegate() {
    local sa="$1" d
    ((${#DELEGATES[@]})) || return 1
    for d in "${DELEGATES[@]}"; do
        [[ "$sa" == "$d" ]] && return 0
    done
    return 1
}

# functions

# mint_via_token TARGET: on success sets MINT_OUT="accessToken<TAB>expireTime"; else MINT_ERR.
# Call DIRECTLY (not in $()) so the globals survive.
mint_via_token() {
    local target="$1" del_json scope_json body resp http payload
    del_json="$(delegates_json)"
    scope_json=$(printf '%s\n' "${SCOPE_ARR[@]}" | jq -R 'select(length>0)' | jq -sc .)
    body=$(jq -nc --argjson del "$del_json" --argjson sc "$scope_json" \
        '{delegates:$del, scope:$sc}')
    resp=$(authcurl "$CALLER_TOKEN" -X POST -w $'\n%{http_code}' \
        -H "Content-Type: application/json" -d "$body" \
        "$IAMCRED/projects/-/serviceAccounts/${target}:generateAccessToken" 2>/dev/null)
    http=${resp##*$'\n'}; payload=${resp%$'\n'*}
    if [[ "$http" != "200" ]]; then
        MINT_ERR="generateAccessToken HTTP $http: $(jq -rc '.error.message? // empty' <<<"$payload" 2>/dev/null)"
        return 1
    fi
    MINT_OUT=$(jq -r '"\(.accessToken)\t\(.expireTime)"' <<<"$payload")
    return 0
}

# mint_via_jwt TARGET: signJwt a self-issued assertion (iss=target, NO sub -- matches
# the SA self-impersonation flow), then exchange it at oauth2/token for a token.
# On success sets MINT_OUT="accessToken<TAB>expireTime"; else MINT_ERR. Call DIRECTLY.
mint_via_jwt() {
    local target="$1" del_json scope_str iat exp claims req resp http signed
    local xresp xhttp at ein expts
    del_json="$(delegates_json)"
    scope_str=$(printf '%s ' "${SCOPE_ARR[@]}"); scope_str="${scope_str% }"
    iat=$(date +%s); exp=$((iat + 3600))
    claims=$(jq -nc --arg iss "$target" --arg scope "$scope_str" --arg aud "$TOKEN_URI" \
        --argjson iat "$iat" --argjson exp "$exp" \
        '{iss:$iss, scope:$scope, aud:$aud, iat:$iat, exp:$exp}')
    req=$(jq -nc --argjson del "$del_json" --arg payload "$claims" \
        '{delegates:$del, payload:$payload}')
    resp=$(authcurl "$CALLER_TOKEN" -X POST -w $'\n%{http_code}' \
        -H "Content-Type: application/json" -d "$req" \
        "$IAMCRED/projects/-/serviceAccounts/${target}:signJwt" 2>/dev/null)
    http=${resp##*$'\n'}; resp=${resp%$'\n'*}
    if [[ "$http" != "200" ]]; then
        MINT_ERR="signJwt HTTP $http: $(jq -rc '.error.message? // empty' <<<"$resp" 2>/dev/null)"
        return 1
    fi
    signed=$(jq -r '.signedJwt // empty' <<<"$resp")
    [[ -n "$signed" ]] || { MINT_ERR="signJwt returned no signedJwt"; return 1; }
    # exchange the self-signed JWT for an access token (jwt-bearer grant; assertion IS the auth)
    xresp=$(curl -sS -X POST -w $'\n%{http_code}' \
        --data-urlencode 'grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer' \
        --data-urlencode "assertion=$signed" \
        "$TOKEN_URI" 2>/dev/null)
    xhttp=${xresp##*$'\n'}; xresp=${xresp%$'\n'*}
    if [[ "$xhttp" != "200" ]]; then
        MINT_ERR="jwt-bearer exchange HTTP $xhttp: $(jq -rc '(.error_description // .error)? // empty' <<<"$xresp" 2>/dev/null)"
        return 1
    fi
    at=$(jq -r '.access_token // empty' <<<"$xresp")
    ein=$(jq -r '.expires_in // 3600' <<<"$xresp")
    [[ -n "$at" ]] || { MINT_ERR="jwt-bearer exchange returned no access_token"; return 1; }
    expts=$(date -u -d "@$(( $(date +%s) + ein ))" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo "epoch+${ein}s")
    MINT_OUT="${at}"$'\t'"${expts}"
    return 0
}

# mint_token TARGET -> prints "accessToken<TAB>expireTime<TAB>method"; honours $METHOD.
# Minters are called DIRECTLY (not in $()) so their MINT_OUT/MINT_ERR globals survive.
mint_token() {
    local target="$1" terr=""
    MINT_ERR=""; MINT_OUT=""
    if [[ "$METHOD" != "jwt" ]]; then
        if mint_via_token "$target"; then printf '%s\tgenerateAccessToken\n' "$MINT_OUT"; return 0; fi
        terr="$MINT_ERR"
        [[ "$METHOD" == "token" ]] && { warn "mint failed for $target -> $terr"; return 1; }
    fi
    if [[ "$METHOD" != "token" ]]; then
        if mint_via_jwt "$target"; then printf '%s\tsignJwt\n' "$MINT_OUT"; return 0; fi
        if [[ "$METHOD" == "jwt" ]]; then
            warn "mint failed for $target -> $MINT_ERR"
        else
            warn "mint failed for $target -> [token] ${terr:-n/a}  /  [jwt] $MINT_ERR"
        fi
    fi
    return 1
}

# list_projects TOKEN -> tab rows: projectId<TAB>projectNumber<TAB>state<TAB>name
list_projects() {
    local token="$1" pageToken="" url resp http body
    while :; do
        url="$CRM/projects?pageSize=1000"
        [[ -n "$pageToken" ]] && url+="&pageToken=$pageToken"
        resp=$(authcurl "$token" -w $'\n%{http_code}' "$url" 2>/dev/null)
        http=${resp##*$'\n'}; body=${resp%$'\n'*}
        [[ "$http" == "200" ]] || { warn "projects.list HTTP $http: $(jq -rc '.error.message? // empty' <<<"$body" 2>/dev/null)"; return 1; }
        jq -r '.projects[]? | "\(.projectId)\t\(.projectNumber)\t\(.lifecycleState)\t\(.name)"' <<<"$body"
        pageToken=$(jq -r '.nextPageToken // empty' <<<"$body")
        [[ -z "$pageToken" ]] && break
    done
}

# test_perms TOKEN PROJECT PERM... -> granted perms, one per line
test_perms() {
    local token="$1" project="$2"; shift 2
    local -a want=("$@") granted=() chunk
    local i=0 body resp http perm r c1
    while (( i < ${#want[@]} )); do
        chunk=( "${want[@]:i:100}" ); i=$(( i + 100 ))
        body=$(printf '%s\n' "${chunk[@]}" | jq -R . | jq -sc '{permissions:.}')
        resp=$(authcurl "$token" -X POST -w $'\n%{http_code}' \
            -H "Content-Type: application/json" -d "$body" \
            "$CRM/projects/${project}:testIamPermissions" 2>/dev/null)
        http=${resp##*$'\n'}; body=${resp%$'\n'*}
        if [[ "$http" == "200" ]]; then
            while IFS= read -r p; do [[ -n "$p" ]] && granted+=("$p"); done \
                < <(jq -r '.permissions[]?' <<<"$body")
        elif [[ "$http" == "400" ]]; then
            warn "$project: batch rejected (likely an invalid permission string); per-permission fallback"
            for perm in "${chunk[@]}"; do
                r=$(authcurl "$token" -X POST -w $'\n%{http_code}' \
                    -H "Content-Type: application/json" \
                    -d "$(jq -nc --arg p "$perm" '{permissions:[$p]}')" \
                    "$CRM/projects/${project}:testIamPermissions" 2>/dev/null)
                c1=${r##*$'\n'}; r=${r%$'\n'*}
                [[ "$c1" == "200" ]] && [[ "$(jq -r '.permissions|length' <<<"$r" 2>/dev/null)" -gt 0 ]] \
                    && granted+=("$perm")
                sleep "$THROTTLE"
            done
        else
            warn "$project: testIamPermissions HTTP $http: $(jq -rc '.error.message? // empty' <<<"$body" 2>/dev/null)"
        fi
    done
    ((${#granted[@]})) && printf '%s\n' "${granted[@]}"
    return 0
}

# main
log "targets: ${#TARGETS[@]} | delegates: ${#DELEGATES[@]} | method: $METHOD | outdir: $OUTDIR"
minted=0; skipped=0; denied=0
for target in "${TARGETS[@]}"; do
    saf="${target//[^a-zA-Z0-9._-]/_}"

    # a target that is also a delegate is degenerate: you can't mint a token for
    # the delegate itself, so skip it instead of guaranteeing a 403.
    if is_delegate "$target"; then
        warn "skipping $target (also a delegate; you can't mint a token for the delegate itself)"
        skipped=$((skipped+1))
        continue
    fi

    log "impersonating $target"

    if ! read -r token expire method < <(mint_token "$target"); then
        denied=$((denied+1))
        continue
    fi
    minted=$((minted+1))
    printf '%s' "$token" > "$OUTDIR/${saf}.token"      # no trailing newline (gcloud-friendly)
    ok "$target -> token acquired via $method (expires $expire) [$OUTDIR/${saf}.token]"

    recon=$(jq -nc --arg sa "$target" --arg exp "$expire" --arg m "$method" \
        '{sa:$sa, method:$m, expireTime:$exp, projects:[], findings:[]}')

    discovered=()
    if ((DO_LIST)); then
        while IFS=$'\t' read -r pid pnum state name; do
            [[ -z "$pid" ]] && continue
            discovered+=("$pid")
            echo "      project: $pid ($pnum) [$state] $name"
            recon=$(jq -c --arg id "$pid" --arg n "$pnum" --arg s "$state" --arg nm "$name" \
                '.projects += [{projectId:$id, projectNumber:$n, state:$s, name:$nm}]' <<<"$recon")
        done < <(list_projects "$token")
        ok "$target -> ${#discovered[@]} visible project(s)"
    fi

    if ((DO_RECON)); then
        enum=("${PROJECTS[@]}")
        ((ENUM_DISCOVERED)) && enum+=("${discovered[@]}")
        # de-dupe
        if ((${#enum[@]})); then
            mapfile -t enum < <(printf '%s\n' "${enum[@]}" | awk 'NF && !seen[$0]++')
        fi
        for project in "${enum[@]}"; do
            mapfile -t got < <(test_perms "$token" "$project" "${PERM_SET[@]}")
            if ((${#got[@]})); then
                granted_json=$(printf '%s\n' "${got[@]}" | jq -R . | jq -sc .)
                ok "$target @ $project -> ${#got[@]}/${#PERM_SET[@]} permission(s)"
                printf '        ✓ %s\n' "${got[@]}"
            else
                granted_json='[]'
                warn "$target @ $project -> 0/${#PERM_SET[@]} permissions"
            fi
            recon=$(jq -c --arg p "$project" --argjson g "$granted_json" \
                '.findings += [{project:$p, granted:$g}]' <<<"$recon")
        done
    fi

    jq . <<<"$recon" > "$OUTDIR/${saf}.recon.json"
done

# itemized summary: separate real mints from delegate-skips and denials
summary_parts=()
((skipped)) && summary_parts+=("$skipped delegate-skip")
((denied))  && summary_parts+=("$denied denied")
extra=""
if ((${#summary_parts[@]})); then
    joined="${summary_parts[0]}"
    for ((i=1; i<${#summary_parts[@]}; i++)); do joined+=", ${summary_parts[i]}"; done
    extra=" ($joined)"
fi
log "done: minted $minted/${#TARGETS[@]} token(s)${extra}; results in $OUTDIR/"