#!/usr/bin/env bash
#
# gcp-sa-iam-policies.sh
#
# Collect the resource-level IAM policy of every service account in a project
# (i.e. who can act on / impersonate each SA) and save them as one valid JSON
# array. This is the "who can impersonate whom" map that feeds delegation-chain
# hunting: look for members granted roles/iam.serviceAccountTokenCreator,
# serviceAccountUser, workloadIdentityUser, or serviceAccountAdmin on each SA.
#
# JSON is assembled with jq (never by echoing fragments), so the output is
# always valid even when some SAs can't be read; a denied SA is recorded with
# iamPolicy:null and an error string rather than silently corrupting the array.
#
# Intended for authorized red-team / lab use.
#
# ---------------------------------------------------------------------------
# Usage:
#   ./gcp-sa-iam-policies.sh -p PROJECT_ID [-o out.json] [options]
#
# Service account source (at least one of):
#   -p, --project PROJECT_ID   List every SA in this project (also used as gcloud project)
#   -l, --sa-list FILE         Read SAs from this file (one per line; # comments ok).
#                              With -p and no such file yet, the listing is saved here.
#   -s, --sa "SA[,SA...]"      Specific SA email(s), comma/space separated; repeatable
#
# Output:
#   -o, --output FILE          Output JSON array (default: sa-policies-<project>-<ts>.json)
#       --edges                Also extract impersonation-relevant bindings to <output>.edges.txt
#
# Auth / misc:
#       --access-token-file F  Run gcloud as an impersonated identity (e.g. a minted token)
#   -q, --quiet                Suppress per-SA lines; show only the summary
#   -h, --help                 This help
# ---------------------------------------------------------------------------

set -uo pipefail

# defaults
PROJECT_ID=""; SA_LIST_FILE=""; OUTPUT=""; ACCESS_TOKEN_FILE=""
SAS=(); DO_EDGES=0; QUIET=0

# roles that grant impersonation / privesc over a service account
EDGE_ROLES='["roles/iam.serviceAccountTokenCreator","roles/iam.serviceAccountUser","roles/iam.workloadIdentityUser","roles/iam.serviceAccountAdmin","roles/iam.serviceAccountKeyAdmin","roles/iam.serviceAccountOpenIdTokenCreator","roles/owner","roles/editor"]'

log()  { ((QUIET)) || echo "[*] $*"; }
ok()   { ((QUIET)) || echo "[✓] $*"; }
warn() { echo "[!] $*" >&2; }
die()  { echo "[x] $*" >&2; exit 1; }
usage() { sed -n '27,49p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

# arg parsing
while (($#)); do
    case "$1" in
        -p|--project)          PROJECT_ID="$2"; shift 2;;
        -l|--sa-list)          SA_LIST_FILE="$2"; shift 2;;
        -s|--sa)               IFS=', ' read -ra _t <<<"$2"; SAS+=("${_t[@]}"); shift 2;;
        -o|--output)           OUTPUT="$2"; shift 2;;
        --edges)               DO_EDGES=1; shift;;
        --access-token-file)   ACCESS_TOKEN_FILE="$2"; shift 2;;
        -q|--quiet)            QUIET=1; shift;;
        -h|--help)             usage 0;;
        -*)                    die "unknown option: $1 (try --help)";;
        *)                     SAS+=("$1"); shift;;
    esac
done

command -v gcloud >/dev/null 2>&1 || die "gcloud is required"
command -v jq     >/dev/null 2>&1 || die "jq is required"

# global gcloud args (identity override applies to every call)
GCLOUD_ARGS=()
[[ -n "$ACCESS_TOKEN_FILE" ]] && GCLOUD_ARGS+=(--access-token-file="$ACCESS_TOKEN_FILE")

# resolve the SA set: explicit -s, then a list file, then a project listing
if [[ -n "$SA_LIST_FILE" && -r "$SA_LIST_FILE" ]]; then
    while IFS= read -r line || [[ -n "$line" ]]; do
        line="${line%%$'\r'}"; line="${line#"${line%%[![:space:]]*}"}"
        [[ -z "$line" || "$line" == \#* ]] && continue
        SAS+=("$line")
    done < "$SA_LIST_FILE"
fi

if ((${#SAS[@]} == 0)); then
    [[ -n "$PROJECT_ID" ]] || die "no SAs given: pass -p PROJECT_ID, -l FILE, or -s SA"
    log "listing service accounts in $PROJECT_ID"
    mapfile -t SAS < <(gcloud iam service-accounts list --project="$PROJECT_ID" \
        ${GCLOUD_ARGS[@]+"${GCLOUD_ARGS[@]}"} --format="value(email)" 2>/dev/null)
    ((${#SAS[@]})) || die "no service accounts listed (check project, permissions, or token)"
    # persist the listing if a --sa-list path was requested but didn't exist yet
    [[ -n "$SA_LIST_FILE" ]] && printf '%s\n' "${SAS[@]}" > "$SA_LIST_FILE"
fi

# de-dupe while preserving order
mapfile -t SAS < <(printf '%s\n' "${SAS[@]}" | awk 'NF && !seen[$0]++')

# default output name
if [[ -z "$OUTPUT" ]]; then
    tag="${PROJECT_ID:-sa}"
    OUTPUT="sa-policies-${tag}-$(date +%Y%m%d-%H%M%S).json"
fi

umask 077
workdir="$(mktemp -d)"; trap 'rm -rf "$workdir"' EXIT
objs="$workdir/objs.jsonl"; errf="$workdir/err"
: > "$objs"

# collect policies
total=0; okc=0; failc=0
for SA in "${SAS[@]}"; do
    total=$((total+1))
    if policy="$(gcloud iam service-accounts get-iam-policy "$SA" \
            ${GCLOUD_ARGS[@]+"${GCLOUD_ARGS[@]}"} --format=json 2>"$errf")"; then
        jq -c --arg sa "$SA" '{serviceAccount:$sa, iamPolicy:.}' <<<"$policy" >> "$objs"
        bc="$(jq '(.bindings|length)//0' <<<"$policy" 2>/dev/null)"; bc="${bc:-0}"
        okc=$((okc+1))
        if ((bc > 0)); then
            ok "$SA ($bc binding(s))"
        else
            ((QUIET)) || echo "[X] $SA ($bc binding(s))"
        fi
    else
        msg="$(tr '\n' ' ' <"$errf" | sed 's/  */ /g; s/^ *//; s/ *$//')"
        jq -nc --arg sa "$SA" --arg e "$msg" \
            '{serviceAccount:$sa, iamPolicy:null, error:$e}' >> "$objs"
        failc=$((failc+1))
        warn "get-iam-policy denied/failed for $SA: ${msg:-unknown error}"
    fi
done

# assemble the array (valid even with zero objects -> [])
jq -s . "$objs" > "$OUTPUT"
log "done: $okc/$total policies retrieved ($failc denied); wrote $OUTPUT"

# impersonation-edge summary
if ((DO_EDGES)); then
    edges="${OUTPUT%.json}.edges.txt"
    jq -r --argjson roles "$EDGE_ROLES" '
        .[] | .serviceAccount as $sa
        | (.iamPolicy.bindings // [])[]
        | select((.role as $r | $roles | index($r)) or (.role | test("[Ss]erviceAccount")))
        | .role as $role | (.members // [])[]
        | "\(.)\t\($role)\t\($sa)"
    ' "$OUTPUT" | sort -u > "$edges"

    n="$(wc -l < "$edges" | tr -d ' ')"
    if [[ "$n" -gt 0 ]]; then
        ok "impersonation edges ($n) -> $edges"
        ((QUIET)) || awk -F'\t' '{printf "    %s  --[%s]-->  %s\n", $1, $2, $3}' "$edges"
    else
        log "no impersonation-relevant bindings found; $edges is empty"
    fi
fi