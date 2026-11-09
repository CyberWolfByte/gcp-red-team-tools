#!/usr/bin/env bash
#
# gcp-regional-secrets.sh
#
# Sweep the regional (data-residency) Secret Manager endpoints of a project and
# list secrets per region; optionally pull and decode each secret's latest value.
# Complements a global `gcloud secrets list` -- these regional endpoints only
# surface secrets pinned to a specific location.
#
# Per region:  [+] secrets found (listed)   [-] reachable but empty
#              [!] permission denied         [~] region unavailable / no endpoint
# With --access, each secret is additionally [v] read (value) or [!] access denied.
#
# ---------------------------------------------------------------------------
# Usage:
#   ./gcp-regional-secrets.sh -p PROJECT [options]
#
# Required:
#   -p, --project PROJECT     Project ID (falls back to gcloud config)
#
# Caller token source, in precedence order:
#   -t, --caller-token T      Token value on the CLI (handy; visible in ps/proc)
#       --caller-token-file F Read the caller bearer token from a file
#       CALLER_TOKEN env      e.g.  CALLER_TOKEN="$token" ./gcp-regional-secrets.sh ...
#       (default)             gcloud auth print-access-token
#
# Options:
#   -r, --regions "a,b,..."   Only these region(s) instead of the full default sweep
#   -a, --access              Fetch + base64-decode each secret's latest version
#   -o, --outdir DIR          With --access, save each value to DIR/<region>__<secret>
#   -q, --quiet               Show only regions/secrets with hits
#       --list-regions        Print the default region list and exit
#   -h, --help                This help
# ---------------------------------------------------------------------------

set -uo pipefail

PROJECT=""; CALLER_TOKEN_FILE=""; CALLER_TOKEN_ARG=""
REGIONS_ARG=""; ACCESS=0; OUTDIR=""; QUIET=0; LIST_REGIONS=0

DEFAULT_REGIONS=(
    asia-east1 asia-east2 asia-northeast1 asia-northeast2 asia-northeast3 asia-south1
    asia-south2 asia-southeast1 asia-southeast2 australia-southeast1 australia-southeast2
    europe-central2 europe-north1 europe-west1 europe-west2 europe-west3 europe-west4
    europe-west6 me-central1 me-west1 northamerica-northeast1 northamerica-northeast2
    southamerica-east1 southamerica-west1 us-central1 us-east1 us-east4 us-west1 us-west2 us-west3 us-west4
)

log()  { echo "[*] $*"; }
hit()  { echo "[+] $*"; }
val()  { echo "    [v] $*"; }
none() { ((QUIET)) || echo "[-] $*"; }
deny() { ((QUIET)) || echo "[!] $*" >&2; }
off()  { ((QUIET)) || echo "[~] $*" >&2; }
die()  { echo "[x] $*" >&2; exit 1; }
usage() { sed -n '/^# Usage:/,/^# ---/p' "$0" | sed '$d; s/^# \{0,1\}//'; exit "${1:-0}"; }

# curl with the bearer passed via a config fd (keeps the token out of argv/logs)
authcurl() { curl -sS --config <(printf 'header = "Authorization: Bearer %s"\n' "$TOKEN") "$@"; }

# arg parsing
while (($#)); do
    case "$1" in
        -p|--project)        PROJECT="$2"; shift 2;;
        -t|--caller-token)   CALLER_TOKEN_ARG="$2"; shift 2;;
        --caller-token-file) CALLER_TOKEN_FILE="$2"; shift 2;;
        -r|--regions)        REGIONS_ARG="$2"; shift 2;;
        -a|--access)         ACCESS=1; shift;;
        -o|--outdir)         OUTDIR="$2"; shift 2;;
        -q|--quiet)          QUIET=1; shift;;
        --list-regions)      LIST_REGIONS=1; shift;;
        -h|--help)           usage 0;;
        -*)                  die "unknown option: $1 (try --help)";;
        *)                   die "unexpected argument: $1";;
    esac
done

if ((LIST_REGIONS)); then printf '%s\n' "${DEFAULT_REGIONS[@]}"; exit 0; fi

command -v jq     >/dev/null 2>&1 || die "jq is required"
command -v curl   >/dev/null 2>&1 || die "curl is required"
command -v base64 >/dev/null 2>&1 || die "base64 is required"

# project
[[ -z "$PROJECT" ]] && PROJECT="$(gcloud config get-value project 2>/dev/null)"
[[ -n "$PROJECT" && "$PROJECT" != "(unset)" ]] || die "no project: pass -p PROJECT"

# caller token (same precedence as the rest of the kit)
if [[ -n "$CALLER_TOKEN_ARG" ]]; then
    TOKEN="$CALLER_TOKEN_ARG"
    echo "[!] note: -t/--caller-token places the token in argv (visible via ps / /proc); use \$CALLER_TOKEN on shared hosts" >&2
elif [[ -n "$CALLER_TOKEN_FILE" ]]; then
    [[ -r "$CALLER_TOKEN_FILE" ]] || die "cannot read caller token file: $CALLER_TOKEN_FILE"
    TOKEN="$(<"$CALLER_TOKEN_FILE")"
elif [[ -n "${CALLER_TOKEN:-}" ]]; then
    TOKEN="$CALLER_TOKEN"
else
    command -v gcloud >/dev/null 2>&1 || die "no token source: use -t, --caller-token-file, \$CALLER_TOKEN, or install gcloud"
    TOKEN="$(gcloud auth print-access-token 2>/dev/null)" || die "failed to obtain access token"
fi
TOKEN="${TOKEN//[[:space:]]/}"
[[ -n "$TOKEN" ]] || die "empty caller token"

# region set
declare -a REGIONS
if [[ -n "$REGIONS_ARG" ]]; then IFS=', ' read -ra REGIONS <<<"$REGIONS_ARG"
else REGIONS=("${DEFAULT_REGIONS[@]}"); fi

if ((ACCESS)) && [[ -n "$OUTDIR" ]]; then umask 077; mkdir -p "$OUTDIR" || die "cannot create outdir: $OUTDIR"; fi

# access_secret FULLNAME REGION: on success sets ACC_OUT=decoded value; else sets ACC_ERR.
# Call DIRECTLY (not in $()) so the globals survive.
ACC_ERR=""; ACC_OUT=""
access_secret() {
    local name="$1" region="$2" aurl resp code body data
    ACC_ERR=""; ACC_OUT=""
    aurl="https://secretmanager.${region}.rep.googleapis.com/v1/${name}/versions/latest:access"
    resp="$(authcurl -w $'\n%{http_code}' "$aurl" 2>/dev/null)"
    code="${resp##*$'\n'}"; body="${resp%$'\n'*}"
    if [[ "$code" != 200 ]]; then
        [[ "$code" == 403 ]] && ACC_ERR="access denied" || ACC_ERR="HTTP ${code:-error}"
        return 1
    fi
    data="$(jq -r '.payload.data // empty' <<<"$body" 2>/dev/null)"
    [[ -n "$data" ]] || { ACC_ERR="empty payload"; return 1; }
    ACC_OUT="$(base64 --decode <<<"$data" 2>/dev/null)"
    return 0
}

log "project: $PROJECT | regions: ${#REGIONS[@]} | access: $((ACCESS))"
total_secrets=0; hit_regions=0
for region in "${REGIONS[@]}"; do
    url="https://secretmanager.${region}.rep.googleapis.com/v1/projects/${PROJECT}/locations/${region}/secrets"
    resp="$(authcurl -w $'\n%{http_code}' "$url" 2>/dev/null)"
    code="${resp##*$'\n'}"; body="${resp%$'\n'*}"

    case "$code" in
        200) : ;;
        403) deny "$region -> permission denied"; continue;;
        000|404) off "$region -> unavailable (no regional endpoint / unreachable)"; continue;;
        *) msg="$(jq -rc '.error.message? // empty' <<<"$body" 2>/dev/null)"
           grep -qi 'disabled\|not been used' <<<"$msg" && off "$region -> API not enabled" \
               || deny "$region -> HTTP $code${msg:+: $msg}"; continue;;
    esac

    mapfile -t names < <(jq -r '.secrets[]?.name // empty' <<<"$body" 2>/dev/null)
    if ((${#names[@]} == 0)); then none "$region -> none"; continue; fi

    hit_regions=$((hit_regions+1)); total_secrets=$((total_secrets + ${#names[@]}))
    hit "$region -> ${#names[@]} secret(s)"
    for name in "${names[@]}"; do
        short="${name##*/secrets/}"
        echo "    - $short"
        if ((ACCESS)); then
            if access_secret "$name" "$region"; then
                value="$ACC_OUT"
                if [[ -n "$OUTDIR" ]]; then
                    printf '%s' "$value" > "$OUTDIR/${region}__${short}"
                    val "$short -> saved ($OUTDIR/${region}__${short})"
                else
                    val "$short = $value"
                fi
            else
                deny "    $short -> $ACC_ERR"
            fi
        fi
    done
done

log "done: $total_secrets secret(s) across $hit_regions region(s) in $PROJECT"