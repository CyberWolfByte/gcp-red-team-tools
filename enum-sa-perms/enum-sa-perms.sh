#!/usr/bin/env bash
#
# Enumerate impactful IAM permissions the current caller holds over a list of
# service accounts, via iam.serviceAccounts.testIamPermissions.
#
# Usage: ./enum-sa-perms.sh [options] [serviceaccounts.txt] [output.jsonl]
#
#   -t, --caller-token T      Token value on the CLI (handy; visible in ps/proc)
#       --caller-token-file F Read the caller bearer token from a file
#       CALLER_TOKEN env      e.g.  CALLER_TOKEN="$token" ./enum-sa-perms.sh ...
#       (default)             gcloud auth print-access-token
#   precedence: -t  >  --caller-token-file  >  $CALLER_TOKEN  >  gcloud
#
# Input file: one SA email (or unique ID) per line; blank lines and #comments ignored.
# Output:     JSONL of hits only -> {"sa": "...", "permissions": [...]}

set -uo pipefail

CALLER_TOKEN_FILE=""; CALLER_TOKEN_ARG=""; POSITIONAL=()
while (($#)); do
    case "$1" in
        -t|--caller-token)   CALLER_TOKEN_ARG="$2"; shift 2;;
        --caller-token-file) CALLER_TOKEN_FILE="$2"; shift 2;;
        -h|--help)           sed -n '2,19p' "$0" | sed 's/^# \{0,1\}//'; exit 0;;
        -*)                  echo "[!] unknown option: $1 (try --help)" >&2; exit 1;;
        *)                   POSITIONAL+=("$1"); shift;;
    esac
done
INPUT="${POSITIONAL[0]:-serviceaccounts.txt}"
OUT="${POSITIONAL[1]:-sa-perms-$(date +%Y%m%d-%H%M%S).jsonl}"
THROTTLE="${THROTTLE:-0.2}"   # seconds between calls; smooths quota + audit burst

# Impersonation / privesc-relevant permissions on a service account.
read -r -d '' PERMS_JSON <<'JSON' || true
{
  "permissions": [
    "iam.serviceAccounts.getAccessToken",
    "iam.serviceAccounts.getOpenIdToken",
    "iam.serviceAccounts.signJwt",
    "iam.serviceAccounts.signBlob",
    "iam.serviceAccounts.implicitDelegation",
    "iam.serviceAccounts.actAs",
    "iam.serviceAccounts.setIamPolicy"
  ]
}
JSON

command -v jq >/dev/null 2>&1 || { echo "[!] jq is required" >&2; exit 1; }
[[ -r "$INPUT" ]] || { echo "[!] cannot read input file: $INPUT" >&2; exit 1; }

# Resolve the caller token once. precedence: -t > --caller-token-file > $CALLER_TOKEN > gcloud
if [[ -n "$CALLER_TOKEN_ARG" ]]; then
    TOKEN="$CALLER_TOKEN_ARG"
    echo "[!] note: -t/--caller-token places the token in argv (visible via ps / /proc/<pid>/cmdline); use \$CALLER_TOKEN on shared hosts" >&2
elif [[ -n "$CALLER_TOKEN_FILE" ]]; then
    [[ -r "$CALLER_TOKEN_FILE" ]] || { echo "[!] cannot read caller token file: $CALLER_TOKEN_FILE" >&2; exit 1; }
    TOKEN="$(<"$CALLER_TOKEN_FILE")"
elif [[ -n "${CALLER_TOKEN:-}" ]]; then
    TOKEN="$CALLER_TOKEN"   # inherited from the environment
else
    command -v gcloud >/dev/null 2>&1 \
        || { echo "[!] no token source: use -t, --caller-token-file, \$CALLER_TOKEN, or install gcloud" >&2; exit 1; }
    TOKEN="$(gcloud auth print-access-token 2>/dev/null)" \
        || { echo "[!] failed to obtain access token" >&2; exit 1; }
fi
TOKEN="${TOKEN//[[:space:]]/}"
[[ -n "$TOKEN" ]] || { echo "[!] empty caller token" >&2; exit 1; }

hits=0 total=0
while IFS= read -r sa || [[ -n "$sa" ]]; do
    sa="${sa%%$'\r'}"                              # tolerate CRLF input
    [[ -z "$sa" || "$sa" == \#* ]] && continue
    total=$((total + 1))

    resp="$(curl -sS -X POST \
        --config <(printf 'header = "Authorization: Bearer %s"\n' "$TOKEN") \
        -H "Content-Type: application/json" \
        -d "$PERMS_JSON" \
        -w $'\n%{http_code}' \
        "https://iam.googleapis.com/v1/projects/-/serviceAccounts/${sa}:testIamPermissions" \
        2>/dev/null)"

    code="${resp##*$'\n'}"
    body="${resp%$'\n'*}"

    if [[ "$code" != "200" ]]; then
        msg="$(jq -rc '.error.message? // empty' <<<"$body" 2>/dev/null)"
        echo "[!] ${sa} -> HTTP ${code}${msg:+: $msg}" >&2
        [[ "$code" == "429" ]] && { echo "[!] rate limited; backing off 5s" >&2; sleep 5; }
        continue
    fi

    granted="$(jq -rc '.permissions // []' <<<"$body" 2>/dev/null)"
    if [[ -n "$granted" && "$granted" != "[]" ]]; then
        hits=$((hits + 1))
        echo "[+] ${sa} -> ${granted}"
        jq -c --arg sa "$sa" '{sa: $sa, permissions: (.permissions // [])}' \
            <<<"$body" >>"$OUT"
    else
        echo "[-] ${sa} -> none"
    fi

    sleep "$THROTTLE"
done < "$INPUT"

echo "[*] done: ${hits}/${total} service accounts with >=1 impactful permission"
[[ "$hits" -gt 0 ]] && echo "[*] hits written to ${OUT}"