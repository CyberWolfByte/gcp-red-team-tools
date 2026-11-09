# GCP Service Account Permission Enumerator

GCP Service Account Permission Enumerator tests which impactful IAM permissions the current caller holds over a list of service accounts, via `iam.serviceAccounts.testIamPermissions`. Unlike a token minter, it surfaces standalone **`implicitDelegation`** / `actAs` / `setIamPolicy` grants — permissions you can't mint with directly but that still enable a pivot.

`testIamPermissions` returns only the queried permissions the caller actually holds, so a non-empty result means an abusable service account.

Bash implementation:

- `enum-sa-perms.sh`

## Features

- Tests seven impersonation / privesc permissions per SA (`getAccessToken`, `getOpenIdToken`, `signJwt`, `signBlob`, `implicitDelegation`, `actAs`, `setIamPolicy`)
- Detects standalone `implicitDelegation` — the pivot edge a token minter can't see
- Caller token from `-t`, `--caller-token-file`, `$CALLER_TOKEN`, or active gcloud
- JSONL output of hits only, for easy downstream parsing
- Throttle plus `429` backoff to smooth quota and audit-log burst
- Token kept out of `ps` / argv via a curl config fd

## Usage

```
chmod +x enum-sa-perms.sh

# As the active gcloud identity
./enum-sa-perms.sh serviceaccounts.txt

# As a minted identity, token supplied out of argv
CALLER_TOKEN="$token" ./enum-sa-perms.sh serviceaccounts.txt

# Or from a token file
./enum-sa-perms.sh --caller-token-file minted.token serviceaccounts.txt
```

## How It Works

- Resolves the caller token from the first available source
- Reads SAs from the input file (blank and `#` lines ignored; tolerant of a missing trailing newline)
- POSTs the permission set to `:testIamPermissions` for each SA
- Prints `[+]` with the granted subset, `[-]` for none, `[!]` on HTTP errors (with `429` backoff)
- Appends each hit to a JSONL file

## Output Examples

```
[-] analytics@PROJECT.iam.gserviceaccount.com -> none
[+] sql-512@PROJECT.iam.gserviceaccount.com -> ["iam.serviceAccounts.implicitDelegation"]
[!] 123456789102@cloudservices.gserviceaccount.com -> HTTP 404: Unknown service account
[*] done: 1/8 service accounts with >=1 impactful permission
[*] hits written to sa-perms-20261019-072826.jsonl
```

## Contributing

If you have an idea for improvement or wish to collaborate, feel free to contribute.

## Disclaimer

Use responsibly. This tool is intended for red teamers, security auditors, and penetration testers with proper authorization.