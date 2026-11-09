# GCP Regional Secrets Harvester

GCP Regional Secrets Harvester sweeps the **regional (data-residency) Secret Manager endpoints** of a project, lists secrets per region, and optionally pulls and decodes each secret's latest value. It complements a global `gcloud secrets list` — the regional `*.rep.googleapis.com` endpoints only surface secrets pinned to a specific location.

Bash implementation:

- `gcp-regional-secrets.sh`

## Features

- Sweeps 31 default regions, or a targeted subset via `--regions`
- Per-region classification: `[+]` secrets found / `[-]` reachable but empty / `[!]` permission denied / `[~]` region unavailable
- `--access` fetches and base64-decodes each secret's latest version
- `--outdir` saves harvested values to disk under a `umask 077`
- Per-secret read status: `[v]` value read / `[!]` access denied — because list and read are different permissions
- Caller token from `-t`, `--caller-token-file`, `$CALLER_TOKEN`, or active gcloud; token kept out of argv

## Usage

```
chmod +x gcp-regional-secrets.sh

# List secrets across all regions, as a minted identity
./gcp-regional-secrets.sh -p PROJECT --caller-token-file minted.token

# One region, pull and decode the values
./gcp-regional-secrets.sh -p PROJECT -r us-central1 --access

# Harvest to files, token supplied out of argv
CALLER_TOKEN="$token" ./gcp-regional-secrets.sh -p PROJECT --access --outdir loot
```

## How It Works

- Resolves the project (flag or gcloud config) and the caller token
- For each region, GETs the regional `secrets` endpoint and classifies the response
- Lists each secret's short id; with `--access`, GETs `versions/latest:access` and base64-decodes the payload
- Separates the list permission (`secretmanager.secrets.list`) from the read permission (`secretmanager.versions.access`), which is commonly granted per-secret
- Saves values to `<outdir>/<region>__<secret>` when `--outdir` is set

## Output Examples

```
[+] us-central1 -> 2 secret(s)
    - db-password
    [v] db-password = Sup3rP@$5w0rd!
    - api-key
[!]     api-key -> access denied
[-] asia-east1 -> none
[~] me-west1 -> unavailable (no regional endpoint / unreachable)
[*] done: 2 secret(s) across 1 region(s) in PROJECT
```

## Contributing

If you have an idea for improvement or wish to collaborate, feel free to contribute.

## Disclaimer

Use responsibly. This tool is intended for red teamers, security auditors, and penetration testers with proper authorization.