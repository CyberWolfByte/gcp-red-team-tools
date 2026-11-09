# GCP Service Account IAM Policy Mapper

GCP Service Account IAM Policy Mapper collects the resource-level IAM policy of every service account in a project who can act on/impersonate each SA and saves them as one valid JSON array. This is the **"who can impersonate whom"** map that feeds delegation-chain hunting: members granted `tokenCreator`, `serviceAccountUser`, `workloadIdentityUser`, or `serviceAccountAdmin` on an SA are its inbound impersonation edges.

JSON is assembled with jq (never by echoing fragments), so the output stays valid even when some SAs can't be read; a denied SA is recorded with `iamPolicy:null` and an error string instead of corrupting the array.

Bash implementation:

- `gcp-sa-iam-policies.sh`

## Features

- Dumps the resource-level IAM policy of each SA to one valid JSON array
- `--edges` extracts impersonation-relevant bindings as a `member --[role]--> SA` map
- SA source is flexible: a project listing, a file (`-l`), or explicit `-s`
- Per-SA status at a glance: `[✓]` has bindings / `[X]` empty / `[!]` denied
- Runs as an impersonated identity via `--access-token-file`
- Resilient output: denied SAs are recorded, never silently dropped

## Usage

```
chmod +x gcp-sa-iam-policies.sh

# List and map every SA in a project, with the impersonation-edge summary
./gcp-sa-iam-policies.sh -p PROJECT_ID --edges

# Reuse a curated SA list, running as a minted identity
./gcp-sa-iam-policies.sh -l serviceaccounts.txt --edges --access-token-file minted.token
```

## How It Works

- Resolves the SA set (`-s`, then an `-l` file, then a project listing)
- Calls `get-iam-policy` per SA, wrapping each result — or its error — as a JSON object
- Slurps the objects into one array with jq
- With `--edges`, filters bindings to impersonation roles and emits a de-duplicated edge list
- Note: custom roles (e.g. `svcDelegation`) whose names don't contain "serviceAccount" won't match the edge filter — resolve those with `gcloud iam roles describe` to confirm the permissions inside

## Output Examples

```
[✓] payments-processor@PROJECT.iam.gserviceaccount.com (1 binding(s))
[X] foundry@PROJECT.iam.gserviceaccount.com (0 binding(s))
[*] done: 10/10 policies retrieved (0 denied); wrote sa-policies-PROJECT-20260930-080647.json
[✓] impersonation edges (3) -> sa-policies-PROJECT-20260930-080647.edges.txt
    serviceAccount:example-test@PROJECT.iam.gserviceaccount.com  --[roles/iam.serviceAccountTokenCreator]-->  dev-example@PROJECT.iam.gserviceaccount.com
```

## Contributing

If you have an idea for improvement or wish to collaborate, feel free to contribute.

## Disclaimer

Use responsibly. This tool is intended for red teamers, security auditors, and penetration testers with proper authorization.