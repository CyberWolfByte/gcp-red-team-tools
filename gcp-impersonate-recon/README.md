# GCP Impersonation Recon

GCP Impersonation Recon mints access tokens for target service accounts by walking a **delegation chain**, then uses each minted token to gain situational awareness *as that identity*. It lists the projects it can see and tests a matrix of IAM permissions against them.

It ships two delegation-aware minting primitives and auto-selects between them:

- `generateAccessToken` — a direct token (needs `iam.serviceAccounts.getAccessToken`)
- `signJwt` — signs a self-issued JWT (needs `iam.serviceAccounts.signJwt`), then exchanges it at the OAuth2 token endpoint for an access token

Because `getAccessToken` and `signJwt` are distinct permissions, a delegate may hold one but not the other. `--method auto` tries the direct token first and falls back to signJwt when it's denied.

Bash implementation:

- `gcp-impersonate-recon.sh`

## Features

- Delegation-chain minting via repeatable `--delegate` hops (`implicitDelegation` / `tokenCreator`)
- Two primitives — `generateAccessToken` and `signJwt` + OAuth2 exchange — selectable with `token | jwt | auto`
- Caller (chain-root) token from four sources: `-t`, `--caller-token-file`, `$CALLER_TOKEN`, or active gcloud
- Per-identity situational awareness: project listing plus a configurable `testIamPermissions` matrix
- Writes each minted token to disk and a structured `recon.json` per identity
- Keeps bearer tokens out of `ps` / argv via a curl config fd
- Itemized summary separating real mints, delegate-skips, and denials

## Usage

```
chmod +x gcp-impersonate-recon.sh

# Sweep a list of targets through a delegate with signJwt, enumerate every visible project
./gcp-impersonate-recon.sh -f serviceaccounts.txt \
  -d analytics-exporter@PROJECT.iam.gserviceaccount.com \
  -m jwt --enum-discovered

# Single known target, caller token supplied out of argv
CALLER_TOKEN="$token" ./gcp-impersonate-recon.sh \
  -s mobile-backend@PROJECT.iam.gserviceaccount.com \
  -d analytics-exporter@PROJECT.iam.gserviceaccount.com -m jwt
```

## How It Works

- Resolves a caller (chain-root) token from the first available source (`-t` > `--caller-token-file` > `$CALLER_TOKEN` > gcloud)
- For each target SA, builds a `delegates[]` chain and calls `generateAccessToken` and/or `signJwt`
- For signJwt, signs an assertion (`iss` = target) and exchanges it at `oauth2.googleapis.com/token` for a bearer token
- Skips any target that is also a delegate — you can't mint a token for the delegate itself
- With a minted token, lists visible projects and runs `testIamPermissions` for the permission matrix
- Saves `<outdir>/<sa>.token` and `<outdir>/<sa>.recon.json`, and reports which primitive succeeded

## Output Examples

```
[*] targets: 10 | delegates: 1 | method: jwt | outdir: impersonate-20261001-081852
[!] mint failed for payments-processor@PROJECT.iam.gserviceaccount.com -> signJwt HTTP 403: Permission 'iam.serviceAccounts.signJwt' denied on resource (or it may not exist).
✓ mobile-backend@PROJECT.iam.gserviceaccount.com -> token acquired via signJwt (expires 2026-10-01T14:18:52Z) [impersonate-20261001-081852/mobile-backend_PROJECT.iam.gserviceaccount.com.token]
      project: PROJECT (89587951786) [ACTIVE] ai-innovation
✓ mobile-backend@PROJECT.iam.gserviceaccount.com -> 1 visible project(s)
✓ mobile-backend@PROJECT.iam.gserviceaccount.com @ PROJECT -> 2/21 permission(s)
        ✓ resourcemanager.projects.get
        ✓ secretmanager.secrets.list
[*] done: minted 1/10 token(s) (1 delegate-skip, 8 denied); results in impersonate-20261001-081852/
```

## Contributing

If you have an idea for improvement or wish to collaborate, feel free to contribute.

## Disclaimer

Use responsibly. This tool is intended for red teamers, security auditors, and penetration testers with proper authorization.