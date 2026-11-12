# WebLibre update catalogues

This repository publishes the signed catalogues that WebLibre's in-app updater reads:

```
https://updates.weblibre.eu/v1/eu.weblibre.gecko/catalogue.json
https://updates.weblibre.eu/v1/eu.weblibre.gecko.alpha/catalogue.json
```

A catalogue lists the recent releases of one package and what each release brings: download URL, size and SHA-256 of every GitHub APK, the Play version, component versions, a security classification, a short summary and advisories. It is a DSSE envelope signed with Ed25519. The app trusts only the public keys compiled into it, so whoever serves these files cannot change what they say. The APKs themselves stay in the [WebLibre releases](https://github.com/FaFre/WebLibre/releases); the app verifies their signer again before installing.

The design is in the app repository: `plans/APP_UPDATER_IMPLEMENTATION_PLAN.md`, sections 5 (format and trust) and 9.2 (this repository).

## How it works

The `Catalogue` workflow (`.github/workflows/catalogue.yml`) runs every hour, when started by hand, and when `policy/` or `keys/` changes on `main`. It has two jobs:

- **`sign`** (environment `update-metadata`, holds the online key):
  1. Verifies the catalogues at the head of `main`. They are the revision record; if they don't verify, the run stops.
  2. Reads `release.json` from the newest app releases. The app's release workflow attaches it, and this repository treats it as untrusted data.
  3. Applies `policy/`: withdrawals, advisories and security classifications.
  4. Downloads and checks every GitHub APK it hasn't verified before: SHA-256, length, production signer, package, version code, minimum SDK, ABI, and the embedded build manifest. An APK listed unchanged in the head catalogue was verified when it was first signed and isn't downloaded again.
  5. Signs a new catalogue if the releases or advisories changed, or if the current one is older than 7 days. Otherwise it does nothing.
  6. Commits it to `site/` and pushes to `main` as a plain fast-forward. If `main` moved during the run, the push fails and nothing is published; the next run starts over.
- **`deploy`** (environment `github-pages`, no secrets): always runs, even when `sign` did nothing or failed. It checks out the head of `main` as it is at that moment, verifies its catalogues and compares them with what `updates.weblibre.eu` serves. If they differ, it deploys and checks again until the live site serves the head. A failed deployment is therefore repaired by the next run, without a new revision and without the key.

A catalogue is valid for 30 days and re-signed at least weekly. The weekly commits also keep GitHub from switching off the hourly schedule, which it does after 60 days without activity in a public repository.

A release whose `release.json` or APKs fail a check is left out, and the run ends with an error after publishing everything else. You get the usual failed-workflow notification. Withdrawing the release (below) silences it.

## Layout

| Path | What |
|---|---|
| `tools/update_catalogue.py` | The tool: `keygen`, `update`, `verify`, `sign`, `served`. Python standard library plus `openssl`, `apksigner`, `aapt2`. |
| `tools/test_update_catalogue.py` | Its tests: `python3 -m unittest discover -s tools` |
| `keys/trusted_keys.json` | Public metadata keys. Must match the app's `productionMetadataKeys`. |
| `policy/withdrawn.json` | Releases or single targets that must never be offered. |
| `policy/advisories.json` | Security advisories. |
| `policy/release-security/<tag>.json` | Security classification of one release. |
| `site/` | The signed catalogues, written only by the workflow. |

The tool's constants (app repository, production certificate fingerprint, package IDs, limits) sit at the top of `tools/update_catalogue.py` and change only by a reviewed pull request.

## One-time setup

### Repository settings

- **Actions → General:**
  - Allow FaFre and select non-FaFre actions, with "Allow actions created by GitHub" on and the SHA-pinning requirement on.
  - Workflow permissions: "Read repository contents".
  - Require approval for fork pull request workflows from every outside contributor.
- **Rules → Rulesets**, new branch ruleset on the default branch:
  - Rules: restrict deletions, block force pushes, require a pull request (0 approvals).
  - Bypass: the deploy key below set to *Always*, and Repository admin set to *For pull requests only*.
- **Pages:** Source *GitHub Actions*, custom domain `updates.weblibre.eu`, *Enforce HTTPS*.
  - DNS: `updates CNAME fafre.github.io.`
  - Verify `weblibre.eu` first, under your account's Settings → Pages; keep its TXT record.
- **Environments:**
  - `update-metadata`: deployment branches "Selected branches" → `main` only, no reviewers. Secrets:
    - `METADATA_KEY_ONLINE`: the online private key, the whole PEM text
    - `CATALOGUE_DEPLOY_KEY`: the deploy key's private half
  - `github-pages`: deployment branches `main` only, no secrets.

### Keys

Generate them on your own machine, not in CI. `*.pem` is ignored by git, but keep private keys outside this checkout anyway.

```sh
# Online key: unencrypted, goes into the update-metadata environment.
python3 tools/update_catalogue.py keygen --key-id wl-meta-2026a --out ~/weblibre-keys

# Offline backup key: passphrase-encrypted (scrypt, AES-256). Use a long
# generated passphrase from your password manager.
python3 tools/update_catalogue.py keygen --key-id wl-meta-2026b --out ~/weblibre-keys --encrypt
```

Each command prints the public half twice: as a `keys/trusted_keys.json` entry and as a `TrustedMetadataKey(...)` for the app's `lib/features/app_update/data/metadata/trusted_metadata_keys.dart`. Put both keys into both places.

Then:

1. Paste the whole content of `wl-meta-2026a.private.pem` into the `METADATA_KEY_ONLINE` secret and delete the file.
2. Copy `wl-meta-2026b.private.pem` to offline media and add it, with its passphrase, to the password manager. Delete it from the machine after the drill below.

### Deploy key

```sh
ssh-keygen -t ed25519 -N '' -C weblibre-updates-catalogue -f ~/weblibre-keys/catalogue-deploy
```

- Add `catalogue-deploy.pub` under Settings → Deploy keys, with write access.
- Paste `catalogue-deploy` into the `CATALOGUE_DEPLOY_KEY` secret and delete both files.
- Add the key to the ruleset's bypass list.

### Recovery drill (plan 5.4)

Run it once now, and again whenever the offline key moves to new media. It builds a throwaway catalogue in a separate folder, signed with the offline key alone; nothing in `site/` changes and nothing is published.

```sh
# Asks for the passphrase. Needs network access to read the app's releases.
python3 tools/update_catalogue.py update --key /media/offline/wl-meta-2026b.private.pem --site /tmp/drill
python3 tools/update_catalogue.py verify /tmp/drill/v1/eu.weblibre.gecko/catalogue.json --only-key wl-meta-2026b

# The app, with the keys compiled in, accepts it (from the app repository's apps/weblibre):
WEBLIBRE_DRILL_CATALOGUE=/tmp/drill/v1/eu.weblibre.gecko/catalogue.json \
    flutter test test/features/app_update/data/tool_catalogue_test.dart

rm -r /tmp/drill
```

## Operating it

**Publish now** (for a security release, or after a fix): Actions → Catalogue → Run workflow. Tick "Re-sign" to force a new revision even if nothing changed.

**Withdraw a release.** This takes two steps, and the catalogue is only one of them:

1. Add an entry by pull request and merge it. The merge publishes a catalogue without the release, and it stays out until the entry is removed.
   ```json
   { "withdrawn": [ { "id": "v0.50.0", "date": "2026-12-01", "reason": "crashes on start on Android 9" } ] }
   ```
   An `id` may also be a single target, such as `v0.50.0/github/stable/impeller/x86_64`.
2. Delete the GitHub release in the app repository, so Obtainium and the releases page stop offering it. Its tag name is gone for good; ship the fix as a new version.

**Advisories** go in `policy/advisories.json`:

```json
{ "advisories": [ {
  "id": "WL-2026-003",
  "url": "https://weblibre.eu/security/WL-2026-003",
  "severity": "critical",
  "affected": { "introducedInSequence": 31, "fixedInSequence": 48 },
  "packages": ["eu.weblibre.gecko"]
} ] }
```

- `severity` is `low`, `moderate`, `high` or `critical`.
- Sequences are the app's build numbers.
- `introducedInSequence` is optional; leaving it out means every earlier build is affected.
- `packages` is optional and defaults to both packages.
- Keep an entry for as long as any supported installation could still be affected.

**Security classification of a release:** `policy/release-security/v0.50.0.json` containing `{"classification": "fixesIncluded"}` (or `critical`). Without a file, a release is `unknown`. `/prepare-release` in the app repository suggests a value.

**Rotating the metadata key:**

1. Generate the new key and add it to `keys/trusted_keys.json` and the app.
2. Release the app. From then on sign with both keys: add a second secret and a second `--key-env` in the workflow.
3. Once every supported app version trusts the new key, drop the old key from both places and from the workflow.

Never remove a key from `keys/trusted_keys.json` while the head catalogue is signed only by it. The next run could no longer verify the head, and stops.

**When a run fails:**

| Error | What it means and what to do |
|---|---|
| *head catalogue does not verify* | `site/` was changed by something other than the workflow, or a key was removed too early. Find out which before doing anything else. |
| *the verified catalogue has …, release.json now says …* | An APK already in the catalogue now reports a different digest. Immutable releases should make this impossible. Treat it as an incident. |
| *no release found, but the head catalogues list some* | The release listing came back empty, which is more likely a GitHub glitch than every release deleted at once. Nothing was published; the next run retries. |
| *release.json rejected* / *excluded* | One release was left out and everything else was published. Fix the release, or withdraw it. |
| A failed push | `main` moved during the run. Nothing was published; the next run starts from the new head. |
| `deploy` failed | The site wasn't updated or didn't serve the head within 15 minutes. The next run tries again. |

## Checking the setup (gate G2)

- A catalogue signed by the online key is served over HTTPS from `updates.weblibre.eu`.
- The recovery drill passes.
- The hourly schedule and a manual run both work.
- A run on another branch gets neither the key nor a Pages deployment. Push a branch with a copy of the workflow and dispatch it; both jobs must be skipped or refused.
- Re-running an old run deploys the newest head.
- Two runs started together produce consecutive revisions or publish nothing.
- After a week, the schedule is still active.
