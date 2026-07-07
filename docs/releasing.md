# Releasing BAMF

Releases are **fully automated via GitHub Actions**: pushing a semver tag
(`vX.Y.Z`) retags the images built for that commit, publishes the Helm chart,
attaches the Go binaries + SBOMs, and creates the GitHub Release. This page is
the mechanical how-to; the **quality gates** that must pass *before* you tag —
the pre-release audit and the independent third-party review — live in
[`AGENTS.md` → Release discipline](https://github.com/mattrobinsonsre/bamf/blob/main/AGENTS.md#release-discipline). Do those
first; then follow the steps here.

## Before tagging

1. **All intended PRs are merged with green CI.** Don't tag a release with
   unmerged work that was meant for it.
2. **Run the pre-release audit (A–H) and the third-party review** described in
   [`AGENTS.md`](https://github.com/mattrobinsonsre/bamf/blob/main/AGENTS.md#release-discipline), and land any fixes as a
   dedicated `docs:`/`chore:` PR. Minor/major releases require the full audit;
   patch releases still run the content-hygiene (D) and live-smoke (F) gates and
   the third-party review (which scales with the diff).
3. **`main` CI is green** on the commit you're about to tag. **Never tag a red
   main.** (`gh run watch` the main-branch run to exit 0 first — "it'll probably
   pass" is not sufficient.) This is enforced by discipline, not by CI: image
   builds gate only on `prepare`, so a commit whose lint/test failed can still
   have images in GHCR. A tag on that commit sees `images_exist=true`, **skips**
   re-validation, and the release gate accepts the skip — so a red commit *can*
   be released via a tag. (Terrapod's pipeline has the same shape; closing this
   would mean gating image builds on the full validation set and slowing every
   main-push publish.)

## Cutting the release

```sh
git tag vX.Y.Z && git push origin vX.Y.Z
```

Then **watch the tag pipeline** (test → build → scan → manifest → release) in
GitHub Actions. If any stage fails, the tag is **auto-deleted** by the
`cleanup.yml` workflow — fix the issue and re-tag the same version (it's back to
"never released", so reuse is safe).

## Verify the published artifacts

```sh
docker manifest inspect ghcr.io/mattrobinsonsre/bamf-api:vX.Y.Z
helm pull oci://ghcr.io/mattrobinsonsre/bamf --version X.Y.Z
```

## How the CI release flow works

- Every push to `main` builds **SHA-tagged** images (`sha-<commit>`).
- Pushing a semver tag **retags** those SHA images with the version + `:latest`,
  publishes the Helm chart, and creates the GitHub Release. If the images for
  that commit already exist (tag pushed on a commit `main` already built), tests
  and builds are skipped and the release runs immediately.
- A failed tag pipeline auto-cleans the tag (no partial release is left behind).
- SHA-tagged images are garbage-collected after 30 days; **semver-tagged images
  are kept indefinitely**.

**Never move an existing (successfully published) release tag** to a different
commit. If a version is broken after it published, abandon it and cut the next
patch (`vX.Y.Z+1`). The criterion is "did the pipeline succeed and publish?" —
if `cleanup.yml` deleted the tag, the version is free to reuse; otherwise it is
frozen.

All release logic is in [`.github/workflows/ci.yml`](https://github.com/mattrobinsonsre/bamf/blob/main/.github/workflows/ci.yml);
GHCR retention cleanup is in
[`.github/workflows/cleanup.yml`](https://github.com/mattrobinsonsre/bamf/blob/main/.github/workflows/cleanup.yml).

## Published artifacts

| Artifact | Registry |
|---|---|
| `bamf-api` | `ghcr.io/mattrobinsonsre/bamf-api` |
| `bamf-bridge` | `ghcr.io/mattrobinsonsre/bamf-bridge` |
| `bamf-agent` | `ghcr.io/mattrobinsonsre/bamf-agent` |
| `bamf-web` | `ghcr.io/mattrobinsonsre/bamf-web` |
| `bamf-proxy` | `ghcr.io/mattrobinsonsre/bamf-proxy` |
| Helm chart | `oci://ghcr.io/mattrobinsonsre/bamf` |
| Go binaries | GitHub Release assets (linux/macOS/windows, amd64/arm64) |
| SBOMs | GitHub Release assets (SPDX JSON per image) |

All images are `linux/amd64` + `linux/arm64`; semver tags also get `:latest`.
The Helm chart version strips the `v` prefix (`v0.1.0` → chart `0.1.0`);
`Chart.yaml` stays at `0.0.0` in source and CI injects the real version at
publish time via `helm package --version`.

## Version flow

```
git tag v0.2.0
    ↓  CI: VERSION="v0.2.0" (from GITHUB_REF)
Go binaries:    -ldflags "-X ...Version=v0.2.0"
Docker images:  bamf-api:v0.2.0, bamf-bridge:v0.2.0, ...  (+ :latest)
Helm chart:     version: 0.2.0, appVersion: "v0.2.0"
GitHub Release: "v0.2.0" with binaries + SBOMs + checksums
```

## Release notes

The git tag, release tag, and release title are the bare semver: `vX.Y.Z`. CI
auto-generates categorized notes from conventional commits between the previous
and current tag. When editing manually:

```markdown
<One-sentence summary of what this release represents.>

## Highlights
- **Feature name** — concise, value-oriented description.

## Bug Fixes
- ... (only if any)

## Breaking Changes
- ... and migration path (only if any)

## Security
- ... (only if any)

## Status
<Alpha|Beta|Stable> — <one-line status note>.

**Full Changelog**: https://github.com/mattrobinsonsre/bamf/compare/vPREV...vCURR
```

Conventions: lead with a one-line context sentence; bold feature names in
Highlights; omit empty sections; end with the `**Full Changelog**` compare link;
**no co-author lines or AI attribution**.
