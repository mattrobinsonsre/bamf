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

## Patching an older release line

Ordinary releases are cut by tagging `main`. A **patch for a line that `main`
has already moved past** is different — [`SECURITY.md`](../SECURITY.md) offers
*security fixes only* for the previous minor, and this is how you discharge that
promise.

**The tag push is the gate.** A cherry-picked or hand-written commit is a *new*
commit, so no `sha-<commit>` images exist for it and the tag workflow runs the
full lint/test/build set before publishing. If any of it fails, `cleanup.yml`
deletes the tag and re-tagging the same version after a fix is safe.

```sh
git fetch origin --tags
git checkout -b release/v0.1 v0.1.1   # branch from the tag, not from main
# ...apply the fix (see below)...
git push -u origin release/v0.1
git tag v0.1.2 && git push origin v0.1.2   # the gate and the release
```

**Two mechanisms — pick the smallest change that fixes it, not "did it come from
`main`":**

- **Cherry-pick** when the fix already exists on `main` as a discrete commit
  that still applies: `git cherry-pick -x <sha>` (`-x` records the origin for
  free).
- **A minimal fix written directly on the release branch** when it doesn't —
  and for some fixes this is the *only* correct mechanism. The case that forces
  it: a vulnerable dependency whose fix on `main` is a lockfile regenerated a
  whole minor later. Cherry-picking that lockfile drags `main`'s entire
  dependency tree onto the old line — the "fix without the features" rule
  violated by the tool meant to uphold it. Bump the specific package on the
  release branch instead (`npm install next@X`, or a single Poetry constraint +
  re-lock) and regenerate only what that requires. Say so in the commit message
  — a reviewer needs to know a patch-branch commit has no `main` counterpart.

**The trap — a patch with nothing to cherry-pick.** A base-image CVE is cleared
by *rebuilding* against a refreshed base, with no code change. Tagging the
existing commit **retags the identical images under a new version** (the
pipeline skips building when `sha-<commit>` images already exist) — a release
that claims a fix and ships the same bytes. Force a real build with an empty
commit: `git commit --allow-empty -m "chore: rebuild v0.1.x against a refreshed base image"`.

**Rules:**

- **Never merge `main` into the release branch** (defeats "fix without the
  features"), and **never merge the release branch back into `main`** (its
  commits are already there). Keep the branch — it's where the next patch on
  that line starts.
- **Bring the accepted-risk register forward with the patch.** The release
  pipeline reads the scanner suppression allowlists (`pentest/trivy/.trivyignore`,
  `pentest/pip-audit/ignore-vulns.txt`, `pentest/npm-audit-allow.txt`) **from
  the branch it runs on**, so an old line carries an old register and will block
  itself on risks already accepted since. Copy the current register onto the
  release branch in the same commit as the fix — it applies the position already
  held, it doesn't change it.
- **Rebuilding an old tag runs today's advisory data against yesterday's tree**,
  so expect the first attempt to fail on something unpublished when the tag was
  cut — that's the mechanism working. Prefer the upstream fix (a targeted bump
  on the branch); reach for the register only where no fix exists.
- **A security-driven patch is still a release** — same pre-release audit and
  independent third-party review as any other; being prompted by a scanner earns
  no shortcut. Name the advisories it clears in the release notes so an operator
  can match them against their own scan output.

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
