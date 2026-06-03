# Supply chain — independent verification guide

Everything you need to convince an auditor, a security reviewer, or
yourself that a `PostQuantum.Identity.<version>.nupkg` pulled from
nuget.org was built **by this repository, at a specific commit, on
GitHub's hosted runners** — with nothing substituted in between.

The README's [three-command summary](../README.md#how-to-verify-this-package-supply-chain--three-commands)
is the fast path. This document is the deeper version: what the chain of
custody looks like, what each artifact proves, what verification commands
should produce, and where each promise is wired in CI.

## Chain of custody, end to end

```
        ┌─────────────────────────┐
        │  systemslibrarian /     │     1. push tag v<version>
        │  postquantum-identity   │ ──────────────────────────────────────┐
        │  (GitHub repo)          │                                       │
        └───────────┬─────────────┘                                       │
                    │ release.yml on a hosted runner                      │
                    │  (deterministic build + SourceLink + CycloneDX SBOM)│
                    ▼                                                     │
        ┌───────────────────────────────────────────────────────────┐     │
        │ .nupkg + .snupkg + bom.json + SHA256SUMS.txt              │     │
        │ (artifacts of THIS workflow run, attested by Sigstore via │     │
        │ actions/attest-build-provenance)                          │     │
        └───────────┬───────────────────────────────────────────────┘     │
                    │ dotnet nuget push                                   │
                    ▼                                                     │
        ┌─────────────────────────┐         ┌───────────────────────┐     │
        │   nuget.org             │ ◄────── │ Repository signing    │     │
        │   (CDN distribution)    │         │  applied on push      │     │
        └───────────┬─────────────┘         └───────────────────────┘     │
                    │ nuget install                                       │
                    ▼                                                     │
                  YOU  ─── 3-command verify ──────────────────────────────┘
```

Every arrow has at least one independently checkable signal:

| Arrow | What you verify | How |
|---|---|---|
| Tag → workflow | The csproj `<Version>` matches the tag | [`scripts/check-version-sync.sh`](../scripts/check-version-sync.sh) (runs in CI before pack) |
| Workflow → artifacts | The `.nupkg` was produced by `release.yml` at a specific commit on a hosted runner | `gh attestation verify` against the Sigstore-signed provenance bundle |
| Workflow → SBOM | The component graph reflects the multi-TFM dependency surface (no TFM collapse) | `unzip -p <nupkg> bom.json` ; CycloneDX runs with `--disable-package-restore` to preserve multi-TFM groups |
| Artifacts → nuget.org | The bytes you fetched match what the workflow produced | `sha256sum` against the run's `SHA256SUMS.txt` |
| Source ↔ binary | Stack traces from your deployed binary point at this repo at the build commit | SourceLink + `.snupkg` symbols |
| Binary determinism | Two builds of the same commit produce byte-equal output | `Deterministic=true`, `ContinuousIntegrationBuild=true`, `EmbedUntrackedSources=true` (Directory.Build.props + csproj) |

## Hygiene checklist — what's in `release.yml`

Every line of this is wired into [`.github/workflows/release.yml`](../.github/workflows/release.yml):

- **OIDC-backed identity** — `permissions.id-token: write` allows the runner
  to mint a short-lived OIDC token that Sigstore uses to attest the build.
  No long-lived signing key lives in the repo.
- **Full fetch-depth** — `fetch-depth: 0` so SourceLink can record the
  precise commit and history in the symbol package.
- **Tag/version pin** — the workflow refuses to build if `${GITHUB_REF_NAME}`
  doesn't match the csproj `<Version>`.
- **CycloneDX SBOM** — `dotnet CycloneDX --disable-package-restore` is the
  load-bearing flag. Without it, CycloneDX rewrites `obj/project.assets.json`
  to a single TFM and the resulting `bom.json` silently drops transitive
  dependencies for net8/net9 consumers. We pin the flag.
- **Per-`.nupkg` build-provenance attestation** — `actions/attest-build-provenance@v3`
  signs each artifact's hash with Sigstore. Verifiable with
  `gh attestation verify`. Generated for **every** `.nupkg`, the `.snupkg`,
  and the top-level `bom.json` — one Sigstore bundle per file.
- **SHA256SUMS.txt** — published alongside the artifacts so the hashes are
  pinned in plain text outside any tooling.
- **Gated `nuget.org` publish** — the `publish` job is bound to the
  `nuget-publish` environment, so an approver must release the artifact.
- **Optional author code-signing** — if a code-signing certificate is
  configured on the environment, the workflow author-signs the `.nupkg`
  before push, with a DigiCert timestamper. Absent the cert we log it and
  continue (nuget.org's repository signing on push is the always-present
  layer); see `KNOWN-GAPS.md` for the rationale.

## Reproducing a build locally

```bash
git clone https://github.com/systemslibrarian/postquantum-identity
cd postquantum-identity
git checkout v0.5.0-preview.1   # or the tag you're auditing
dotnet pack src/PostQuantum.Identity/PostQuantum.Identity.csproj \
  -c Release -o ./local
```

Within toolchain-version equivalence (the same .NET SDK + the same set of
NuGet sources), the assemblies inside `./local/*.nupkg` are byte-equal to
the published ones at the same commit. The csproj enables
`Deterministic=true`, `ContinuousIntegrationBuild=true` (under CI), and
`EmbedUntrackedSources=true` to make this a structural property rather
than a happy accident.

## Verifying SHA-256 of every shipped artifact

The release uploads `SHA256SUMS.txt` alongside the `.nupkg` /
`.snupkg` / `bom.json`. To cross-check what you pulled:

```bash
# From the GitHub Release page, grab SHA256SUMS.txt; then:
sha256sum -c SHA256SUMS.txt
# Each line must say "OK".
```

If `sha256sum -c` flags any line as `FAILED`, the bytes you have do not
match the bytes the workflow attested. Stop and re-pull from nuget.org or
the release page; do not deploy.

## What this does **not** prove

Honesty is part of the supply-chain story too. The chain above proves:

- The package was built by this repo's `release.yml` at a specific commit
  on a hosted runner.
- The dependency graph at build time matches what the SBOM records.
- The bytes you have are the bytes that were attested.

It does **not** prove:

- That the source code at that commit is free of vulnerabilities. (That's
  what [`SECURITY.md`](../SECURITY.md), [`KNOWN-GAPS.md`](../KNOWN-GAPS.md),
  CodeQL, and the eventual external audit are for.)
- That every upstream dependency in the SBOM is free of vulnerabilities.
  (Run an SCA tool over `bom.json`.)
- That nuget.org itself is uncompromised. (NuGet's repository signing on
  push is the next layer; if you require defence in depth, mirror the
  package into your own feed after `gh attestation verify` passes.)

## If verification fails

| Symptom | Likely cause | What to do |
|---|---|---|
| `gh attestation verify` says **"no attestation found"** | The artifact is from before attestations were added, OR the `.nupkg` was renamed/repacked | Compare the package hash against `SHA256SUMS.txt`; if it doesn't match, the bytes are not what the workflow produced |
| `gh attestation verify` says **"verification failed"** | The `.nupkg`'s SHA-256 doesn't match any attested artifact for that subject path | Do not deploy. File a security report per [`SECURITY.md`](../SECURITY.md) |
| `bom.json` not present in the `.nupkg` | Old release predating the SBOM target, OR a packed-without-tool fresh-machine build | Cross-check version; SBOM has shipped since 0.2 — file an issue if missing on a tagged release |
| `bom.json` present but `components: 0` | CycloneDX ran without the multi-TFM aggregation flag | This is the bug that `--disable-package-restore` exists to prevent. If you see it on a released artifact, file a security advisory |

---

*To God be the glory — 1 Corinthians 10:31.*
