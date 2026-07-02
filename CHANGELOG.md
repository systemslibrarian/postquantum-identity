# Changelog

All notable changes to PostQuantum.Identity are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/), and the project adheres
to [Semantic Versioning](https://semver.org/).

## [1.0.0] — 2026-07-02

**Stable API on stable upstream.** From this release the public API only
breaks with a major version (semver). 1.0 is explicitly **not** an audit
claim — the library remains independently unaudited, and the README's
"What 1.0 means — and what it does not" section states both halves plainly.

### Changed

- **Upstream `PostQuantum.Jwt` / `PostQuantum.Jwt.AspNetCore` upgraded from
  `1.0.0-preview.1` to `1.0.0` (stable)** — library and all three web
  samples. Verified: zero API drift (clean compile), the full test suite
  green with zero skips on the PQ-capable host (442 tests incl. all token
  KATs and the fail-closed corpus), and the issuer → verifier cross-service
  flow exercised live. No preview dependency remains anywhere in the graph.
- **README reframed for 1.0.** The "Roadmap to 1.0" gate table is replaced
  by "What 1.0 means — and what it does not" (semver commitment, stable
  upstream, closed engineering gates / no audit, no generic-JWT interop)
  plus a post-1.0 roadmap (third-party review, IETF JOSE PQC alignment,
  coverage-guided fuzzing, macOS PQ-required lane). `SECURITY.md`,
  `KNOWN-GAPS.md`, the threat model, the production checklist, and the
  security-review checklist re-aligned in lockstep — the unaudited and
  non-interoperable statements are unchanged in substance everywhere.

## [0.6.0-preview.1] — 2026-07-02

Verify-path hardening, the full owned-ecosystem sample lifecycle
(provision → issue → verify → rotate), developer playbooks, and trusted
publishing. One behavioral change on the Argon2id surface, all in the
fail-closed direction; no new library API.

### Security

- **PHC acceptance bounds — poisoned-stored-row DoS closed.** `Verify` spends
  whatever work factors the stored PHC string declares, so a poisoned row
  (compromised database, hostile import) declaring `m=2147483647` previously
  triggered a ~2 TiB allocation attempt on every verification of that row,
  and sub-floor values (`t=0`, `p=0`) made the underlying Argon2id
  implementation throw out of `Verify` instead of failing closed. The parser
  now enforces documented acceptance bounds — `m` ∈ [8 KiB, 4 GiB],
  `t` ∈ [1, 512], `p` ∈ [1, 64], `m ≥ 8·p`, salt ∈ [8, 64] bytes,
  tag ∈ [12, 512] bytes — chosen to clear every profile a legitimate encoder
  emits (reference CLI, libsodium through its "sensitive" profile, all
  presets) while failing closed on anything outside, before any allocation.
- **Canonicality pins — one accepted spelling per hash.** Salt and tag
  segments must be the single canonical unpadded-base64 encoding of their
  bytes (`Convert`'s silent whitespace-skipping and non-zero-trailing-bit
  tolerance previously let distinct stored strings alias to the same decoded
  value), and numeric fields reject leading-zero aliases (`m=08192` parsed
  identically to `m=8192` under `NumberStyles.None`). Oversized base64
  fields are additionally rejected on length *before* any decode work, so a
  multi-megabyte poisoned field can't extract pad/decode/re-encode passes
  before the byte-length bounds turn it away.
- **`Argon2idOptions.Validate()` gains matching upper bounds** (4 GiB /
  t≤512 / p≤64 / 64-byte salt / 512-byte tag) so a configuration can never
  emit a hash the library's own verifier refuses.
- **⚠️ Breaking — read before upgrading if you ever ran an out-of-range
  config.** Earlier versions had no upper bounds, so configurations like
  `DegreeOfParallelism = Environment.ProcessorCount` on a >64-core host,
  `Iterations > 512`, or `SaltSizeBytes > 64` were legal and produced stored
  hashes that the new parser **permanently rejects** — verification returns
  `Failed` exactly as for a wrong password, and since rehash-on-login
  requires a successful verify, there is **no automatic recovery**: affected
  users need a password reset. The startup validation error you'd hit when
  upgrading such a config is the tripwire — do NOT "fix" it by just lowering
  the value; audit whether stored hashes were produced above the ceilings
  first. Same applies to imported foreign hashes below the new floors
  (salt < 8 bytes or tag < 12 bytes — spec-legal but sub-credible). No
  published profile (OWASP, RFC 9106, libsodium, this library's presets) is
  affected. Details in `KNOWN-GAPS.md` and `docs/TROUBLESHOOTING.md`.

### Added

- **Deterministic generative (fuzz-style) corpus for the PHC parser**
  (`PhcStringPropertyTests`) — seeded-PRNG format/parse roundtrips across the
  full acceptance bounds, structural mutations of valid stored hashes, and
  hostile random garbage; pins that parsing never throws, anything accepted
  is inside the bounds, and no mutation of a stored hash ever verifies.
  Fixed seeds make every failure reproducible. Closes the in-repo half of
  the Roadmap-to-1.0 fuzz gate; the token validator's generative coverage
  belongs to upstream PostQuantum.Jwt and is tracked there.
- **Acceptance-bounds edge tests** — both edges of every axis asserted
  exactly, plus poisoned-work-factor entries in the adversarial corpus and
  non-canonical-base64 rejection pins.
- **`samples/PostQuantum.Identity.Verifier.Demo`** — the missing half of the
  "you own both the issuer and every verifier" deployment model: a separate
  resource service that validates tokens issued by the main demo across a
  real process boundary. Holds only public keys (via the issuer's `pq-jwks`
  or provisioned `*.public.pem` files); references only
  `PostQuantum.Jwt.AspNetCore` — no Identity, no passwords, no private keys.
  Fail-closed startup: no loadable keys → the host refuses to start. Its
  README states plainly that revocation does not cross service boundaries.
- **`samples/PostQuantum.Identity.KeyTool`** — makes "provision an ML-DSA-65
  key out of band" concrete: `generate` (PKCS#8 private — AES-256-CBC +
  PBKDF2-SHA256 when a password is given — plus SPKI public PEM, with
  refuse-to-overwrite kid discipline) and `inspect` (algorithm + SPKI
  SHA-256 fingerprint). Pure .NET 10 BCL, zero dependencies.
- **Issuer demo: PEM-provisioned key ring.** `PQ_ISSUER_KEY_DIR` (+
  `PQ_ISSUER_KEY_PASSWORD`) loads KeyTool-provisioned `<kid>.private.pem`
  files and signs with the highest-sorting kid, completing the
  provision → issue → verify → rotate lifecycle across the three samples.
  Per-process random keys remain the zero-setup default.
- **`docs/QUANTUM-READINESS.md`** — a sequencing playbook for Identity
  apps: the threat scoped honestly (HNDL vs. signature forgery, what Grover
  does and doesn't break), an asset inventory table, a four-step adoption
  order (passwords now → owned-ecosystem tokens now → third-party
  boundaries deliberately later → TLS via platform), a "what done looks
  like" checklist, and an explicit "Argon2id is not PQC" clarification.
- **`docs/TROUBLESHOOTING.md`** — greppable symptom → cause → fix for
  everything adopters hit: ML-DSA unavailability / 503s, the five reasons a
  valid-looking token gets 401, generic-JWT-tooling rejection (by design),
  startup validation failures, container OOM sizing, foreign-hash
  verification (bounds / canonical encoding / variant), rehash-on-login not
  firing, appsettings binding precedence, demo rate-limit 429s, and the
  verifier's fail-closed startup.
- **`.http` walkthrough files for all three web samples** — runnable from
  Visual Studio 2022 / VS Code REST Client with named-request token
  chaining, including the negative cases (tampered token, revoked jti,
  wrong password) and the verifier demo's revocation-doesn't-cross-services
  edge, demonstrated live.
- **README: configuration-binding recipe** — tuning `Argon2idOptions` from
  `appsettings.{Environment}.json` via `Configure<Argon2idOptions>`, with
  the precedence rule stated (inline registration options would win) and
  the preflight logger as the "what did it actually resolve" answer.

### Infrastructure

- **NuGet Trusted Publishing.** The release workflow no longer uses a
  long-lived `NUGET_API_KEY` secret: the `publish` job exchanges its GitHub
  OIDC token for a short-lived nuget.org API key via `NuGet/login`, under a
  trusted-publishing policy pinned to this repo + workflow (+ the
  `nuget-publish` environment). Requires the `NUGET_USER` repository
  variable. A stolen copy of repo secrets can no longer publish this
  package; revoke any legacy key on nuget.org.
- **Benchmarks in CI with a regression budget** (closes a Roadmap-to-1.0
  gate). Argon2id benchmarks run on every push to `main` (short job,
  net10.0, JSON export), tracked over time on `gh-pages` via
  `github-action-benchmark`, failing on a >150% step-change. The budget's
  honesty limits (hosted-runner noise; no quiet-drift detection) are stated
  in `KNOWN-GAPS.md`.
- **macOS CI discovery job** (`macos-discovery`, pushes to `main` only —
  the signal it gathers changes per runner-image release, not per commit,
  so it deliberately stays off the per-PR critical path). Builds and runs
  the net10 suite; reports — without failing — whether the .NET 10 BCL
  macOS ML-DSA path let the PQ token tests run. README compatibility table
  updated from "untested" to "discovery lane".
- **Skip-count parsing extracted to `scripts/count-skipped-tests.sh`.** The
  fragile `dotnet test` console-log parsing behind the zero-skip PQ gates
  previously existed as three diverging inline copies (the Linux variant's
  `tail -1` would have under-counted a multi-TFM lane). One script, used by
  all lanes, that **errors when no summary lines are found** — a console-
  format change now breaks visibly instead of silently reporting 0 skips.

## [0.5.0-preview.1] — 2026-06-03

A final production-readiness polish release on top of 0.3. **No public API
changes; no behavior changes** — the deltas are all in framing, docs, and
the auditor-facing surface.

### Added

- **`docs/SUPPLY-CHAIN.md`** — auditor-facing companion to the README's
  three-command verify. Includes a chain-of-custody diagram from tag-push
  to `gh attestation verify`, a per-arrow verification table, the full
  `release.yml` hygiene checklist (OIDC, deterministic build, CycloneDX
  with the load-bearing `--disable-package-restore` flag, per-`.nupkg`
  attestation, `SHA256SUMS.txt`, gated publish, optional author signing),
  a reproducibility recipe, SHA-256 cross-check guidance, and an explicit
  "what this does NOT prove" honesty section.

### Changed

- **README — leading production-readiness banner.** New "Production-ready
  for owned and trusted ecosystems" callout above the split-surface table.
  Both rows in that table now describe the surface as production-ready
  rather than preview, with the token surface gated on "you own both the
  issuer and every verifier."
- **README — Roadmap to 1.0 gates re-framed.** Each gate is annotated with
  the surface it blocks (Argon2id / tokens / both) and the introduction
  states that most gates are external signals (upstream releases, RFCs,
  audits) rather than missing engineering. Closes the gap between "the
  code is production-discipline" and "the version says `-preview.N`."
- **README — supply-chain section renamed** to "How to verify this package
  (supply chain — three commands)" so auditors can find it cold; the body
  cross-references the new `docs/SUPPLY-CHAIN.md` companion.
- **`SECURITY.md` honesty statement** and **`KNOWN-GAPS.md` maturity
  preface** reworded to match the new production-readiness lead. Both now
  state explicitly that the `-preview.N` suffix reflects honest semver
  discipline against the Roadmap gates, not the engineering quality.
- **MVC demo** (`samples/PostQuantum.Identity.Mvc.Demo`) — token `Lifetime`
  lifted into a `TokenConstants.Lifetime` source-of-truth; login and
  refresh responses now surface `expires_in` for parity with the
  minimal-API demo.

### Repo hygiene

- **`.gitignore` hardened against secret leaks.** `nuget.key` /
  `nuget.key.*` / `*.nuget.key` are now explicitly excluded so a stray
  local API-key file at the repo root can never be committed.

## [0.3.0-preview.1] — 2026-06-02

A polish and assurance release. No public API changes from 0.2 — this hardens
testing, documentation, and samples toward a 10/10 bar.

### Added

- **Argon2id Known Answer Tests (multi-layer):**
  - RFC 9106 §5.3 reference vector (incl. keyed + associated-data path).
  - Canonical reference-`argon2`-CLI PHC string verifies through our hasher.
  - **PHC emitter wire-format pin** on the same vector (segment count, version
    field, comma-ordering, padding-stripping).
  - **Compute-then-format-then-verify roundtrips** across OWASP 2024 minimum
    (19 MiB, t=2), library default / RFC 9106 second profile (64 MiB, t=3),
    a stronger profile (128 MiB, t=4), and the documented minimum allowed by
    `Argon2idOptions` (8 MiB, t=1).
  - Single-byte-tag-tamper rejection KAT.
- **Token Known Answer Tests** (net10): JOSE header pin (typ:JWT,
  alg:ML-DSA-65, kid); registered-claim shape + timestamp consistency; single
  vs. multi-role array shape; **sign-then-encrypt envelope KAT** (5-seg JWE,
  alg:X-Wing, enc:A256GCM, cty:JWT) with full validation roundtrip; end-to-end
  recovered-claim equality.
- **Token security/validation corpus** (net10): sign-then-encrypt (X-Wing)
  roundtrip, multi-role JSON-array claims, reserved-claim override protection,
  and fail-closed rejection of expired / wrong-key / per-segment-tampered /
  malformed tokens.
- **`Argon2idOptions` validation tests** covering every out-of-range branch,
  the defensive-copy guarantee, and salt-size-driven rehash.
- **Production-shaped reference samples:**
  - `samples/PostQuantum.Identity.Demo` (minimal API) adds `/refresh` (with
    old-jti revocation), `/logout`, `/.well-known/pq-jwks` key discovery,
    in-memory revocation middleware, and ProblemDetails error responses.
  - `samples/PostQuantum.Identity.Mvc.Demo` (controllers) is a controller-
    based mirror of the same flows.
- **README — "Production readiness — at a glance"** stating the split-surface
  maturity (Argon2id production-ready; hybrid tokens preview for owned/trusted
  ecosystems), with an explicit **Roadmap to 1.0** listing every gate that has
  to close before the version stops carrying `-preview.N`.
- **README — "Getting started in five minutes"** taking a reader from
  `dotnet new` to a working register/login endpoint, with a one-line PBKDF2 →
  Argon2id migration diff and the .NET 10 hybrid-token bolt-on.
- **README — "When to use this library"** with sharper four-bucket framing
  (✅ adopt today / ⚠️ use standalone Argon2id / ⏳ wait on the token surface
  / ⛔ don't) and a **Comparison table** vs. default Identity / Argon2id-alone
  / hand-rolled PQ JWT.
- **README — "Supply chain — verifiable in three commands"** leading with the
  `nuget install` → `unzip -p bom.json` → `gh attestation verify` flow, a
  per-hygiene matrix (SBOM, attestation, deterministic builds, SourceLink,
  pinned deps, Dependabot, CodeQL, version-sync), and a reproducible local
  build snippet.
- **MIGRATION.md — "What you can promise stakeholders before shipping"**
  operational checklist: zero forced resets, no migration job, reversible,
  fail-closed, no new persisted state, single dep.
- **Opinionated `Argon2idOptions` presets** — four named factory methods
  (`RecommendedDefault()`, `OwaspMinimum()`, `HighSecurity()`,
  `LowMemoryContainer()`) cover the realistic environment classes without
  hand-tuning. Each is KAT-asserted to match its published profile.
- **One-line preset DI overloads** — `AddArgon2idPasswordHasher<TUser>(preset)`
  and `AddArgon2idPasswordHasherWithMigration<TUser>(preset)` on both
  `IServiceCollection` and `IdentityBuilder`. Values are snapshotted at
  registration time, so a caller mutating their preset reference between
  `services.Add…` and `app.Build()` cannot silently weaken the hasher.
- **Startup-time options validation** — DI now registers
  `IValidateOptions<Argon2idOptions>` (and, on net10,
  `IValidateOptions<PostQuantumTokenOptions>`), so a misconfigured work
  factor or missing `SigningKey` fails when the host starts with a message
  naming the offending property, instead of throwing at first hash / first
  login.
- **Production-scenario test corpus** — concurrent verification correctness,
  per-axis rehash-threshold theory (memory / iterations / parallelism / salt
  / tag), and an adversarial PHC corpus (variant casing, segment-count
  attacks, embedded whitespace, base64 attacks, path-traversal noise, raw
  junk) all proving `TryParse` stays fail-closed.
- **UserManager-based migration integration tests** — full
  PBKDF2-seeded → `CheckPasswordAsync` → row-rewrites-to-Argon2id cycle
  through a real `UserManager`, plus a no-rewrite-on-wrong-password
  regression and a new-users-hash-Argon2id-immediately check.
- **DoS protection wired into both samples** — fixed-window IP-partition
  rate limiter on `/register`, `/login`, `/refresh` (10 reqs / 30 s). Smoke-
  tested: returns 429 after the budget, matching the documented policy.
- **IETF JOSE PQC alignment subsection** in the README explaining where the
  `alg = ML-DSA-65` identifier comes from (upstream PostQuantum.Jwt, not
  this package), why it's intentionally non-IANA today (drafts in flight),
  and how cross-ecosystem verification will land via a normal upstream
  version bump with no PostQuantum.Identity API change.
- **`docs/THREAT-MODEL.md`** — STRIDE per surface (Argon2id and tokens), with
  per-threat code/test pointers and an explicit out-of-scope list.
- **`docs/SECURITY-REVIEW-CHECKLIST.md`** — auditor-facing single-page index
  to every claim in the security posture with file/line/test backings.
- **`docs/PRODUCTION-CHECKLIST.md`** — go-live signoff checklist covering
  hasher, sign-in protection, tokens, revocation, encryption, observability,
  supply chain, DR, compliance, and final signoff.
- **`SECURITY.md` — "FIPS 140-3 deployment guidance"** — per-primitive FIPS
  cert status (honest: Argon2id outside, AES-256-GCM approved, ML-DSA/ML-KEM
  TBD upstream), OS-level FIPS-mode behavior, compliance-friendly deployment
  patterns, and what the library does/doesn't promise.
- **README "Compatibility"** expanded: per-TFM surface table, per-OS support
  rows (Windows / Linux modern / Linux older OpenSSL / macOS / Alpine),
  container constraints with preset-to-pod-size mapping, CPU-arch note.
- **README "Crypto agility — key rotation and algorithm rotation"** — extends
  the `kid` rotation story with a full procedure and the future algorithm-
  rotation path (`kid`-per-algorithm), honest about what depends on upstream.
- **Opt-in startup preflight logger** — `AddPostQuantumPreflightLogging()`
  registers a hosted service that writes a single structured INFO line at
  boot summarising the resolved Argon2id work factors and approximate
  per-call memory budget. Source-generated `LoggerMessage` for allocation-
  free output. Sentinel-string-tested to confirm it never logs key material,
  passwords, or token contents. Wired into both samples.

### Changed

- net10 line coverage is now ~94% (71 tests on net10; 49 on net8/net9).
- **Sample bug fixes** (also shipped to `main` before tag): /refresh issues
  the new token BEFORE revoking the old jti (transient failure cannot leave
  the caller token-less); /me formats `expiresAt` as ISO-8601 instead of a
  raw Unix-seconds string; `expires_in` is no longer hardcoded — `Lifetime`
  is lifted into a single source-of-truth constant.
- `docs/MIGRATION.md` rewritten as a step-by-step transparent-migration guide
  (PBKDF2 path, bcrypt/scrypt path, work-factor tuning, rollback, FAQ) and
  now leads with a stakeholder checklist.
- `SECURITY.md` and `KNOWN-GAPS.md` restructured around the split-surface
  stance and the Roadmap-to-1.0 gates; expanded KAT corpus and revocation
  contract preserved.
- `.csproj` package description and release notes restructured to lead with
  the production-readiness positioning and the supply-chain verification flow.

## [0.2.0-preview.1] — 2026-06-02

The v0.2 roadmap, delivered. Builds on the 0.1 surface; no breaking changes to
existing types.

### Added

- **Migration to Argon2id from a legacy store:**
  - `MigratingPasswordHasher<TUser>` — verifies any stored hash that isn't an
    Argon2id PHC string with the stock ASP.NET Core Identity PBKDF2 hasher, then
    reports `SuccessRehashNeeded` so Identity rewrites it as Argon2id on the next
    sign-in. New hashes are always Argon2id; garbage/wrong inputs fail closed.
  - `Argon2idPasswordHasher.IsArgon2idHash(string?)` — cheap format check used to
    route verification.
  - DI: `AddArgon2idPasswordHasherWithMigration<TUser>()` (IServiceCollection +
    IdentityBuilder).
- **Key rotation (`kid`):** `PostQuantumTokenOptions.KeyId` is stamped into each
  token's `kid` header. The demo wires a two-key ring and validates with a
  `SignatureKeyResolver`, so tokens signed by the current or previous key both
  verify.
- **AOT/trim-clean token issuance:** claims now serialize through a
  source-generated `JsonTypeInfo<T>` (`PostQuantumIdentityJsonContext`) and
  PostQuantum.Jwt's typed `WithClaim<T>` overload — no reflection. The net10
  assembly asserts `IsAotCompatible`.
- **Supply chain:** a CycloneDX SBOM (`bom.json`) is generated and embedded in
  the `.nupkg` on every pack (restore disabled so multi-TFM dependency groups
  stay intact).
- **CI/CD:** `.github/workflows/ci.yml` (version-sync, Windows + Linux build/test,
  a PQ-required lane pinning OpenSSL 3.5+ via conda-forge that fails on any
  skipped test, pack-verify) and `release.yml` (tag-driven pack + SBOM +
  build-provenance attestation + gated nuget.org publish), plus
  `scripts/check-version-sync.sh` and `global.json`.
- **Benchmarks:** `benchmarks/PostQuantum.Identity.Benchmarks` (BenchmarkDotNet)
  measuring Argon2id hash/verify across work-factor profiles.

### Changed

- The demo (`samples/PostQuantum.Identity.Demo`) now validates tokens through the
  real `PqJwtBearer` authentication handler (`[Authorize]`) instead of validating
  manually, and demonstrates `kid`-based key rotation.

## [0.1.0-preview.1] — 2026-06-02

Initial preview.

### Added

- **Argon2id password hashing** (`net8.0`/`net9.0`/`net10.0`):
  - `Argon2idPasswordHasher` core — `HashPassword`, `Verify`, `NeedsRehash`,
    producing/parsing PHC strings (`$argon2id$v=19$…`).
  - `Argon2idPasswordHasher<TUser>` — `IPasswordHasher<TUser>` adapter that maps a
    weaker-than-current stored hash to
    `PasswordVerificationResult.SuccessRehashNeeded` for transparent upgrade.
  - `Argon2idOptions` — secure-by-default work factors (64 MiB, t=3, p=1) with
    enforced minimums and the standard Options pattern.
  - `VerifyResult` — `Success` + `NeedsRehash` from a single verification.
- **Post-quantum hybrid token issuance** (`net10.0`):
  - `IPostQuantumTokenService<TUser>` / `PostQuantumTokenService<TUser>` — issues
    PostQuantum.Jwt tokens (ML-DSA-65 signature, optional X-Wing encryption) from
    an Identity user's id, name, email, roles, and claims.
  - `PostQuantumTokenOptions` — signing key, issuer/audience, lifetime, optional
    encryption recipient, claim-mapping toggles, with validation.
- **DI extensions** — `AddArgon2idPasswordHasher<TUser>` (IServiceCollection +
  IdentityBuilder) and, on net10, `AddPostQuantumTokenService<TUser>` /
  `AddPostQuantumTokens<TUser>`.
- **Sample** — `samples/PostQuantum.Identity.Demo`, a minimal-API app with real
  ASP.NET Core Identity (in-memory EF store), register/login/me endpoints.
- **Docs** — README, SECURITY.md, KNOWN-GAPS.md, CLAUDE.md, docs/.

### Notes

- Preview software. **Not** independently audited; **not** for production.
- Issued tokens use non-IANA JOSE identifiers and are intentionally
  non-interoperable with generic JWT tooling.

[1.0.0]: https://github.com/systemslibrarian/postquantum-identity/releases/tag/v1.0.0
[0.6.0-preview.1]: https://github.com/systemslibrarian/postquantum-identity/releases/tag/v0.6.0-preview.1
[0.5.0-preview.1]: https://github.com/systemslibrarian/postquantum-identity/releases/tag/v0.5.0-preview.1
[0.3.0-preview.1]: https://github.com/systemslibrarian/postquantum-identity/releases/tag/v0.3.0-preview.1
[0.2.0-preview.1]: https://github.com/systemslibrarian/postquantum-identity/releases/tag/v0.2.0-preview.1
[0.1.0-preview.1]: https://github.com/systemslibrarian/postquantum-identity/releases/tag/v0.1.0-preview.1
