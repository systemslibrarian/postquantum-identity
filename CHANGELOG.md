# Changelog

All notable changes to PostQuantum.Identity are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/), and the project adheres
to [Semantic Versioning](https://semver.org/).

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

[0.3.0-preview.1]: https://github.com/systemslibrarian/postquantum-identity/releases/tag/v0.3.0-preview.1
[0.2.0-preview.1]: https://github.com/systemslibrarian/postquantum-identity/releases/tag/v0.2.0-preview.1
[0.1.0-preview.1]: https://github.com/systemslibrarian/postquantum-identity/releases/tag/v0.1.0-preview.1
