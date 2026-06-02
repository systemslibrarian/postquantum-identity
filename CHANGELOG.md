# Changelog

All notable changes to PostQuantum.Identity are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/), and the project adheres
to [Semantic Versioning](https://semver.org/).

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

[0.2.0-preview.1]: https://github.com/systemslibrarian/postquantum-identity/releases/tag/v0.2.0-preview.1
[0.1.0-preview.1]: https://github.com/systemslibrarian/postquantum-identity/releases/tag/v0.1.0-preview.1
