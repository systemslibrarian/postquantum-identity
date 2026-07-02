# Security Review Checklist

A one-stop reference for security reviewers, auditors, and compliance
stakeholders evaluating PostQuantum.Identity. Every claim below points to
the code, the test, or the document that backs it — so a reviewer can
independently verify rather than take our word for it.

This page is intentionally short. Deep dives live in:

- [`SECURITY.md`](../SECURITY.md) — full security policy + cryptographic construction + FIPS guidance
- [`docs/THREAT-MODEL.md`](THREAT-MODEL.md) — STRIDE per surface, assets, mitigations, out-of-scope
- [`KNOWN-GAPS.md`](../KNOWN-GAPS.md) — what's not done yet, by surface
- [`README.md` → What 1.0 means](../README.md#what-10-means--and-what-it-does-not) — exactly what the version number does and does not claim, plus the post-1.0 roadmap

---

## 1. Surface scope and maturity

| What | Where to verify |
|---|---|
| Library ships **two surfaces** at different scopes (Argon2id everywhere; hybrid tokens for owned ecosystems only) | [`README.md` → Production readiness](../README.md#production-readiness--at-a-glance) |
| 1.0 = semver-stable API on stable upstream; explicitly NOT an audit claim; post-1.0 roadmap lists what remains | [`README.md` → What 1.0 means](../README.md#what-10-means--and-what-it-does-not) |
| What is explicitly out of scope (KMS, replay store, lockout, TLS, OAuth2/OIDC server) | [`docs/THREAT-MODEL.md` → Explicitly out of scope](THREAT-MODEL.md#explicitly-out-of-scope) |

## 2. Cryptographic primitives

| What | Where to verify |
|---|---|
| Argon2id from [Konscious.Security.Cryptography.Argon2](https://github.com/kmaragon/Konscious.Security.Cryptography) — Argon2 1.3 spec | [`PostQuantum.Identity.csproj`](../src/PostQuantum.Identity/PostQuantum.Identity.csproj) `<PackageReference>` |
| ML-DSA-65 / ML-KEM-768 from the .NET 10 BCL via PostQuantum.Jwt | [`PostQuantum.Identity.csproj`](../src/PostQuantum.Identity/PostQuantum.Identity.csproj) net10-only ItemGroup |
| Constant-time tag compare via `CryptographicOperations.FixedTimeEquals` | [`Argon2idPasswordHasher.cs:124`](../src/PostQuantum.Identity/Argon2idPasswordHasher.cs) |
| Salt source: `RandomNumberGenerator.GetBytes` (.NET CSPRNG) | [`Argon2idPasswordHasher.cs:73`](../src/PostQuantum.Identity/Argon2idPasswordHasher.cs) |
| Plaintext bytes + computed candidate zeroed with `CryptographicOperations.ZeroMemory` | [`Argon2idPasswordHasher.cs:82-83, 125, 136`](../src/PostQuantum.Identity/Argon2idPasswordHasher.cs) |
| No hand-rolled crypto in this library | Search the source: `grep -r "Argon2id\|MLDsa\|MLKem" src/` finds usage only via the libraries above |

## 3. Known Answer Tests (cryptographic correctness, pinned in CI)

| What | Where to verify |
|---|---|
| RFC 9106 §5.3 Argon2id reference vector (incl. keyed + AD) | [`Argon2idKnownAnswerTests.cs::Rfc9106_argon2id_reference_vector`](../tests/PostQuantum.Identity.Tests/Argon2idKnownAnswerTests.cs) |
| Reference-`argon2`-CLI PHC interop | [`Argon2idKnownAnswerTests.cs::Verifies_phc_string_from_reference_argon2_cli`](../tests/PostQuantum.Identity.Tests/Argon2idKnownAnswerTests.cs) |
| PHC emitter wire-format pin | [`Argon2idKnownAnswerTests.cs::Phc_emitter_pins_reference_cli_wire_format`](../tests/PostQuantum.Identity.Tests/Argon2idKnownAnswerTests.cs) |
| Compute → format → verify roundtrips across OWASP / RFC 9106 / strong / minimum profiles | [`Argon2idKnownAnswerTests.cs::Phc_roundtrips_for_published_work_factor_profiles`](../tests/PostQuantum.Identity.Tests/Argon2idKnownAnswerTests.cs) |
| Single-byte tag tamper rejection | [`Argon2idKnownAnswerTests.cs::Single_byte_tag_tamper_rejects_verification`](../tests/PostQuantum.Identity.Tests/Argon2idKnownAnswerTests.cs) |
| Token JOSE header KAT (`typ:JWT`, `alg:ML-DSA-65`, `kid`) | [`PostQuantumTokenKnownAnswerTests.cs::Header_kat_signed_token_declares_typ_jwt_alg_mldsa65_kid`](../tests/PostQuantum.Identity.Tests/Tokens/PostQuantumTokenKnownAnswerTests.cs) |
| Token payload KAT (registered claims, timestamp consistency, unique `jti`) | [`PostQuantumTokenKnownAnswerTests.cs::Payload_kat_carries_registered_claims_with_consistent_timestamps`](../tests/PostQuantum.Identity.Tests/Tokens/PostQuantumTokenKnownAnswerTests.cs) |
| Sign-then-encrypt envelope KAT (5-seg JWE, `alg:X-Wing`, `enc:A256GCM`, `cty:JWT`) | [`PostQuantumTokenKnownAnswerTests.cs::Envelope_kat_sign_then_encrypt_declares_xwing_a256gcm_with_inner_jws`](../tests/PostQuantum.Identity.Tests/Tokens/PostQuantumTokenKnownAnswerTests.cs) |

## 4. Fail-closed behavior

| What | Where to verify |
|---|---|
| Malformed PHC → `VerifyResult.Failed`, never a partial match | [`PhcStringTests.cs::TryParse_fails_closed_on_malformed_input`](../tests/PostQuantum.Identity.Tests/PhcStringTests.cs) |
| Adversarial PHC corpus (variant casing, segment counts, embedded whitespace, base64 attacks, path-traversal noise, poisoned work factors, junk) | [`Argon2idProductionScenarioTests.cs::TryParse_fails_closed_on_adversarial_input`](../tests/PostQuantum.Identity.Tests/Argon2idProductionScenarioTests.cs) |
| PHC acceptance bounds pinned at both edges of every axis (`m`/`t`/`p`/salt/tag, `m ≥ 8·p`) | [`PhcStringTests.cs::TryParse_enforces_acceptance_bounds_at_the_exact_edges`](../tests/PostQuantum.Identity.Tests/PhcStringTests.cs) |
| Canonical-base64 pin — whitespace and trailing-bit aliases rejected | [`PhcStringTests.cs::TryParse_rejects_non_canonical_base64`](../tests/PostQuantum.Identity.Tests/PhcStringTests.cs) |
| Numeric canonicality — leading-zero aliases (`m=08192`) rejected | [`PhcStringTests.cs::TryParse_rejects_leading_zero_aliases_in_numeric_fields`](../tests/PostQuantum.Identity.Tests/PhcStringTests.cs) |
| Oversized base64 fields rejected on length before decode work | [`PhcStringTests.cs::TryParse_rejects_oversized_base64_fields_before_decoding`](../tests/PostQuantum.Identity.Tests/PhcStringTests.cs) |
| Deterministic generative (fuzz-style) corpus — roundtrips, mutations, garbage; never throws, stays bounded, no mutation verifies | [`PhcStringPropertyTests.cs`](../tests/PostQuantum.Identity.Tests/PhcStringPropertyTests.cs) |
| Token: expired / wrong-key / per-segment-tampered / malformed → `PqJwtException` | [`PostQuantumTokenSecurityTests.cs`](../tests/PostQuantum.Identity.Tests/Tokens/PostQuantumTokenSecurityTests.cs) |
| Reserved JWT claims (`iss/sub/aud/exp/nbf/iat/jti`) cannot be overridden by user-store claims | [`PostQuantumTokenSecurityTests.cs::Custom_user_claims_flow_through_but_cannot_override_reserved`](../tests/PostQuantum.Identity.Tests/Tokens/PostQuantumTokenSecurityTests.cs) |
| Insecure `Argon2idOptions` (< 8 MiB, t<1, etc.) reject at construction | [`Argon2idOptions.cs::Validate`](../src/PostQuantum.Identity/Argon2idOptions.cs) |
| **Fail-fast at host startup** via `IValidateOptions<T>` (Argon2id + token options) | [`Argon2idStartupValidationTests.cs`](../tests/PostQuantum.Identity.Tests/Argon2idStartupValidationTests.cs) |

## 5. Migration safety

| What | Where to verify |
|---|---|
| Full `UserManager` rewrite-on-sign-in (PBKDF2 → Argon2id) | [`MigrationUserManagerIntegrationTests.cs::UserManager_rewrites_legacy_pbkdf2_hash_as_argon2id_on_successful_sign_in`](../tests/PostQuantum.Identity.Tests/MigrationUserManagerIntegrationTests.cs) |
| Wrong password does NOT trigger a rewrite (no silent success masking) | [`MigrationUserManagerIntegrationTests.cs::UserManager_does_not_rewrite_when_password_check_fails`](../tests/PostQuantum.Identity.Tests/MigrationUserManagerIntegrationTests.cs) |
| New users hash with Argon2id immediately (no PBKDF2 detour) | [`MigrationUserManagerIntegrationTests.cs::UserManager_hashes_new_users_with_argon2id_immediately`](../tests/PostQuantum.Identity.Tests/MigrationUserManagerIntegrationTests.cs) |
| Stakeholder-friendly migration claims (zero forced resets, no migration job, reversible, fail-closed, single dep) | [`docs/MIGRATION.md` → What you can promise stakeholders](MIGRATION.md#what-you-can-promise-stakeholders-before-shipping) |
| End-to-end MIGRATION.md path including bcrypt/scrypt adapter shape, work-factor tuning, rollback, FAQ | [`docs/MIGRATION.md`](MIGRATION.md) |

## 6. Concurrency & DoS resistance

| What | Where to verify |
|---|---|
| `Verify` thread-safe under 64-way Parallel.For load | [`Argon2idProductionScenarioTests.cs::Verify_is_safe_under_concurrent_load`](../tests/PostQuantum.Identity.Tests/Argon2idProductionScenarioTests.cs) |
| Concurrent `HashPassword` produces distinct salts (CSPRNG contention-free) | [`Argon2idProductionScenarioTests.cs::HashPassword_produces_distinct_salts_under_concurrent_load`](../tests/PostQuantum.Identity.Tests/Argon2idProductionScenarioTests.cs) |
| Wrong-password Verify under concurrency is always `Failed` (no transient match) | [`Argon2idProductionScenarioTests.cs::Verify_wrong_password_under_concurrency_is_always_Failed`](../tests/PostQuantum.Identity.Tests/Argon2idProductionScenarioTests.cs) |
| Poisoned-stored-row DoS bounded: parser rejects out-of-bounds work factors before any allocation | [`SECURITY.md` → Bounded verification cost](../SECURITY.md#threat-model), [`PhcString.cs`](../src/PostQuantum.Identity/Internal/PhcString.cs) acceptance-bounds block |
| Asymmetric DoS mitigation: fixed-window IP-partition rate limiter on `/register`/`/login`/`/refresh` | Samples: [`PostQuantum.Identity.Demo/Program.cs`](../samples/PostQuantum.Identity.Demo/Program.cs), [`PostQuantum.Identity.Mvc.Demo/Controllers/AccountController.cs`](../samples/PostQuantum.Identity.Mvc.Demo/Controllers/AccountController.cs) — smoke-tested 200 → 429 at budget |
| `/refresh` issues new token BEFORE revoking old `jti` (no token-less window on transient failures) | [`PostQuantum.Identity.Demo/Program.cs` → `/refresh`](../samples/PostQuantum.Identity.Demo/Program.cs) — comment `// Issue the new token BEFORE revoking the old jti` |

## 7. Token surface (owned ecosystems)

| What | Where to verify |
|---|---|
| `alg = ML-DSA-65` is intentionally non-IANA (rationale, no rename surprise) | [`README.md` → IETF JOSE PQC alignment](../README.md#ietf-jose-pqc-alignment--where-the-alg-identifier-comes-from) |
| Path to cross-ecosystem verification (upstream version bump, no PostQuantum.Identity API change) | Same section as above |
| `kid` rotation contract demonstrated end-to-end with a two-key ring | [`PostQuantumTokenServiceTests.cs::Token_from_rotated_key_validates_via_kid_resolver`](../tests/PostQuantum.Identity.Tests/Tokens/PostQuantumTokenServiceTests.cs), and live in [`PostQuantum.Identity.Demo/Program.cs`](../samples/PostQuantum.Identity.Demo/Program.cs) |
| Owned-ecosystem topology (separate issuer + verifier services, verifier holds public keys only) demonstrated live | [`samples/PostQuantum.Identity.Verifier.Demo`](../samples/PostQuantum.Identity.Verifier.Demo) — no Identity / private-key / password dependency; fail-closed startup |
| Out-of-band key provisioning (PKCS#8 + SPKI PEM, encrypted option, refuse-to-overwrite kid discipline) | [`samples/PostQuantum.Identity.KeyTool`](../samples/PostQuantum.Identity.KeyTool) — pure BCL |
| Optional hybrid encryption (X-Wing + AES-256-GCM); holds unless both classical and PQ halves are broken | [`PostQuantumTokenSecurityTests.cs::Sign_then_encrypt_roundtrips_and_marks_encrypted`](../tests/PostQuantum.Identity.Tests/Tokens/PostQuantumTokenSecurityTests.cs) |

## 8. Supply-chain integrity

| What | Where to verify |
|---|---|
| Three-command verification flow (`nuget install` → `unzip -p bom.json` → `gh attestation verify`) | [`README.md` → Supply chain](../README.md#supply-chain--verifiable-in-three-commands) |
| Embedded CycloneDX SBOM in every `.nupkg` | Inspect: `unzip -p PostQuantum.Identity.<v>.nupkg bom.json` |
| GitHub build-provenance attestation (Sigstore-signed) | Verify: `gh attestation verify <nupkg> --owner systemslibrarian` |
| Deterministic builds, SourceLink, `.snupkg` symbols | [`Directory.Build.props`](../Directory.Build.props), [`PostQuantum.Identity.csproj`](../src/PostQuantum.Identity/PostQuantum.Identity.csproj) |
| Trusted Publishing — no long-lived NuGet API key; publish job exchanges GitHub OIDC for a short-lived key under a repo+workflow-pinned policy | [`release.yml`](../.github/workflows/release.yml) `publish` job, [`docs/SUPPLY-CHAIN.md` → Hygiene checklist](SUPPLY-CHAIN.md#hygiene-checklist--whats-in-releaseyml) |
| CodeQL on every PR/push, Dependabot enabled | [`.github/workflows/codeql.yml`](../.github/workflows/codeql.yml), [`.github/dependabot.yml`](../.github/dependabot.yml) |
| Version-sync check (csproj / README / CHANGELOG must agree) | [`scripts/check-version-sync.sh`](../scripts/check-version-sync.sh) |

## 9. Operational hygiene

| What | Where to verify |
|---|---|
| Library never persists key material; you own all keys | [`SECURITY.md` → Non-goals → Key management](../SECURITY.md#threat-model) |
| Library never logs hashed passwords, plaintext passwords, or token contents | [`KNOWN-GAPS.md` → Operational hygiene](../KNOWN-GAPS.md) |
| FIPS 140-3 deployment guidance (cert status per primitive, OS-level FIPS modes, deployment patterns) | [`SECURITY.md` → FIPS 140-3 deployment guidance](../SECURITY.md#fips-140-3-deployment-guidance) |
| Container sizing table (preset ↔ pod memory budget) | [`README.md` → Compatibility → Container constraints](../README.md#container-constraints) |

## 10. What's NOT done yet (honest disclosure)

| Gap | Tracked at |
|---|---|
| No independent third-party audit — 1.0 does not change this | [`README.md` → What 1.0 means](../README.md#what-10-means--and-what-it-does-not), [`KNOWN-GAPS.md`](../KNOWN-GAPS.md) |
| Generative fuzz corpus covers the PHC parser only; token-validator fuzzing is upstream (PostQuantum.Jwt); coverage-guided fuzzing unexplored | [`KNOWN-GAPS.md` → Testing & environment](../KNOWN-GAPS.md) |
| Benchmark budget in CI catches step-changes (150%), not quiet drift; precision runs need pinned hardware | [`KNOWN-GAPS.md` → Testing & environment](../KNOWN-GAPS.md) |
| macOS is a discovery lane, not PQ-required | [`KNOWN-GAPS.md` → Testing & environment](../KNOWN-GAPS.md) |
| Tokens remain non-interoperable with generic JWT tooling (waiting on IETF JOSE PQC drafts → upstream identifier adoption) | [`README.md` → What 1.0 means](../README.md#what-10-means--and-what-it-does-not) |
| No bundled KMS integration | [`KNOWN-GAPS.md` → Tokens & protocol](../KNOWN-GAPS.md) |

---

## How to run the test suite a reviewer cares about

```bash
# All KATs, all production-scenario regression tests, all integration tests.
dotnet test -c Release

# On Linux where system OpenSSL predates ML-DSA, point at conda's OpenSSL 3.5+.
LD_LIBRARY_PATH=/opt/conda/lib dotnet test -c Release
```

Current count: **135 (net8) / 135 (net9) / 157 (net10)** — all green.

A passing run is the floor, not the ceiling. Pair it with the threat model
and the gap list above for the full picture.

---

*To God be the glory — 1 Corinthians 10:31.*
