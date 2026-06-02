# Known Gaps

A transparent, running list of what PostQuantum.Identity does **not** yet do,
what is unverified, and where the sharp edges are. Honesty over polish: if
something is incomplete, it is listed here rather than glossed over. This file is
part of the contract with anyone evaluating the library.

Last reviewed for: `0.2.0-preview.1`.

## Maturity

- **No external audit.** No third party has reviewed the design or
  implementation. Do not use in production.
- **Preview API.** Public types and method signatures may change without notice
  until 1.0.

## Password hashing

- **No pepper / keyed hashing.** This package's Argon2id core hashes with salt +
  work factors only; it does not mix in a server-held secret. If you need a
  pepper, the standalone
  [`argon2id-passwordhasher`](https://github.com/systemslibrarian/argon2id-passwordhasher)
  package provides one (`PepperRing`), plus a PBKDF2→Argon2id migration adapter
  and benchmarks. PostQuantum.Identity intentionally ships a smaller, dependency-
  light Argon2id core so it does not require that package; the two are siblings,
  not layers.
- **Migration adapter covers the stock PBKDF2 hasher only.**
  `MigratingPasswordHasher<TUser>` (via `AddArgon2idPasswordHasherWithMigration`)
  verifies the default ASP.NET Core Identity PBKDF2 format and rehashes to
  Argon2id. It does **not** bundle adapters for bcrypt/scrypt/other legacy
  formats — supply your own `IPasswordHasher<TUser>` as the legacy hasher if your
  store uses something else.
- **String-only API.** `HashPassword`/`Verify` take `string`, not
  `ReadOnlySpan<char>`/`byte[]`. The plaintext therefore lives on the managed
  heap as a `string` (immutable, not zeroable) for the duration of the call; only
  the derived UTF-8 bytes are zeroed.
- **No throttling or lockout.** Memory-hard hashing raises the cost of offline
  cracking; it is not a substitute for online rate-limiting / lockout, which is
  Identity's job, not this package's.

## Tokens & protocol (.NET 10)

- **`.NET 10 only, OpenSSL 3.5+ on Linux.**` The token service depends on the
  BCL post-quantum primitives and PostQuantum.Jwt, which target .NET 10. On
  `net8.0`/`net9.0` the token types are not compiled in at all. Where ML-DSA is
  unavailable at runtime, operations fail closed.
- **Non-standard JOSE identifiers.** Issued tokens use `alg = ML-DSA-65` (and,
  when encrypted, `enc = X-Wing` / `A256GCM`), none of which are IANA-registered.
  They will **not** validate in standard JWT tooling. This is inherited from
  PostQuantum.Jwt by design.
- **No bundled authentication handler.** This package *issues* tokens; it does not
  ship its own `AuthenticationHandler`. Validate them with PostQuantum.Jwt's
  `AddPqJwtBearer` (the demo does exactly this, with a `kid` resolver) or
  `PqJwtValidator` directly.
- **Rotation is issuer-stamps-`kid` + validator-resolves-`kid`.** The token
  service stamps `PostQuantumTokenOptions.KeyId` into each token; the verifier
  picks the key via PostQuantum.Jwt's `SignatureKeyResolver` (demonstrated in the
  sample). This package does not itself manage a key store, schedule rotations, or
  pick "the current key" for you — you own the key ring.
- **AOT: the claim path is clean; full-app AOT is your responsibility.** Token
  issuance serializes claims via source-generated `JsonTypeInfo<T>` and the net10
  assembly asserts `IsAotCompatible`. That covers this library's surface; whether
  your whole app publishes AOT also depends on ASP.NET Core Identity, EF, and your
  other dependencies.

## Testing & environment

- **net8.0 / net9.0 are build-verified and unit-tested; net8.0 unit tests require
  the .NET 8 runtime.** The Argon2id code is runtime-agnostic and is exercised on
  every installed runtime in CI. The hybrid-token tests run only on net10.0 and
  skip themselves when the host's OpenSSL predates ML-DSA (3.5+).
- **No property-based or fuzz tests yet.** The PHC parser has hand-written
  malformed-input cases but no generative fuzzing.
- **Benchmarks are not run in CI.** `benchmarks/PostQuantum.Identity.Benchmarks`
  (BenchmarkDotNet) exists for local Argon2id work-factor tuning, but the CI
  workflow does not execute it or track regressions over time.

---

If you hit a gap not listed here, that itself is a gap — please open an issue so
it can be recorded honestly.

---

*To God be the glory — 1 Corinthians 10:31.*
