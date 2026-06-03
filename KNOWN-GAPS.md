# Known Gaps

A transparent, running list of what PostQuantum.Identity does **not** yet do,
what is unverified, and where the sharp edges are. Honesty over polish: if
something is incomplete, it is listed here rather than glossed over. This file
is part of the contract with anyone evaluating the library.

Last reviewed for: `0.3.0-preview.1` (2026-06-02).

## Maturity — split by surface

PostQuantum.Identity ships two surfaces with deliberately different stances:

- **Argon2id password hashing** (`net8` / `net9` / `net10`): implemented to
  production discipline, RFC 9106 §5.3 KAT-pinned, fail-closed, vetted
  dependency. Suitable for production adoption today.
- **Hybrid post-quantum tokens** (`net10` only): preview, suitable for
  **owned / trusted ecosystems** where you own the issuer and every verifier.
  Not for public-internet OIDC. Pending: upstream PostQuantum.Jwt 1.0, IETF
  JOSE PQC drafts settling, third-party audit.

The "preview" label on the package as a whole reflects the more conservative
of the two surfaces; the [`Roadmap to 1.0`](README.md#roadmap-to-10) in the
README lists every gate that has to close before the version stops carrying
`-preview.N`.

### Cross-cutting

- **No external audit.** No third party has reviewed the design or
  implementation. Independent review is one of the Roadmap-to-1.0 gates.
- **Preview API.** Public types and method signatures may change without notice
  until 1.0. Breaking changes will be called out in the changelog and the
  pre-release tag.
- **Identity drag-in only — no full IdentityServer / OpenIddict story.** This
  library plugs into Identity's `IPasswordHasher<TUser>` and adds a token
  issuer. It is not an OAuth2/OIDC authorization server and does not implement
  RFC 6749 flows. Use it from within your own auth surface.

## Password hashing

- **No pepper / keyed hashing.** This package's Argon2id core hashes with salt +
  work factors only; it does not mix in a server-held secret. If you need a
  pepper, the standalone
  [`argon2id-passwordhasher`](https://github.com/systemslibrarian/argon2id-passwordhasher)
  package provides one (`PepperRing`), plus a PBKDF2→Argon2id migration adapter
  and benchmarks. PostQuantum.Identity intentionally ships a smaller, dependency-
  light Argon2id core so it does not require that package; the two are siblings,
  not layers.
- **Migration adapter covers the stock PBKDF2 hasher only out of the box.**
  `MigratingPasswordHasher<TUser>` (via `AddArgon2idPasswordHasherWithMigration`)
  verifies the default ASP.NET Core Identity PBKDF2 format and rehashes to
  Argon2id. It does **not** bundle adapters for bcrypt/scrypt/other legacy
  formats — supply your own `IPasswordHasher<TUser>` as the legacy hasher if
  your store uses something else.
  [`docs/MIGRATION.md`](docs/MIGRATION.md#migrating-from-bcrypt--scrypt--a-custom-hasher)
  shows the ten-line adapter shape.
- **String-only API.** `HashPassword`/`Verify` take `string`, not
  `ReadOnlySpan<char>`/`byte[]`. The plaintext therefore lives on the managed
  heap as a `string` (immutable, not zeroable) for the duration of the call;
  only the derived UTF-8 bytes are zeroed. The Identity contracts dictate the
  shape; a span overload would be additive but is not in 0.3.
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
- **No bundled authentication handler.** This package *issues* tokens; it does
  not ship its own `AuthenticationHandler`. Validate them with PostQuantum.Jwt's
  `AddPqJwtBearer` (the demos do exactly this, with a `kid` resolver) or
  `PqJwtValidator` directly.
- **Rotation is issuer-stamps-`kid` + validator-resolves-`kid`.** The token
  service stamps `PostQuantumTokenOptions.KeyId` into each token; the verifier
  picks the key via PostQuantum.Jwt's `SignatureKeyResolver` (demonstrated in
  the sample). This package does not itself manage a key store, schedule
  rotations, or pick "the current key" for you — you own the key ring.
- **Revocation is the caller's concern.** Each token carries a unique `jti`
  (`Guid.NewGuid().ToString("N")`); the samples implement an in-memory
  revocation list, but the library itself does not provide one. Plug your own
  cache (Redis, a DB table) into the post-authentication pipeline as the
  samples illustrate.
- **No `nbf` floor by default.** PostQuantum.Jwt's builder emits `iat` and
  `exp`; whether `nbf` is stamped is delegated to it. Our payload KAT pins
  consistency (`iat ≤ exp`, lifetime correct) and tolerates either presence.
- **AOT: the claim path is clean; full-app AOT is your responsibility.** Token
  issuance serializes claims via source-generated `JsonTypeInfo<T>` and the
  net10 assembly asserts `IsAotCompatible`. That covers this library's
  surface; whether your whole app publishes AOT also depends on ASP.NET Core
  Identity, EF, and your other dependencies.

## Testing & environment

- **net8.0 / net9.0 are build-verified and unit-tested; net8.0 unit tests
  require the .NET 8 runtime.** The Argon2id code is runtime-agnostic and is
  exercised on every installed runtime in CI. The hybrid-token tests run only
  on net10.0 and skip themselves when the host's OpenSSL predates ML-DSA
  (3.5+).
- **Argon2id has multi-layer Known Answer Tests; ML-DSA/X-Wing KATs live in
  PostQuantum.Jwt.** This repo pins (1) the RFC 9106 §5.3 reference vector
  including the keyed + AD path, (2) a canonical reference-CLI PHC string that
  must verify, (3) a wire-format pin of the emitter on the same vector, and
  (4) compute-then-format-then-verify roundtrips across the OWASP / RFC 9106 /
  libsodium-shaped work-factor profiles. The token-level cryptographic KATs
  (ML-DSA, X-Wing) live in PostQuantum.Jwt; this repo additionally pins the
  *identity* contract — header `alg`/`kid`/`cty`, registered + private claim
  shapes, and the sign-then-encrypt envelope structure — as structural KATs.
- **No property-based or fuzz tests yet.** The PHC parser and token validator
  have hand-written malformed-input corpora but no generative fuzzing.
- **Benchmarks are not run in CI.** `benchmarks/PostQuantum.Identity.Benchmarks`
  (BenchmarkDotNet) exists for local Argon2id work-factor tuning, but the CI
  workflow does not execute it or track regressions over time.

## Operational hygiene

- **Logging is the consumer's responsibility.** The library never logs hashed
  passwords, plaintext passwords, or token contents. It does not emit
  structured logs of its own — wire your `ILogger<T>` at the call sites if
  you need audit trails.
- **Telemetry / OpenTelemetry instrumentation is not built in.** Add spans
  around `CreateTokenAsync` / `VerifyHashedPassword` from the caller if you
  want them on the trace.

---

If you hit a gap not listed here, that itself is a gap — please open an issue
so it can be recorded honestly.

---

*To God be the glory — 1 Corinthians 10:31.*
