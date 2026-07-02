# Known Gaps

A transparent, running list of what PostQuantum.Identity does **not** yet do,
what is unverified, and where the sharp edges are. Honesty over polish: if
something is incomplete, it is listed here rather than glossed over. This file
is part of the contract with anyone evaluating the library.

Last reviewed for: `1.0.0` (2026-07-02).

## Maturity — split by surface

PostQuantum.Identity ships two surfaces with deliberately different stances:

- **Argon2id password hashing** (`net8` / `net9` / `net10`): implemented to
  production discipline, RFC 9106 §5.3 KAT-pinned, fail-closed, vetted
  dependency. **Suitable for production adoption today.**
- **Hybrid post-quantum tokens** (`net10` only): production-ready for
  **owned / trusted ecosystems** where you own the issuer and every
  verifier, built on upstream PostQuantum.Jwt 1.0.0 (stable). Not
  appropriate for public-internet OIDC until the IETF JOSE PQC drafts land.

**1.0 is a semver commitment, not an audit claim.** The public API only
breaks with a major version; what the version does and does not promise is
spelled out in
[What 1.0 means](README.md#what-10-means--and-what-it-does-not).

### Cross-cutting

- **No external audit.** No third party has reviewed the design or
  implementation — 1.0 does not change that. Independent review is the top
  item on the post-1.0 roadmap; organizations that require an audit before
  adoption should treat this library as not yet qualifying.
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
- **Verification acceptance bounds are fixed, not configurable.** To keep a
  poisoned stored row from demanding an absurd computation at verify time,
  the parser only accepts `m` ∈ [8 KiB, 4 GiB], `t` ∈ [1, 512], `p` ∈ [1, 64]
  (with `m ≥ 8·p`), salt ∈ [8, 64] bytes, tag ∈ [12, 512] bytes. Every profile
  a legitimate encoder emits fits comfortably; but if your store somehow
  contains spec-legal Argon2id hashes outside these bounds (e.g. a bespoke
  KDF deployment with `m > 4 GiB`, or `p = ProcessorCount` on a >64-core
  host under a pre-bounds version of this library), they will fail
  verification here rather than run. **The failure is indistinguishable from
  a wrong password, and because rehash-on-login requires a successful
  verify, there is no automatic upgrade path — affected users need a
  password reset.** Audit historical work-factor configs before upgrading.
  There is no override switch — that is a deliberate fail-closed trade,
  stated here so nobody discovers it in production.
- **Bounds cap the poisoned-row DoS; they don't eliminate it.** The worst
  case a hostile row can still demand is one bounded-but-heavy computation
  (up to 4 GiB / 512 passes). The rate-limiter guidance in the README is the
  other half of the mitigation; pods sized below the acceptance ceiling
  would OOM on a legitimate hash of that size too.

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
- **Revocation is the caller's concern — and does not cross service
  boundaries by itself.** Each token carries a unique `jti`
  (`Guid.NewGuid().ToString("N")`); the samples implement an in-memory
  revocation list, but the library itself does not provide one. Plug your own
  cache (Redis, a DB table) into the post-authentication pipeline as the
  samples illustrate. Note the sharpest edge: a downstream verifier that only
  checks signature/issuer/audience/expiry (like the Verifier demo) will keep
  accepting a token the issuer revoked, until it expires. Cross-service
  revocation requires a **shared** store consulted by every verifier; short
  token lifetimes bound the exposure either way.
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
- **Property-based / fuzz coverage is in place for the PHC parser; the token
  validator's is upstream.** The PHC parser has a deterministic generative
  corpus (seeded-PRNG roundtrips across the full acceptance bounds, structural
  mutations, hostile garbage — thousands of cases per run, reproducible from
  the fixed seeds) alongside the hand-written adversarial corpus. The token
  *validator* lives in PostQuantum.Jwt, so generative fuzzing of token
  parsing belongs to (and is tracked in) that repo; this repo pins the
  issuance contract structurally but does not fuzz the upstream validator.
  Coverage-guided fuzzing (e.g. SharpFuzz) remains unexplored on both.
- **Benchmarks run in CI with a step-change budget, not a precision budget.**
  The Argon2id benchmarks execute on every push to `main` (short job,
  net10.0), with history tracked on `gh-pages` and a 150% alert threshold
  that fails the job. Hosted-runner noise makes a tighter budget dishonest:
  this catches an accidental extra memory pass or a quadratic slip, **not** a
  quiet 10% drift. Latency-precise comparisons still belong on pinned
  hardware with the full BenchmarkDotNet job
  (`benchmarks/PostQuantum.Identity.Benchmarks`).
- **macOS is a discovery lane, not a PQ-required lane — and runs on pushes
  to `main`, not per-PR.** The `macos-discovery` job builds and runs the
  net10 suite on `macos-latest` and reports (without failing) whether the
  BCL's macOS ML-DSA path let the PQ token tests run on the current runner
  image; that answer changes per runner-image release, not per commit, so
  burning the scarcest runner class on every PR would buy nothing. Windows
  and the pinned-OpenSSL Linux lane remain the two zero-skip
  cryptographic-assurance lanes, on every PR.

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
